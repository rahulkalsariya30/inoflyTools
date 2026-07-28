**Inofly Firmware Flashing SOP — OEM Firmware Flashing Manual**

| | |
|---|---|
| **Doc No.:** | 01 - FF - INF |
| **Issue** | 01 |

| Version History Table | | |
|---|---|---|
| **Revision No.:** | **Revision Date:** | **Description** |
| 1 | 14/07/2026 | Initial Release |

| Prepared by: | Approved by: |
|---|---|
| _(name / signature)_ | _(name / signature)_ |

**Scope.** Standard Operating Procedure for generating the manufacturer signing keys, signing the firmware, and flashing the secure bootloader and signed firmware onto the flight module (**CubePilot CubeOrange+ / STM32H743, board-id 1063**) — from key generation through testing and verification against DGCA Certification Scheme §7.1. All procedures in this document are **hardware procedures** performed on the real flight module.

> **Roles.** Inofly is both the drone OEM and the firmware manufacturer: key generation, public-key embedding, firmware signing and bundling all happen in-house on the offline signing machine. There is no external firmware-provider round-trip. The Certification Body (CB) receives the public key, the certificate chain, and the registered checksums.

---

# STEPS FOR GENERATING THE KEYS

- The manufacturer purchases a **document-signing digital certificate from a CCA-licensed Certifying Authority** (Controller of Certifying Authorities, Government of India) or an authorized distributor. The certificate file is delivered in **`.PFX`** (PKCS#12) format with an import password.
- **The certificate must be RSA-2048, with an exportable private key.** The architecture is sized for RSA-2048 (256-byte signatures, ~294-byte DER public key embedded in the bootloader's sector-0 budget, 373-byte binary manifest). An RSA-3072/4096 certificate will not fit and must not be purchased.
- The manufacturer generates the **public and private keys from the `.PFX` file using OpenSSL commands** (see GENERATION OF THE CERTIFICATE, KEYS & SIGNATURE below).
- The **public key is embedded into the secure bootloader and the application firmware at build time** (`tools/pki/embed_pubkey.py` regenerates the C header; both images are then rebuilt). This embedded key is the root-of-trust verification key — the flight module verifies every signature against it and encrypts audit-log hashes with it.
- The manufacturer signs the firmware with the **private key** using the in-house signing pipeline. **All signing uses RSA-PSS (SHA-256, MGF1-SHA256, salt length 32)** — the scheme the on-device verifier expects.
- The **public key (`.pem`), the full X.509 certificate chain, and the registered checksums** (code part and data part, SHA-256, calculated separately) are submitted to the CB and retained.
- The private key **never leaves the offline signing machine**. It is never committed to version control; the master copy is kept on encrypted offline media.

> Development and bench-reference builds are signed with a self-generated RSA-2048 test keypair (`tools/pki/keygen.py`). Production units use the CCA-derived key. The key *source* differs; the signing scheme, tools and every verification step are identical.

---

# INSTALLATION OF OPENSSL IN WINDOWS

- Download the OpenSSL 3.x (64-bit) installer for Windows (e.g. from slproweb.com — "Win64 OpenSSL") and run the setup on the signing machine.
- Accept the license agreement, keep the default destination (`C:\Program Files\OpenSSL-Win64`), and complete the installation.
- Add OpenSSL to the system **PATH** environment variable:
  1. Right-click **This PC → Properties → Advanced system settings → Environment Variables**.
  2. Under *System variables*, open **Path** and add `C:\Program Files\OpenSSL-Win64\bin` if it is not already present.
- Verify from a new PowerShell window:

```powershell
openssl version
# → OpenSSL 3.x.x
```

- The signing tools additionally require **Python 3.13** on the same machine (`py -3 --version`). All tool commands below run from the repository root.

> OpenSSL is used for key extraction and inspection only. **Do not sign firmware with a raw `openssl dgst -sha256 -sign` command** — that produces a PKCS#1 v1.5 signature, which the flight module will reject. All signing goes through the Inofly pipeline tools, which apply RSA-PSS.

---

# GENERATION OF THE CERTIFICATE, KEYS & SIGNATURE

All commands run on the **offline signing machine**, from the repository root. Replace `cca_cert.pfx` with the actual certificate filename; enter the `.PFX` import password when prompted.

**1. Extract the private key from the `.PFX` file** into the manufacturer private-key slot:

```bash
openssl pkcs12 -in cca_cert.pfx -nocerts -nodes \
  | openssl pkcs8 -topk8 -nocrypt \
  -out pki/manufacturer/private/manufacturer_private.pem
chmod 600 pki/manufacturer/private/manufacturer_private.pem
#   (chmod applies in a POSIX shell — WSL/Git Bash; in plain Windows PowerShell,
#    restrict the file instead via Properties → Security to the signing user only)
```

**2. Derive the public key** from the private key:

```bash
openssl rsa -in pki/manufacturer/private/manufacturer_private.pem \
  -pubout -out pki/manufacturer/public/manufacturer_public.pem
```

**3. Verify the key is RSA-2048 and record its fingerprint** (the fingerprint goes into the Build Identity record):

```bash
openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -noout -text | head -1
# → must print: Public-Key: (2048 bit)   — if not, STOP: wrong certificate key size

openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -outform DER \
  | openssl dgst -sha256
```

**4. Retain the X.509 certificate chain for the CB** (this ties the public key to the manufacturer's legal identity):

```bash
openssl pkcs12 -in cca_cert.pfx -clcerts -nokeys -out cca_cert.pem
```

**5. Embed the public key into the firmware and bootloader**, then rebuild both images:

```bash
python tools/pki/embed_pubkey.py
#   → firmware/include/manufacturer_pubkey.h (DER SubjectPublicKeyInfo, ~294 bytes)
# Rebuild (build host):
#   make cubepilot_cubeorangeplus_default      (application firmware)
#   make cubepilot_cubeorangeplus_bootloader   (secure bootloader — embeds the same key)
```

**6. Generate the firmware signatures** — one pipeline command signs the firmware image and its manifest with the private key using RSA-PSS:

```bash
BUILD=<build-dir>/cubepilot_cubeorangeplus_default
python tools/pipeline.py \
    $BUILD/cubepilot_cubeorangeplus_default.px4 \
    --board-id 1063 \
    --elf $BUILD/cubepilot_cubeorangeplus_default.elf \
    --private-key pki/manufacturer/private/manufacturer_private.pem \
    --public-key  pki/manufacturer/public/manufacturer_public.pem \
    --output-dir release/
# Confirm the run logs: "BOOT001 image: SIGNED (RSA-PSS)"
```

The pipeline performs, in order (each signing step is followed by a mandatory self-verification gate — the run aborts if any gate fails):

1. **Image signing (BOOT001)** — patches the RSA-PSS signature into the firmware image so the secure bootloader will accept it at boot (a stock, unsigned build carries a zero placeholder and is refused fail-closed).
2. **Checksum calculation (CHK001)** — SHA-256 of the **code part** and the **data part separately**; `--elf` makes it hash the exact flash ranges the device re-hashes at POST.
3. **Manifest signing (SIG001)** — signs the registered checksums with the manufacturer private key; verified before proceeding.
4. **Bundling (PKG001)** — packages firmware + signed manifest into a single distributable `.fwbundle`; bundle signature verified.
5. **Binary manifest export (PRV001)** — the 373-byte `*_manifest.bin` (magic `INOFLY03`) provisioned onto the flight module, protected by RSA-PSS signature + CRC32; verified (CRC + signature).

**7. Sign the secure bootloader (BOOT008)** — a **separate** one-liner, run after building the bootloader target (the bootloader must be a fresh build carrying its embedded image TOC — after any bootloader source change, rebuild **then** re-sign; never re-sign a stale binary in place):

```bash
python tools/signer/sign_bootloader.py \
    <build-dir>/cubepilot_cubeorangeplus_bootloader/cubepilot_cubeorangeplus_bootloader.bin \
    boards/cubepilot/cubeorangeplus/bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin
# → the signed artifact the on-device bl_update command verifies before
#   erasing sector 0 (an unsigned/tampered bootloader is refused fail-closed)
```

---

# FIRMWARE UPLOAD PROCESS

After the pipeline run, the signed release artifacts are in `release/`:

| Artifact | Contents | Goes to |
|---|---|---|
| `<name>_manifest.json` | Registered checksums (code + data, SHA-256 hex), version, board-id | **Certification Body** (registered-checksum submission) |
| `<name>_signed.json` | Signed manifest wrapper (base64 RSA-PSS signature) | Certification Body / manufacturer records |
| `<name>_manifest.bin` | 373-byte binary manifest for the flight module | Flight module SD (`/fs/microsd/inofly/manifest.bin`) |
| `<name>.px4` | The BOOT001-signed firmware image (loose copy alongside the bundle) | Manufacturing station (first factory load) |
| `<name>.fwbundle` | Firmware + signed manifest in one installable file | **Operator / GCS** — the only file the operator receives |

The BOOT008-signed secure bootloader is produced by the separate `sign_bootloader.py` step and lives in the firmware tree at `boards/cubepilot/cubeorangeplus/bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin` — it goes to the manufacturing station for the SD one-shot install.

Upload / submission steps:

1. **Submit the registered checksums to the CB** — `<name>_manifest.json` (+ `_signed.json`), together with the public key and certificate chain from the key-generation step. These become the *registered checksums* the CB may digitally sign and retain.
2. **Record the release in the Build Identity record** — version, git hash, code/data hashes, bootloader hash, key fingerprint.
3. **Stage the `.fwbundle` for distribution** to operators via the manufacturer's release channel. Any modification to the bundle breaks the signature and the GCS/device will refuse it.
4. **Stage the signed bootloader binary and `_manifest.bin`** at the manufacturing station for unit provisioning (next sections).

---

# CONNECTION DIAGRAM

Production flashing uses **USB and the microSD card only**. No ST-Link/SWD connection is used or required: on a production unit the SWD/JTAG pads sit inside the Cube enclosure behind the tamper-evident seal, and every flash path is gated by signature verification instead of debugger access.

```
 +----------------------+           USB (data)            +---------------------------+
 |  Provisioning host   | <-----------------------------> |  CubeOrange+ on carrier   |
 |  (Windows laptop:    |                                 |                           |
 |   QGC / nsh console) |                                 |   [microSD slot] <--- SD  |
 +----------------------+                                 |   POWER1 <-- power module |
                                                          +-------------^-------------+
 +----------------+       +------------------+                          |
 |  LiPo battery  | ----> |  Power module    | ------------------------->
 +----------------+       +------------------+
```

| Host side | Flight module side | Purpose |
|---|---|---|
| USB port | CubeOrange+ carrier USB | QGC connection, nsh/MAVLink console, firmware load |
| microSD card (via card reader or MAVLink-FTP) | microSD slot | Binary manifest, signed bootloader one-shot, staged updates, audit log |
| — | LiPo → power module → POWER1 | **Mandatory:** USB alone does not boot the flight module |

Before flashing, verify:

1. SD card is seated in the CubeOrange+ carrier.
2. Flight module is powered from the battery/power module (POWER1), not USB alone.
3. USB cable connected to the provisioning host; the device enumerates in QGC.

---

# BOOTLOADER FLASHING STEPS

The secure bootloader (signature-verifying, manufacturer public key embedded) is installed **once per unit at manufacturing** via PX4's `bl_update` mechanism — a one-shot from the SD card. After the tamper seal is applied the bootloader is immutable in the field; a later bootloader change is a return-to-manufacturer operation.

1. **Verify the factory bootloader** (supply-chain check, done while the as-shipped Hex factory bootloader is still in place): read sector 0 (128 KB at `0x08000000`) from the provisioning host, compute SHA-256, and compare against the documented factory-bootloader reference hash. On mismatch, **quarantine the unit** — do not proceed.
2. **Load the first signed application firmware** (see FIRMWARE FLASHING STEPS below). The `bl_update` command runs from the signed application firmware, so this must be done first.
3. **Copy the signed bootloader to the SD card** — `cubepilot_cubeorangeplus_bootloader.bin` (the BOOT008-signed artifact from the release pipeline) to the SD root, via card reader or QGC MAVLink-FTP to `/fs/microsd/`. Do **not** use a hand-built unsigned bootloader binary — it will be refused.
4. **Run `bl_update`** from the QGC MAVLink Console (or `nsh` over USB):

```
nsh> bl_update /fs/microsd/cubepilot_cubeorangeplus_bootloader.bin
```

   The running firmware **verifies the manufacturer RSA-PSS signature on the candidate bootloader before erasing sector 0**. Expected console output:
   - `BOOT008: bootloader signature verified` → header validation → sector-0 erase → write → verify (~5–10 s).
   - If the signature is invalid: `BOOT008: … refusing to flash (sector 0 untouched)` — the command aborts **without erasing**. Re-check that the signed artifact was copied.
5. **Reboot** the device and confirm the secure bootloader is running (boot LEDs / serial output).
6. **Verify the installed bootloader hash**: read sector 0 again, compute SHA-256, compare against the secure-bootloader reference hash for the build. Record the hash in the unit's QMS record. On persistent mismatch after one retry, quarantine the unit.
7. **Delete the bootloader binary from the SD card** after a confirmed install (one-shot use).

From this point on, the unit's sector 0 contains the verifying bootloader: at every boot it verifies the application firmware's RSA-PSS signature against the embedded manufacturer public key and refuses to launch an unsigned or tampered image.

---

# FIRMWARE FLASHING STEPS

Firmware loaded onto the flight module must be the **pipeline-signed release image** (`release/<name>.px4` or the `.fwbundle` wrapping it). A normally-built image carries a zero signature placeholder and the secure bootloader will refuse to boot it.

1. Obtain the signed release image from the release pipeline (confirm the pipeline logged `BOOT001 image: SIGNED (RSA-PSS)`).
2. Connect the flight module per the CONNECTION DIAGRAM and open QGroundControl.
3. **Vehicle Setup → Firmware → Load Custom Firmware**, select the signed release image, and let the flash complete. Wait for the device to reboot.
4. **Provision the binary manifest**: copy `release/<name>_manifest.bin` onto the SD card as `/fs/microsd/inofly/manifest.bin` (card reader or MAVLink-FTP).
5. **Provision the MAVLink signing key** (GCS↔FM authentication):

```bash
# SD card mounted on the provisioning host (e.g. E:\); omit --passphrase for a
# hidden interactive prompt (recommended — keeps it out of the shell history)
python tools/provisioning/provision_signing_key.py \
    --drone-id <UNIT_ID> --hardware-mount E:\ --no-sitl
# → writes <mount>/mavlink/mavlink-signing-key.bin to the drone's SD; the operator
#   enters the same passphrase in QGC (both sides derive the key as SHA256(passphrase))
```

6. **Reboot and verify POST** at the console:

```
nsh> listener firmware_integrity_status
#   check_passed: True, failure_reason: 0,
#   code_hash / data_hash equal to the registered checksums in the manifest
nsh> secure_boot audit_status
#   POST PASS entry recorded in the audit log
```

7. Confirm the firmware version in QGC matches the release, and record it in the unit's QMS record.
8. **Negative enforcement check (manufacturing step, one-shot):** attempt to load an intentionally tampered copy of the firmware (single byte flipped in the signed region — manufacturing fixture only, never distributed). The secure bootloader **must refuse to launch it** (no MAVLink heartbeat; unit holds in bootloader until a valid image is loaded). Re-flash the production image to recover. If the tampered image runs, quarantine the unit — this is a release-blocking failure.
9. Apply the tamper-evident seals (airframe + Cube enclosure) and complete the unit's QMS record per the Manufacturing Runbook before shipment.

---

# INSTALLATION METHOD OF QGROUNDCONTROL

- The operator installs **inoflyGCU** — the Inofly build of QGroundControl — from the installer provided by Inofly. Installation follows the standard QGroundControl setup for Windows (run the installer, accept defaults, launch).
- inoflyGCU adds the security panels used in this SOP on top of stock QGroundControl:
  - **Secure Firmware Update** (Vehicle Setup) — signed-bundle verification and installation.
  - **Audit Log panel** — download of the flight module's signed audit log and its signature file.
  - **MAVLink signing** — Application Settings → MAVLink → Signing → **Add Key**: the operator enters the drone's passphrase; QGC derives the same 32-byte key as the flight module. With the wrong passphrase the flight module drops the link (no telemetry, no commands).

---

# FIRMWARE FLASHING PROCESS THROUGH QGROUNDCONTROL

Field firmware updates are performed through inoflyGCU using the signed `.fwbundle` — the only file the operator receives.

1. Connect the drone (USB or telemetry link with MAVLink signing active) and open **Vehicle Setup → Secure Firmware Update**.
2. Click **Browse** and select the release `.fwbundle`.
3. QGC verifies the bundle's manufacturer signature client-side:
   - **VERIFIED (green)** → the **Install on Drone** button becomes available.
   - **FAILED (red)** (tampered/unsigned bundle) → installation is blocked; nothing is sent to the drone.
4. Click **Install on Drone**. The flight module **does not trust the GCS's verdict** — it independently re-verifies the update manifest (CRC32 → RSA-PSS signature against the embedded public key → board-id) before accepting. On success the signed update manifest is staged on the SD (`/fs/microsd/inofly/update_manifest.bin`) and an `UPDATE_ATTEMPT` SUCCESS entry is written to the audit log.
5. The new firmware image is applied through the authorized update path (QGC firmware load of the signed image, or the SD-staged update where the image and its manifest are placed on the SD and verified with `secure_boot apply_update`). In every path the image is signature-verified before flash and again by the bootloader at next boot.
6. **Reboot.** POST re-computes the code/data checksums of the new firmware and compares them against the **new registered checksums** from the signed update manifest — the registered checksums are updated only through this authorized, signed procedure.
7. Verify at the console: `listener firmware_integrity_status` → `check_passed: True`; the update and the POST result both appear in the audit log (visible via the Audit Log panel or `tools/decode_audit_log.py`).

**Rejection behavior (expected):** a tampered bundle fails at step 3 (red FAILED); a corrupted staged manifest is rejected on-device with reason=2 (CRC); an update signed with a non-manufacturer key is rejected with reason=3 (signature); a manifest for a different board is rejected with reason=4 (board-id). Every rejected attempt is logged with its reason code and nothing is flashed.

---

# TESTING AND VERIFICATION

## 7.1 Firmware Tamper Avoidance

a) Protection of onboard computer firmware from tampering (software). UAS should not function if the firmware is changed by any procedure other than authorized update procedure.

| Method of Evaluation | Test Cases | Remarks |
|---|---|---|
| A) Verification of secure boot: Manufacturer to produce a certificate of compliance indicating compliance with all conditions mentioned: | **i) Flight module security implementation.** a) Check if the flight module have 'level 0 or level 1' compliance as defined in Annexure E. | a) FM follows **Level 1** compliance. |
| | b) Check that the flight module follows the communication requirement (if applicable) as defined in Annexure E. | b) All secure execution occurs inside the flight module only (no separate companion computer). The GCS↔FM link is authenticated with SHA-256-based MAVLink v2 message signing (key = SHA256 of the per-drone passphrase). |
| | c) Check that the flight module have a root of trust mechanism implemented which is used to sign the data generated inside the FM. | c) **RSA-2048 root of trust** signs/authenticates all FM-generated compliance data. The verification chain is anchored in the verifying bootloader with the manufacturer public key embedded; physical debug access is closed by the tamper-evident seal. |
| | d) The verification key of the root of trust may be recorded and retained. | d) The public key (`manufacturer_public.pem`) is retained and supplied to the CB; it verifies firmware signatures and the origin of every log generated by the FM. |
| | **ii) Calculation of checksums.** a) Manufacturer to submit checksums of the firmware to the CB ('registered checksums'). | a) Registered checksums are generated by the release pipeline and submitted to the CB (`*_manifest.json` / `*_signed.json`). |
| | b) Code part and data part checksums to be calculated separately. | b) `code_hash` and `data_hash` are independent SHA-256 values, so data/parameters can be revised in a future release without re-checksumming code. |
| | c) All checksums calculated using a Secure Hash Algorithm (SHA2 or SHA3). | c) SHA-256 throughout. |
| | d) Registered checksums stored securely in the flight module such that they cannot be updated without manufacturer authorization. | d) Registered checksums live in the 373-byte binary manifest on the FM, protected by an RSA-PSS manufacturer signature + CRC32. Any alteration is detected at POST (distinct reason codes); they change only through a manufacturer-signed update. |
| | e) Registered checksums may be digitally signed by the CB and retained. | e) The submitted registered checksums can be digitally signed by the CB. |
| | **iii) Power On Self-Test (POST).** a) Manufacturers should implement POST. | a) POST runs automatically on every boot. |
| | b) Checksums of firmware (code and data part) calculated and matched with the registered checksum stored in the flight module. | b) At every boot the FM re-computes the code and data SHA-256 from **live flash** and compares both against the registered checksums in the signed manifest. |
| | c) The result of the POST should be logged. | c) Both PASS and FAIL results are written to the signed audit log on the SD card. |
| | d) Mismatch of checksum should prevent the UAS from booting and be logged. | d) On mismatch the UAS is non-functional: arming is refused (`Preflight Fail: Firmware integrity check failed`), the failure is logged with its reason code (2 CRC · 3 signature · 4 code-hash · 5 data-hash · 6 board-id). |
| | **iv) Testing of firmware protection (software).** a) Attempt modifying the firmware (code and data) in an unauthorized manner. The firmware update should fail; if it gets through, UAS must fail POST. Test conducted in presence of CB. | a) Three independent fail-closed layers, demonstrated live: (1) the GCS refuses a tampered bundle (signature FAILED, nothing sent); (2) the FM independently rejects a tampered/foreign-signed staged update (reason 2/3/4); (3) the verifying bootloader refuses to launch a tampered image, and any unauthorized change that reaches flash fails POST and blocks arming. Every rejection is logged. |

## b) Safety and security of firmware update

| Method of Evaluation | Test Cases | Remarks |
|---|---|---|
| Secure upgrade test: | i) The update should be permitted only if it is signed by the manufacturer's digital certificate. | i) The update bundle carries an RSA-PSS signature made with the manufacturer private key. The GCS verifies it before offering **Install on Drone**, and the FM re-verifies it independently — unsigned or foreign-signed updates are refused fail-closed. |
| | ii) UAS should be able to verify the authenticity of the update with the public key of the manufacturer. | ii) The FM verifies the update manifest's hash and signature against the **public key embedded in its firmware** (and the bootloader re-verifies the image signature at next boot). |
| | iii) Firmware change should be recorded in the logs. | iii) Every update attempt — accepted **and** rejected, with reason code — is recorded in the FM's signed audit log (not only on the GCS side). |
| | iv) After upgrade, the registered checksum should be updated in the flight module securely. | iv) The new registered checksums travel inside the signed update manifest; they replace the old ones only after signature verification, and the next POST validates the new firmware against them. |
| | v) Checksums of the updated firmware (code and data) to be digitally signed by the CB and retained. | v) The updated registered checksums can be digitally signed by the CB. |

## c) Secure change of flight parameters

| Method of Evaluation | Test Cases | Remarks |
|---|---|---|
| Testing of parameter update: | i) UAS should be able to verify the authenticity of the manufacturer citing the process for instituting a change in any given parameter. | i) Compliance parameters are **compiled into the signed firmware** (flash table covered by `data_hash`). The only way to change a registered value is a new manufacturer-signed firmware release — verified with the embedded public key like any update. |
| | ii) Change should be recorded in the logs. | ii) Every rejected attempt to move a compliance parameter is written to the FM's signed audit log (with attempted value and registered value/ceiling). |
| | iii) After upgrade, the registered checksum should be updated in the flight module securely. | iii) A parameter change ships as a signed release: new `data_hash` in the signed manifest, installed via the secure update path. |
| | iv) Checksums of the updated firmware to be digitally signed by the CB for their records. | iv) Done by the CB on the submitted checksums. |
| | v) Try to update the parameters that affect compliance conditions using the manufacturer's standard operating procedure. The parameter should remain unaffected. | v) Demonstrated live at the console: a **CAPPED** parameter (e.g. `GF_MAX_VER_DIST`, ceiling 120 m) rejects any value above its compiled ceiling and never persists across reboots; a **LOCKED** parameter (e.g. `CA_AIRFRAME`) rejects any value other than its registered value. In both cases the registered value is unaffected and the attempt is logged. |
| | vi) Try to update the parameters in the firmware that affect compliance conditions using an invalid digital signature. The update should fail. | vi) A parameter-changing update signed with an invalid/non-manufacturer key is rejected (reason=3, signature) — nothing is flashed, the registered values stand, arming policy is unchanged, and the rejection is logged. |

**Witnessed verification.** The live demonstration sequence for the CB (positive POST, tamper→POST fail→arming blocked, signed update accepted, tampered/attacker update rejected, parameter enforcement, MAVLink signing, audit-log offline verification) is scripted step-by-step in the CB Test Runbook (`CB_TEST_RUNBOOK.md`), with expected console output and reason codes for each test.
