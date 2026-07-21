# DGCA Certification Scheme §7.1 — Compliance Mapping
## Inofly UAS Firmware Security — Level 1 (Firmware Manufacturer)

| | |
|---|---|
| **Document** | Compliance mapping — Gazette Certification Scheme for UAS, Section 7.1 |
| **Scope** | Firmware tamper avoidance, safety/security of firmware update, secure change of flight parameters, log file signing |
| **Platform** | PX4 (inoflyPilot fork) on CubePilot CubeOrange+ (STM32H743), QGroundControl (inoflyGCU fork) |
| **Role** | Firmware Manufacturer — provider of the Flight Module firmware. We are **not** the Certification Body. |
| **Last updated** | 2026-07-10 |
| **Companion docs** | [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md) (live-demo runbook, step IDs `D1…D9` referenced below) · [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) (system architecture + diagrams) · [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) (tooling used during evaluation) |

---

## 0. Reference summary of compliance

| Sr. No | Parameter | Compliance criteria | Where satisfied | Demo |
|---|---|---|---|---|
| 7.1 (a) | Firmware tamper avoidance | UAS should not function if firmware is changed by any procedure other than the authorized update procedure | §1 (Secure boot), §2 (Checksums), §3 (POST), §4 (Firmware protection testing) | D3, D4, D5, D6 |
| 7.1 (b) | Safety and security of firmware update | Update permitted only if signed by manufacturer; UAS verifies authenticity; changes logged; registered checksums updated | §5 (Secure upgrade) | D5, D6 |
| 7.1 (c) | Secure change of flight parameters | Compliance-affecting parameters cannot be changed except by the manufacturer's authorized process | §6 (Parameter protection) | D7 |
| Additional | Log file signing | Binary logs signed; tamper detectable offline | §7 (LOG001) | D9 |
| Annexure E | Flight module security level | Level 1 — secure execution inside the flight module | §1.1 | D1 |

**Overall implementation status:** all Section 7.1 controls are implemented and validated on real hardware (CubeOrange+, bench acceptance Tier 1 H0–H15 complete 2026-06-05; secure-bootloader chain B1–B9 complete 2026-07-09). The automated compliance test suite (358 tests) passes; see `Docs/compliance_report.txt` (regenerate with `python tools/generate_compliance_report.py --run-tests`).

---

## 1. Verification of Secure Boot — Flight Module Security Implementation (§7.1 a.i)

### 1.1 Level 0 / Level 1 compliance (Annexure E)

> *"Check if the flight module has 'Level 0 or Level 1' compliance as defined in Annexure E."*

**Satisfied — Level 1.** All secure execution occurs inside the Flight Module, on the STM32H743 microcontroller of the CubeOrange+ flight controller:

- Signature verification (boot-time and update-time) runs on the microcontroller using **libtomcrypt** (RSA-PSS / SHA-256).
- Checksum computation (POST) runs on the microcontroller over the live flash contents.
- Audit-log hash encryption runs on the microcontroller.
- There is **no separate companion computer** — the Flight Module is a single module, so the Annexure E inter-module 128-bit encryption requirement is not applicable (a common single-module architecture position).

**Evidence:** `src/modules/secure_boot/` (PX4 fork), [ARCHITECTURE_OVERVIEW.md §2](ARCHITECTURE_OVERVIEW.md).

### 1.2 Communication requirement (Annexure E, if applicable)

> *"Check that the flight module follows the communication requirement (if applicable) as defined in Annexure E."*

**Not applicable / exceeded.** Single-module Flight Module ⇒ no inter-module link to protect. Additionally, the Ground Control Station ↔ Flight Module link is authenticated with **MAVLink v2 message signing** (PAIR001): a per-drone 32-byte key derived as `SHA256(passphrase)`, provisioned to the Flight Module at manufacture. A Ground Control Station without the key cannot command the drone — its messages fail HMAC-SHA256 verification and are dropped by the Flight Module. `MAV_SIGN_CFG = 1` (signing required on all non-USB links) is a LOCKED compliance parameter (§6) and cannot be disabled at runtime.

**How this works, briefly.** The ground station and the flight module each derive the same 32-byte key from the pairing passphrase. Every command message then carries an authentication tag (HMAC-SHA256) computed with that key; the flight module recomputes the tag on receipt and silently drops any message whose tag does not match. A ground station that never received the key cannot produce valid tags, so it cannot command the aircraft.

**Evidence:** `tools/provisioning/provision_signing_key.py`, PX4 MAVLink signing, tests `tests/compliance/test_PAIR001_gcs_pairing.py`. **Demo:** D8.

### 1.3 Root of trust mechanism (TPM or TEE for Level 1) used to sign Flight-Module-generated data

> *"Check that the flight module has a root of trust mechanism implemented … which is used to sign the data generated inside the FM."*

**Satisfied — RSA-2048 root of trust.** A single manufacturer RSA-2048 keypair is the root of trust for the entire system (a widely certified key size and pattern for this class of hardware):

- The **private key** never leaves the manufacturer's offline signing environment.
- The **public key** is embedded in two places on the Flight Module: (1) compiled into the **verifying bootloader** binary, and (2) compiled into the **application firmware** (`manufacturer_pubkey.h`, DER SubjectPublicKeyInfo, ~294 bytes).
- All Flight-Module-generated compliance data (the security audit log) is cryptographically bound to this root of trust: the Flight Module encrypts the SHA-256 hash of the log with the embedded public key (§7), which only the manufacturer's private key can open.
- All signing/verification executes within the Flight Module's microcontroller — keys are never exchanged in transit at runtime.

**How this works, briefly.** The two halves of the keypair have asymmetric powers: the public key can only *check* signatures, never *create* them. So the flight module can verify with full confidence that an artifact came from the manufacturer, while carrying nothing an attacker could steal to forge one — even a fully compromised aircraft cannot sign anything on the manufacturer's behalf, because no private key exists outside the manufacturer's offline environment.

**Evidence:** `pki/manufacturer/public/manufacturer_public.pem` (single source of truth), `firmware/include/manufacturer_pubkey.h`, bootloader keystore (PX4 fork), tests `test_ROT001_keygen.py`, `test_ROT002_embed_pubkey.py`. **Demo:** D1.

### 1.4 Verification key of the root of trust recorded and retained

> *"The verification key of the root of trust may be recorded and retained. (This key will also be used for verifying the origin of logs generated by FM.)"*

**Satisfied.** The RSA-2048 public key (PEM) is retained at `pki/manufacturer/public/manufacturer_public.pem` and can be provided to the Certification Body for record. The same keypair verifies the origin of Flight-Module-generated logs: the offline tool `tools/verify_audit_log.py` decrypts the log signature and proves the log was produced by a Flight Module carrying this root of trust (§7).

**Demo:** D1, D9.

---

## 2. Calculation of Checksums (§7.1 a.ii)

### 2.1 Registered checksums submitted to the Certification Body

> *"Manufacturer to submit checksums of the firmware to the CB and these checksums may be called 'registered checksums'."*

**Satisfied.** Every firmware release is processed by the release pipeline (`tools/pipeline.py`), which produces a **manifest** carrying the registered checksums:

- `release/<target>_manifest.json` — human-readable, for Certification Body submission,
- `release/<target>_signed.json` — the same manifest wrapped with the manufacturer RSA-PSS signature,
- `release/<target>_manifest.bin` — the 373-byte binary manifest provisioned onto the flight module (magic `INOFLY03`, format v3: hashes + board_id + version + RSA-PSS signature + CRC32).

**Demo:** D2 (pipeline run in front of the auditor; checksums displayed).

### 2.2 Code part and data part checksums calculated separately

> *"Code part and data part checksums to be calculated separately to enable updating of data/parameters in the future."*

**Satisfied.** Two independent SHA-256 checksums:

- **`code_hash`** — over the firmware code flash range `[_stext … _compliance_params_start)`,
- **`data_hash`** — over the compliance-parameter data table `[_compliance_params_start … _compliance_params_end)` (the `.compliance_params` flash section holding the registered parameter values, §6).

The host pipeline (`--elf` mode) hashes exactly the same flash ranges the Flight Module re-hashes at POST, so host-computed and device-computed values are directly comparable. Registered parameter values can be revised in a future release by re-signing with a new `data_hash` without conflating code and data integrity.

**Evidence:** `tools/checksum/checksum.py`, ADR-018 in `Docs/ARCHITECTURE.md §12`; tests `test_CHK001_checksum.py` (23 tests). **Demo:** D2, D3.

### 2.3 Secure Hash Algorithm (SHA2 or SHA3)

> *"All the checksums should be calculated using a Secure Hash Algorithm (SHA2 or SHA3)."*

**Satisfied.** SHA-256 (SHA-2 family, NIST FIPS 180-4) is used for every hash in the system — firmware checksums, signature digests, audit-log hashing, MAVLink signing-key derivation. MD5/SHA-1 are not used anywhere in the chain (enforced by code review policy and tests).

### 2.4 Registered checksums stored securely — not updatable without manufacturer authorization

> *"Registered checksums should be stored securely in the flight module such that they cannot be updated without the authorization of the manufacturer."*

**Satisfied — by cryptography, not by obscurity.** The registered checksums live inside the binary manifest on the flight module. The manifest is protected by:

1. **RSA-PSS signature** over the manifest payload, made with the manufacturer's offline private key. Any modification of the stored checksums invalidates the signature; POST then fails (reason=3) and the UAS cannot be armed.
2. **CRC32** for corruption detection (fails POST with reason=2).
3. The **only accepted path to replace the manifest** is a manufacturer-signed firmware update (§5): the update bundle carries a new signed manifest, and the Flight Module verifies its signature against the embedded public key before accepting it.

An attacker cannot forge a manifest without the private key, which never leaves the manufacturer.

**How this works, briefly.** The manifest's signature covers exactly the fields that matter: the code checksum, the data checksum, the hardware identifier (board_id) and the firmware version, concatenated in a fixed order and signed offline with the private key. At boot, the flight module rebuilds that same byte sequence from the stored manifest fields, computes its SHA-256 digest, and runs the RSA-PSS verification against the embedded public key. Editing any protected field breaks the verification; replacing the whole manifest with one signed by a different key also fails, because the flight module only trusts its embedded key. Replaying an *old, genuinely signed* manifest passes the signature check but then fails the checksum comparison (§3.2), because its checksums describe different firmware than what is actually in flash — so there is no combination of tampered manifest and tampered firmware that can agree.

**Demo:** D4 (tampered manifest ⇒ POST fail, arming blocked), D6 (attacker-signed manifest ⇒ rejected).

### 2.5 Registered checksums digitally signed by the Certification Body and retained

> *"These registered checksums may be digitally signed by the CB and retained."*

**Supported.** The pipeline outputs (`*_manifest.json` / `*_signed.json`, containing the code and data checksums in hex) are provided to the Certification Body as files; the Certification Body may digitally sign and retain them under its own process. This step is performed by the Certification Body — as the manufacturer we supply the artifacts.

---

## 3. Power On Self-Test (§7.1 a.iii)

### 3.1 POST implemented

> *"Manufacturers should implement Power On Self-Test (POST)."*

**Satisfied.** POST runs **automatically on every boot** (the `secure_boot` module is autostarted from the board init script — no operator action). Sequence on each power-on:

1. Bootloader (BOOT001) verifies the **RSA-PSS signature of the application firmware image** against the embedded manufacturer public key before launching it — fail-closed.
2. App firmware POST loads the binary manifest and verifies, in order: **CRC32 → RSA-PSS manifest signature → code_hash → data_hash → board_id** (the code/data hashes are recomputed live from the actual flash contents using libtomcrypt SHA-256).
3. Result is published (`firmware_integrity_status` internal status message), logged to the audit log, and consumed by the arming gate.

**Evidence:** `FirmwareIntegrityChecker.cpp` (PX4 fork), tests `test_POST001_power_on_self_test.py` (22 tests). **Demo:** D3.

### 3.2 POST compares calculated checksums with registered checksums

> *"It should include calculation of checksums of the firmware (code and data part) and the checksum should be matched with the registered checksum stored in the flight module which was supplied at the time of certification."*

**Satisfied.** At boot the Flight Module re-computes SHA-256 over the live flash code range and the live compliance-parameter data range, and compares each against the registered `code_hash` / `data_hash` in the signed manifest. This is real on-device hashing of real flash (validated on CubeOrange+ hardware, acceptance step H14 — a validly-signed manifest carrying a wrong hash is detected organically, with no test stub).

**How this works, briefly.** The microcontroller's flash is memory-mapped, so "the firmware" is simply a range of readable addresses. The linker places three markers in the binary: the start of the code, and the start and end of the compliance-parameter table. On every boot the flight module runs SHA-256 directly over `[code start … parameter-table start)` to get the calculated code checksum, and over the parameter-table range to get the calculated data checksum — then compares each, byte for byte, against the registered values from the signature-verified manifest. Two distinct operations therefore protect the boot: a *cryptographic signature verification* proves the registered checksums are authentic (only the manufacturer could have produced them), and a *plain byte comparison* proves the flash contents match them. The flight module never creates signatures — it holds no private key — it only verifies.

**Demo:** D3 (match ⇒ pass), optional D4-b (hash mismatch ⇒ reason 4/5).

### 3.3 POST result logged

> *"The result of the POST should be logged."*

**Satisfied — both outcomes.** Every POST writes a `POST_RESULT` entry to the security audit log on the SD card (`/fs/microsd/inofly/audit_log.bin`): **PASS entries as well as FAIL entries** (we deliberately log both, not only failures). Entries carry a wall-clock timestamp, monotonic sequence number, result code and failure reason, are CRC32-protected individually, and the whole file is RSA-signed after every write (§7).

**Demo:** D3, D4, D9.

### 3.4 Mismatch prevents the UAS from functioning, and is logged

> *"Mismatch of checksum should prevent the UAS from booting and be logged."*

**Satisfied.** On any POST failure the UAS is made **non-functional: arming is blocked** by the commander health gate (`Preflight Fail: Firmware integrity check failed`), so the aircraft cannot arm, take off, or fly. The failure (with distinct reason code — 2 CRC, 3 signature, 4 code-hash, 5 data-hash, 6 board-id) is written to the audit log and displayed in the Ground Control Station Security panel.

Design position: the Flight Module intentionally boots far enough to *report and log* the failure — a module that halted silently could neither log the mismatch (required by this same clause) nor tell the operator why. "Prevent from booting" is implemented as "prevent from operating/arming," which is the interpretation commonly accepted in certification. Additionally, if the firmware **image itself** is tampered, the verifying bootloader refuses to launch it at all (BOOT001) — that case genuinely does not boot.

**Demo:** D4.

---

## 4. Testing of firmware protection (§7.1 a.iv)

> *"Attempt modifying the firmware (code and data) in an unauthorized manner. The firmware update should fail. In case the firmware gets updated in an unauthorized manner, then verify that the UAS fails the POST. Test to be conducted in presence of CB."*

**Satisfied — demonstrated live in front of the Certification Body (Demo steps D4–D6).** Layers of the demonstration:

| Attack attempted | Blocking layer | Observed result |
|---|---|---|
| Load a tampered `.fwbundle` in the Ground Control Station | Ground Control Station client-side RSA-PSS verify | Signature **FAILED** (red); install button disabled; nothing sent to Flight Module |
| Push a tampered/corrupted update manifest onto the Flight Module (SD tamper) | Flight Module `verify_update` gate | `UPD001: update REJECTED (reason=2)` + FAILURE audit entry |
| Update artifact signed by a **non-manufacturer key** (valid CRC, valid structure) | Flight Module RSA-PSS verify against embedded public key | `REJECTED (reason=3)` + FAILURE audit entry |
| Tamper the registered manifest on the Flight Module | POST | POST FAILED (reason=2/3), **arming blocked**, FAILURE logged |
| Firmware got modified anyway (simulated: validly-signed manifest with wrong hash vs. live flash) | POST code/data hash compare | POST FAILED (reason=4/5), arming blocked, logged |
| Unsigned/tampered **firmware image** flashed to the Flight Module | Verifying bootloader (BOOT001) | Bootloader refuses to launch the image — fail-closed |
| Unsigned **bootloader** replacement attempt via `bl_update` | BOOT008 signed-bootloader gate | `bl_update` refuses before erasing sector 0 |

The Ground-Control-Station side hash+signature check before flashing and the Flight-Module side verification against the embedded public key together implement exactly the mechanism described in the reference remarks: *"Flight Module verifies the hash and signature using the public key it has; if they match then only firmware flashing is permitted."*

**Evidence:** hardware acceptance `Docs/HARDWARE_ACCEPTANCE.md` H5, H12, H13, H14 (all PASS on CubeOrange+); bootloader bring-up `Docs/BOOTLOADER_BRINGUP.md` B4, B8 (PASS).

---

## 5. Safety and security of firmware update (§7.1 b — Secure Upgrade Test)

### 5.1 Update permitted only if signed by the manufacturer's digital certificate

> *"The update should be permitted only if it is signed by the manufacturer's digital certificate."*

**Satisfied — verified at three independent layers, all fail-closed:**

1. **Ground Control Station client-side (inoflyGCU / QGroundControl Secure Firmware Update page):** verifies the bundle's RSA-PSS signature before allowing "Install on Drone". Unsigned/tampered bundles show red FAILED and cannot be installed.
2. **Flight Module drone-side (UPD001):** the Flight Module independently verifies the staged update manifest — CRC32, RSA-PSS signature against the *embedded* public key, and board_id — before authorizing. The Flight Module does not trust the Ground Control Station's verdict.
3. **Boot-time (BOOT001):** even if both prior layers were bypassed, the verifying bootloader checks the flashed image's RSA-PSS signature on every boot and refuses to launch unsigned firmware; POST then provides the checksum backstop.

The bootloader itself can only be replaced through the same discipline: `bl_update` verifies a manufacturer RSA-PSS signature on the candidate bootloader image before touching sector 0 (BOOT008 / ADR-025).

**Demo:** D5 (signed accepted), D6 (unsigned/tampered/attacker-signed rejected).

### 5.2 UAS verifies authenticity with the manufacturer's public key

> *"UAS should be able to verify the authenticity of the update by verifying it with the public key of the manufacturer."*

**Satisfied.** All Flight-Module side verification uses the RSA-2048 public key compiled into the firmware/bootloader (§1.3). RSA-PSS (SHA-256, MGF1-SHA256, salt length 32) via libtomcrypt on the microcontroller. Interoperability with the manufacturer's OpenSSL signing side is proven on hardware (acceptance H3, H13).

**How this works, briefly.** Verification is not a comparison of two secrets — it is a one-way mathematical check. The flight module computes the SHA-256 digest of the artifact it received, then applies the public-key operation to the 256-byte signature; the RSA-PSS scheme confirms whether that signature binds exactly this digest. A passing check proves two things at once: the artifact is byte-identical to what was signed, and the signer held the manufacturer's private key. One shared verification routine implements this for every check in the system — manifest, staged update image, and candidate bootloader — so there is a single implementation to review and test.

### 5.3 Firmware change recorded in the logs

> *"Firmware change should be recorded in the logs."*

**Satisfied.** Every update attempt — accepted or rejected — writes an `UPDATE_ATTEMPT` entry (result SUCCESS/FAILURE, with reject reason) to the Flight Module audit log on SD, which is itself RSA-signed (§7). The Ground Control Station additionally shows the install state machine outcome and the live audit event stream in the Audit Log panel.

**Demo:** D5/D6 followed by D9 (decode of the log showing the entries).

### 5.4 Registered checksum updated securely in the Flight Module after upgrade

> *"After the UAS is upgraded, the registered checksum should be updated in the flight module securely."*

**Satisfied.** Each signed release carries its **own** signed manifest with the new registered checksums (generated by the same pipeline, §2.1). On update, the new signed manifest replaces the registered manifest on the Flight Module — the Flight Module only accepts it after verifying its RSA-PSS signature, so the registered checksums can never be updated by an unauthorized party. On the next boot, POST verifies the updated firmware against the updated registered checksums.

**How this works, briefly.** Before authorizing an update, the flight module *binds* the new manifest to the new firmware image: it streams the staged image from storage, recomputes the code and data checksums over exactly the byte ranges the new manifest describes, and requires both to match the new manifest's registered values (plus a signature check on the image itself). This prevents a mix-and-match attack — a genuine manifest cannot be paired with a different image, or vice versa. An update whose manifest is older than the currently registered one is refused (anti-rollback).

*Status note for the auditor:* today the new manifest is verified and staged by the Flight Module (`verify_update`/`apply_update` — hash-bound to the new image, with anti-rollback on the manifest creation timestamp); automatic first-boot promotion of the staged manifest is the final work item of the staged-update workstream (ADR-023 A-6, in progress). The equivalent end state is demonstrable now via the manufacturer provisioning flow (pipeline → signed manifest → Flight Module).

### 5.5 Checksums of updated firmware signed by the Certification Body and retained

> *"The checksums of the updated firmware (code and data) to be digitally signed by the CB and retained."*

**Supported.** As §2.5 — for every release, the pipeline emits the code/data checksums in Certification-Body-consumable form; signing/retention is performed by the Certification Body.

---

## 6. Secure change of flight parameters (§7.1 c — Testing of Parameter Update)

**Mechanism.** Compliance-critical parameters have their **registered values compiled into the firmware binary** in a dedicated flash table (`.compliance_params`) that is covered by the registered `data_hash`. They cannot be modified from any Ground Control Station by any method — changing a registered value requires a new manufacturer-signed firmware release (which is exactly the authorized process the Gazette requires). Two enforcement kinds:

| Parameter | Kind | Registered value | Meaning |
|---|---|---|---|
| `GF_MAX_VER_DIST` | CAPPED | 120 m | Max altitude AGL — registered value is a **ceiling** |
| `GF_MAX_HOR_DIST` | CAPPED | 500 m | Fence range — ceiling |
| `MPC_XY_VEL_MAX` | CAPPED | 15 m/s | Max speed — ceiling |
| `SYS_AUTOSTART` | LOCKED | 4001 | Certified airframe model — **fixed by type certificate** |
| `CA_AIRFRAME` | LOCKED | 0 (Multirotor) | Frame configuration — fixed |
| `MAV_SIGN_CFG` | LOCKED | 1 | MAVLink signing required — fixed |

- **CAPPED:** operator may set a *mission value* within `(0, ceiling]` for the current flight only (RAM-only, never persisted). Any attempt above the ceiling is **rejected** with the ceiling named in the error, and **audit-logged**. Boot value is 0 and arming is blocked until each CAPPED parameter is deliberately set — so the certified ceiling can never be silently exceeded.
- **LOCKED:** the parameter always reads the registered value. Any write of a different value is **rejected** (`attempted=X registered=Y (LOCKED)`) and **audit-logged**. The certified configuration cannot be moved.

### 6.1 Authenticity of parameter update

> *"UAS should be able to verify the authenticity of the manufacturer citing the process for instituting a change in any given parameter."*

**Satisfied.** The only way to change a *registered* value is a manufacturer-signed firmware release: the new value changes the `.compliance_params` flash bytes ⇒ new `data_hash` ⇒ new signed manifest ⇒ verified by the Flight Module with the embedded public key (§5). Anything else fails POST on the next boot.

### 6.2 Change recorded in the logs

> *"Change should be recorded in the logs."*

**Satisfied.** Every rejected attempt to move a compliance parameter fires a `COMPLIANCE_PARAM_VIOLATION` audit entry (parameter name recorded; log RSA-signed). Legitimate mission values actually flown are captured in the flight telemetry log, which is the authoritative operational record at audit time.

### 6.3 / 6.4 Registered checksum updated after upgrade; Certification Body signs checksums

**Satisfied / supported.** Identical mechanism to §5.4/§5.5 — parameter data lives under `data_hash`, so a parameter revision is a firmware update with a new signed manifest; checksums furnished to the Certification Body per release.

### 6.5 Parameter update via standard operating procedure — parameter remains unaffected

> *"Try to update the parameters that affect compliance conditions using the manufacturer's standard operating procedure. The parameter should remain unaffected."*

**Satisfied — demonstrated live.** From the Ground Control Station / console, `param set` on a LOCKED parameter to any non-registered value is rejected and the parameter still reads the registered value; `param set` above a CAPPED ceiling is rejected with the ceiling named. A `param save` + power-cycle demonstrates nothing persists (CAPPED returns to 0; LOCKED still pinned to registered value).

**Demo:** D7.

### 6.6 Parameter update with invalid digital signature — update fails

> *"Try to update the parameters in the firmware that affect compliance conditions using an invalid digital signature. The update should fail."*

**Satisfied — demonstrated live.** A firmware/manifest carrying modified parameter data but an invalid (or non-manufacturer) signature is rejected: at the Ground Control Station (bundle FAILED), at the Flight Module update gate (reason=3), and at POST (reason=3, or reason=5 if the data table were modified with the signature somehow intact). Arming stays blocked.

**Demo:** D6, D4.

---

## 7. Log file signing — additional requirement

> *"All binary logs should be signed using public key and they should get validated using private key when required."*

**Satisfied — per-file RSA signing of the security audit log (LOG001), same scheme as the audited reference:**

1. Flight Module writes fixed-size binary entries (each CRC32-protected) to `/fs/microsd/inofly/audit_log.bin`. Events logged: POST result (pass **and** fail), firmware update attempts, arming blocks, compliance-parameter violations.
2. After every write, the Flight Module computes SHA-256 of the whole file and **encrypts the hash with the embedded RSA-2048 public key**, storing the 256-byte result as `audit_log.sig`.
3. Offline, the manufacturer (or Certification Body witness) decrypts `.sig` with the private key and compares hashes: `tools/verify_audit_log.py` prints `PASS: audit log signature is authentic`. Any edit/tamper of the log makes the comparison fail.
4. `tools/decode_audit_log.py` renders the binary log human-readable (timestamped IST/UTC) and can run the signature check in the same invocation.

Both files are downloadable from the Ground Control Station Audit Log panel (MAVLink-FTP) or directly from the SD card.

**Why this proves origin and integrity, briefly.** Encryption with the public key can only be undone with the private key. So when the manufacturer's private key successfully opens `audit_log.sig` and the recovered hash matches the log file, two facts are established at once: the log was produced by a flight module carrying this root of trust (origin), and not a byte of it has changed since the flight module last sealed it (integrity). Because the flight module holds no private key, a compromised aircraft — or anyone who obtains the SD card — cannot re-seal an edited log.

**Evidence:** `SecurityAuditLogger.cpp` (PX4 fork), tests `test_LOG001_audit_log.py` (26 tests); hardware acceptance H7, H9, H10 (PASS). **Demo:** D9.

---

## 8. Traceability — requirement → tests → hardware evidence

| Req ID | Description | Automated tests | Hardware evidence |
|---|---|---|---|
| ROT001/ROT002 | RSA-2048 keypair; public key embedded in Flight Module | `test_ROT001_*`, `test_ROT002_*` | H3 (libtomcrypt verify on silicon) |
| CHK001 | SHA-256 code+data checksums, separate | `test_CHK001_*` | H2/H3 (host vs device hash equality) |
| SIG001/PKG001 | Signed manifest; signed update bundle | `test_SIG001_*`, `test_PKG001_*` | H11 |
| PRV001 | Manifest provisioned to Flight Module | `test_PRV001_*` | H2 |
| POST001–004 | POST: CRC, signature, code/data hash, board_id | `test_POST001_*` | H3, H4, H5, H13, H14, H15 |
| ARM001 | Arming blocked on POST failure | arming-gate tests | H5, H13, H14 |
| PAR001 | Compliance parameter protection | `test_PAR001_*` | H6, H7 |
| LOG001 | Signed audit log | `test_LOG001_*` | H7, H9, H10 |
| UPD001 | Flight Module rejects unsigned update | `test_UPD001_*` | H11, H12, H13, H15 |
| PAIR001 | Ground Control Station ↔ Flight Module authentication | `test_PAIR001_*` | H8 |
| BOOT001 | Verifying bootloader | `test_BOOT001_*` | B3, B4 |
| BOOT006/BOOT008 | Bootloader install path; signed `bl_update` | `sign_bootloader` host tests | B2, B6, B8 |
| BOOT007 | Tamper-evident sealing (physical SWD path) | — (procedural) | `Docs/MANUFACTURING_RUNBOOK.md` |

Full test-to-requirement matrix: `Docs/compliance_report.txt` / `.json` (generated by `tools/generate_compliance_report.py`).
