# Audit Demo Script — Copy/Paste Runbook
## DGCA §7.1 live demonstration for the Certification Body

**Purpose.** A step-by-step, copy-paste demonstration you can run in front of the auditor with minimal typing. Each demo step `Dn` maps to a §7.1 clause and to a row in [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md).

**Two ways to run every step:**
- **Bench (hardware) track** — CubeOrange+ over USB. This is the primary demo.
- **SITL track** — WSL2 PX4 SITL, no hardware. Use as a rehearsal or fallback if hardware is unavailable. Steps that are structurally hardware-only (real flash hashing) are flagged.

> **Convention.** `# host$` = Windows PowerShell or WSL host shell. `pxh>` = PX4 SITL console. `nsh>` = hardware console (PX4 nsh over USB, or the QGC MAVLink Console widget). Where a hardware path differs from SITL it is called out inline.

---

## 0. Pre-flight setup (do this BEFORE the auditor arrives)

Nothing below should be typed for the first time during the demo. Run the whole script once end-to-end the day before.

### 0.1 Environment

| | Bench (hardware) | SITL |
|---|---|---|
| FM | CubeOrange+ on carrier, SD seated, **LiPo → power module → POWER1** (USB alone won't boot the FMU), USB → laptop | WSL2 Ubuntu 22.04, `~/PX4-Autopilot` |
| GCS | inoflyGCU (QGC fork) build | same |
| Tooling | this repo (`d:\Projects\Drone`), Python 3.13, OpenSSL | same |
| Passphrase | `dgca_sitl_test` | `dgca_sitl_test` |

### 0.2 One-time artifact generation (host)

```bash
# host$  (repo root: d:\Projects\Drone)
# 1. Refresh the automated compliance report (358 tests) — show this to the auditor first.
python tools/generate_compliance_report.py --run-tests

# 2. Regenerate the signed + tampered demo bundles (UPD001 positive/negative).
py -3 tools/regenerate_test_fixtures.py
#   Expect: test_firmware.fwbundle verify=PASS
#           test_firmware_tampered.fwbundle verify=FAIL

# 3. Regenerate the attacker-key fixtures (reason=3 signature-mismatch path).
py -3 tools/regenerate_attacker_fixtures.py
#   Output lands in .attacker_fixtures/ (gitignored). The tool aborts if any
#   attacker artifact accidentally verifies under the manufacturer key.
```

### 0.3 SITL bring-up (SITL track only)

```bash
# wsl$
cd ~/PX4-Autopilot && make px4_sitl none_iris     # leave running in its own terminal
# In another terminal, from the repo:
python3 tools/provisioning/provision_sitl.py       # writes signed manifest.bin
tools/sitl_ftp_symlink.sh                          # FTP path parity (needed for D9)
```

### 0.4 Hardware bring-up (bench track only)

Firmware is already flashed and provisioned from Tier-1 acceptance. To re-provision from a fresh build:

```bash
# wsl$
BUILD=~/PX4-Autopilot/build/cubepilot_cubeorangeplus_default
python tools/pipeline.py \
    $BUILD/cubepilot_cubeorangeplus_default.px4 \
    --board-id 1063 \
    --elf $BUILD/cubepilot_cubeorangeplus_default.elf \
    --output-dir release/
# Copy release/cubepilot_cubeorangeplus_default_manifest.bin → SD /fs/microsd/inofly/manifest.bin
```

**Provision the MAVLink signing key** (for D8):
```bash
python tools/provisioning/provision_signing_key.py --drone-id DEMO01 --passphrase dgca_sitl_test
# → key file to SD /fs/microsd/mavlink/mavlink-signing-key.bin
```

---

## Demo running order (≈20–25 min)

| Step | §7.1 clause | Shows | Track |
|---|---|---|---|
| D0 | all | Automated compliance report — 358 tests green | host |
| D1 | a.i.c/d | Root of trust — the manufacturer keypair | host |
| D2 | a.ii | Release pipeline produces signed manifest + separate code/data checksums | host |
| D3 | a.iii | POST passes on boot; integrity status published | FM |
| D4 | a.iii.d / a.iv | Tamper the manifest → POST fails → arming blocked → logged | FM |
| D5 | b | Signed firmware update accepted | GCS+FM |
| D6 | a.iv / b | Unsigned / tampered / attacker-signed update rejected (3 layers) | GCS+FM |
| D7 | c | Compliance parameter cannot be changed (CAPPED + LOCKED) | FM |
| D8 | a.i.b | GCS↔FM authentication (MAVLink signing) | GCS+FM |
| D9 | §8 | Signed audit log — decode + offline signature verify | host |

---

## D0 — Automated compliance evidence (host)

> **Clause:** whole of §7.1. **Talking point:** "Before the live tests, here is the machine-checked evidence — every requirement is mapped to tests, and they all pass."

```bash
# host$
python tools/generate_compliance_report.py --run-tests
type Docs\compliance_report.txt        # (PowerShell)   —  or:  cat Docs/compliance_report.txt
```

**Expected:** `Total tests: 358  Passed: 358  Failed: 0`; `OVERALL VERDICT: PASS` (13 PASS host-tested + 3 HARDWARE_VALIDATED for POST002/003/004). Hand the auditor `Docs/compliance_report.txt` and [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md).

---

## D1 — Root of trust: the manufacturer keypair (host)

> **Clause:** §7.1 a.i (c) root of trust, (d) verification key retained.

```bash
# host$  — show the retained public key (root-of-trust verification key)
openssl rsa -in pki/manufacturer/public/manufacturer_public.pem -pubin -text -noout | findstr /C:"Public-Key"
#   → Public-Key: (2048 bit)

# Show the SAME key is embedded in the firmware as a C header (what the FM verifies with).
type firmware\include\manufacturer_pubkey.h | more
```

**Talking points:**
- One RSA-2048 keypair is the root of trust. The **private key never leaves** the offline signing machine.
- The **public key** is retained for the CB (`manufacturer_public.pem`) and is compiled into both the bootloader and the app firmware — the FM verifies every signature against it and encrypts audit-log hashes with it.

---

## D2 — Release pipeline: signed manifest + separate checksums (host)

> **Clause:** §7.1 a.ii (a) registered checksums, (b) code/data separate, (c) SHA-2, (d) stored securely.

```bash
# host$  — run the full release pipeline on a firmware image
python tools/pipeline.py test_firmware.px4 --output-dir release/

# Show the registered checksums (code and data, separate) in the human-readable manifest:
type release\test_firmware_manifest.json        # look for "code_checksum" and "data_checksum" (SHA-256 hex)
#   (these become code_hash / data_hash in the binary manifest and in the device's POST output)

# Show the signed wrapper and the binary manifest that gets provisioned to the FM:
dir release\test_firmware_signed.json release\test_firmware_manifest.bin
```

**Talking points:**
- `code_hash` and `data_hash` are **independent SHA-256** values — code and data checksummed separately, so parameters/data can be revised in a future release without re-checksumming code.
- `*_manifest.json` / `*_signed.json` are the artifacts we submit to the CB. `*_manifest.bin` (373 bytes, magic `INOFLY03`) is what lives on the flight module, protected by an RSA-PSS signature + CRC32 — it cannot be altered without the private key.

---

## D3 — POST passes on boot; integrity published (FM)

> **Clause:** §7.1 a.iii (a) POST implemented, (b) checksums matched, (c) result logged.

**Bench:** power-cycle the CubeOrange+ (POST autostarts). **SITL:** SITL is already running from D0.3.

```
# nsh>   (hardware)   or   pxh>   (SITL)
listener firmware_integrity_status
```

**Expected:**
- `check_passed: True`
- `failure_reason: 0`
- **Hardware:** non-zero real `code_hash` / `data_hash` (live libtomcrypt SHA-256 of flash) that equal the manifest — this is the real on-silicon hashing SITL cannot show.
- Boot log shows `Pre-operational self-test passed`.

```
# confirm the PASS was logged (both outcomes are logged, not just failures):
secure_boot audit_status
```

**Talking point:** POST runs automatically on every boot, re-computes the code and data checksums from live flash, compares them to the registered checksums in the signed manifest, and logs the result.

---

## D4 — Tamper → POST fails → arming blocked → logged (FM)

> **Clause:** §7.1 a.iii (d) mismatch prevents operation + logged; §7.1 a.iv firmware protection.

**SITL:**
```bash
# host/wsl$ — flip one byte of the provisioned manifest
python3 -c "p='$HOME/PX4-Autopilot/build/px4_sitl_default/rootfs/inofly/manifest.bin'; d=bytearray(open(p,'rb').read()); d[40]^=0xFF; open(p,'wb').write(d)"
```
Restart SITL, then:
```
pxh> commander check
pxh> commander arm
```

**Bench:** power down, mount the SD, flip one byte in `/fs/microsd/inofly/manifest.bin`, reboot, then at `nsh>`: `commander check` / `commander arm` (props OFF).

**Expected:**
- POST FAILED with `reason=2` (CRC) — `firmware_integrity_status.check_passed=false`.
- `commander arm` → **rejected**: `Preflight Fail: Firmware integrity check failed`.
- `commander check` names the firmware-integrity failure.
- A `POST_RESULT` FAILURE entry is written to the audit log.

**Restore** the good manifest (SITL: `python3 tools/provisioning/provision_sitl.py`; bench: restore the saved copy) and confirm POST passes again before continuing.

**Optional D4-b (hardware only — organic hash mismatch, reason 4/5):** provision a validly-signed manifest carrying a wrong hash and show reason=4/5:
```bash
# wsl$ — build a validly-signed manifest with a deliberately wrong code hash
python tools/make_hash_mismatch_manifest.py \
    release/cubepilot_cubeorangeplus_default_manifest.bin \
    --mutate code --output /tmp/wrong_code_manifest.bin
# copy onto SD as manifest.bin, reboot → POST FAILED reason=4 (data → reason=5)
```

**Talking point:** any unauthorized change to firmware or to the registered checksums is caught at boot and the aircraft is prevented from arming/flying, with the event logged. Distinct reason codes (2 CRC, 3 signature, 4 code-hash, 5 data-hash, 6 board-id) show exactly which check failed.

---

## D5 — Signed firmware update accepted (GCS + FM)

> **Clause:** §7.1 b (i) signed-only, (ii) authenticity verified, (iii) recorded, (iv) checksum updated.

1. In inoflyGCU (QGC): **Vehicle Setup → Secure Firmware Update**. **Browse** and load `test_firmware.fwbundle`.
2. Signature Verification turns **green VERIFIED**.
3. Click **Install on Drone** (enabled only when Verified).

**Expected:**
- GCS: install state machine reaches **ACCEPTED**.
- FM SD: `/fs/microsd/inofly/update_manifest.bin` present (373 bytes, fresh timestamp).
- One `UPDATE_ATTEMPT` SUCCESS audit entry.
- SHA-256 cross-check (transport integrity):
```bash
# host$
py -3 -c "import zipfile,hashlib; d=zipfile.ZipFile('test_firmware.fwbundle').read('update_manifest.bin'); print(hashlib.sha256(d).hexdigest())"
# compare to sha256 of the staged file on the FM SD
```

**Talking point:** the update carries its own signed manifest with the new registered checksums; the FM only stages it after verifying the manufacturer signature — so registered checksums are updated only through an authorized, signed update.

---

## D6 — Unsigned / tampered / attacker-signed update rejected (GCS + FM)

> **Clause:** §7.1 a.iv, b (i). Three independent fail-closed layers.

**6.A — GCS client-side reject.** In QGC, **Clear**, then **Browse** and load `test_firmware_tampered.fwbundle`.
- **Expected:** Signature Verification **red FAILED**; "Install on Drone" hidden/disabled; nothing sent to FM.

**6.B — FM drone-side reject (CRC, reason=2).** Simulate SD tamper after a legitimate stage (needs D5 done first):
```bash
# SITL:
python3 -c "p='$HOME/PX4-Autopilot/build/px4_sitl_default/rootfs/inofly/update_manifest.bin'; d=bytearray(open(p,'rb').read()); d[50]^=0xFF; open(p,'wb').write(d)"
```
```
pxh>  (or nsh>)   secure_boot verify_update
```
- **Expected (reason=2 is the authoritative assertion):** console shows `CRC mismatch (stored=0x… computed=0x…)` then `Staged update REJECTED (reason=2) - nothing will be flashed`; one `UPDATE_ATTEMPT` FAILURE entry. Cleanup: `secure_boot clear_update`.

**6.C — Attacker-signed reject (signature, reason=3).** Uses `.attacker_fixtures/` (D0.2). Stage the attacker-signed manifest and verify:
```bash
# copy .attacker_fixtures/attacker_update_manifest.bin onto the FM as update_manifest.bin
```
```
pxh>  (or nsh>)   secure_boot clear_update; secure_boot verify_update
```
- **Expected (reason=3 is the authoritative assertion):** console shows `signature is not from the manufacturer` / `Firmware update REJECTED - it is not a valid manufacturer-signed update` then `Staged update REJECTED (reason=3) - nothing will be flashed` — proves the signature branch is live, not dead code (CRC is valid here; only the signature-vs-embedded-pubkey check fails). Cleanup: `secure_boot clear_update`.

**Talking point:** the drone does not trust the GCS's verdict — it re-verifies independently. Unsigned, corrupted, and attacker-signed updates are all refused, each with a distinct reason code, each logged.

---

## D7 — Compliance parameter cannot be changed (FM)

> **Clause:** §7.1 c (v) SOP update leaves parameter unaffected, (vi) invalid-signature update fails.

Run at `pxh>` / `nsh>`:

**CAPPED (ceiling) — e.g. `GF_MAX_VER_DIST`, registered 120 m:**
```
param show GF_MAX_VER_DIST          # → 0 at boot (must be set deliberately before arming)
param set GF_MAX_VER_DIST 200       # → REJECTED: ceiling is 120  (audit-logged)
param set GF_MAX_VER_DIST 100       # → accepted (RAM-only mission value)
param save
```
Reboot → `param show GF_MAX_VER_DIST` → **0** again (nothing persisted).

**LOCKED (fixed) — e.g. `CA_AIRFRAME`, registered 0:**
```
param show CA_AIRFRAME              # → 0 (registered value, via kind-aware read)
param set CA_AIRFRAME 2             # → REJECTED: attempted=2 registered=0 (LOCKED)  (audit-logged)
param set CA_AIRFRAME 0             # → accepted no-op (value unchanged)
```
Reboot → still `0`.

**Pre-arm gate:** with a CAPPED parameter still at 0, `commander arm` is denied and `commander check` names the offending CAPPED parameter.

**Talking point:** compliance parameters are compiled into the signed firmware (covered by `data_hash`). No GCS can move them. The only way to change a registered value is a new manufacturer-signed release — the authorized process. Every rejected attempt is logged (D9).

---

## D8 — GCS ↔ FM authentication (MAVLink signing) (GCS + FM)

> **Clause:** §7.1 a.i (b) communication requirement; PAIR001.

**Prereq:** signing key provisioned (D0.4). In QGC: **Application Settings → MAVLink → Signing → Add Key**.

1. Connect QGC with the **wrong** passphrase → **no telemetry** (FM drops unsigned/mis-signed messages).
2. Connect QGC with `dgca_sitl_test` → **full bidirectional link**.

**Talking point:** the FM only accepts commands from a GCS that knows the per-drone passphrase (key = `SHA256(passphrase)`). `MAV_SIGN_CFG=1` is a LOCKED parameter (D7), so signing cannot be turned off at runtime.

---

## D9 — Signed audit log: decode + offline verification (host)

> **Clause:** additional log-file-signing requirement; §7.1 a.iii.c / b.iii / c.ii (events recorded).

1. In QGC **Audit Log panel**: click **Download Log** and **Download Signature** (or pull `audit_log.bin` + `audit_log.sig` from the SD directly). A real hardware-captured log is already staged at `release/sd/audit_log.bin` (+ `.sig`) from the bench acceptance session — usable as a ready fallback fixture if you don't want to pull a fresh one live.
2. Decode and verify offline:
```bash
# host$   (swap in release/sd/audit_log.bin to use the staged bench fixture)
python tools/decode_audit_log.py Docs/audit_log.bin
#   → human-readable, timestamped (IST + UTC): POST results (pass & fail),
#     UPDATE_ATTEMPT entries from D5/D6, COMPLIANCE_PARAM_VIOLATION from D7

python tools/verify_audit_log.py \
    --log Docs/audit_log.bin \
    --sig Docs/audit_log.sig \
    --key pki/manufacturer/private/manufacturer_private.pem
#   → PASS: audit log signature is authentic
```
3. **Tamper demonstration:** flip one byte of `audit_log.bin` and re-run `verify_audit_log.py` → it now reports failure, proving edits are detectable.

**Talking point:** the whole log is SHA-256-hashed and the hash encrypted with the embedded public key after every write. Only the manufacturer's private key opens it — so log origin and integrity are provable offline, and any edit is caught.

---

## Appendix A — `secure_boot` console subcommands (FM)

| Command | Purpose |
|---|---|
| `secure_boot start` | Start the module (autostarts at boot; manual call is a no-op if already running) |
| `secure_boot audit_status` | Show audit-log entry count / state |
| `secure_boot param_status` | Show compliance-parameter guard state |
| `secure_boot verify_update` | Verify a staged `update_manifest.bin` (CRC → signature → board_id) |
| `secure_boot clear_update` | Drop staged update state |
| `listener firmware_integrity_status` | Show the POST result (uORB) |
| `commander check` / `commander arm` | Exercise the arming gate |

There is **no** `secure_boot status` subcommand — use `audit_status` + `listener firmware_integrity_status`.

## Appendix B — Reason-code reference

**POST (`firmware_integrity_status.failure_reason`):** 0 pass · 2 manifest CRC · 3 manifest signature · 4 code-hash mismatch · 5 data-hash mismatch · 6 board-id mismatch.

**Update gate (`FirmwareUpdateAuthorization`, separate enum):** 1 no manifest · 2 CRC corrupt · 3 signature invalid · 4 board-id mismatch.

> **On expected console output:** the **reason code** is the authoritative, stable assertion for each test — verify that first. The exact wording of console `PX4_ERR/WARN` strings can vary between firmware builds; the strings quoted in this script match the current source (PX4 fork `c4aa2811eb`) but treat them as indicative, not verbatim contracts. If a string differs but the reason code is correct, the test has passed.

## Appendix C — If something goes wrong mid-demo

- **POST unexpectedly fails at D3:** you likely left a tampered manifest from a prior D4/D6 run. Re-provision (SITL `provision_sitl.py`; bench restore good `manifest.bin`) and reboot.
- **QGC won't connect at D8:** confirm the signing key on SD matches the passphrase, or remove the key temporarily to show the unsigned baseline.
- **Audit panel empty at D9:** the logger must be running (it autostarts). Confirm `secure_boot audit_status` shows entries; on SITL confirm `tools/sitl_ftp_symlink.sh` was run.
- **Fallback:** if hardware misbehaves, run the same step on the SITL track — the security logic is identical; only real-flash hashing (D3 values, D4-b) is hardware-specific.
