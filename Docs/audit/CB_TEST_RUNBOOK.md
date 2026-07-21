# CB Test Runbook — Hardware (CubeOrange+)
## Copy/paste steps for the witnessed §7.1 test session

**What this is.** The exact sequence to run in front of the Certification Body on the CubeOrange+ bench unit, using the pre-generated artifacts in [`cb_test_kit/`](cb_test_kit/). Every negative test uses a ready file — you never hand-edit anything during the demo. Each step lists the artifact, the command, and the expected reason code, and maps to the requirement it proves.

**Coverage.** This runbook covers **every §7.1 clause** (a firmware tamper avoidance, b secure update, c parameter change) plus §8 log signing, and reproduces the full hardware-acceptance set **H2–H15**. See the coverage checklist at the end.

> Internal reference — the operator's script. The auditor-facing narrative is in the Compliance Document.

---

## 0. Before the session

### 0.1 Kit must match the firmware on the unit
The kit's negative artifacts are tied to the **exact build flashed on the unit**. The shipped kit is generated from the B9 bench build:

| | Value |
|---|---|
| Board ID | 1063 |
| code_hash | `2078492570…c02c5d` |
| data_hash | `a3e97baed0…c1dffb` |

If the unit runs a **different** build, regenerate first:
```bash
py -3 tools/build_cb_test_kit.py --manifest <that build>_manifest.bin --bundle <that build>.fwbundle
```
Confirm on the unit that `listener firmware_integrity_status` shows a `code_hash` starting `20 78 49 25` before starting.

### 0.2 Bench setup (H0/H1 prerequisites)
- Unit already flashed with the matching `secure_boot` app firmware, provisioned with `good_manifest.bin`, sealed as per manufacturing.
- CubeOrange+ on carrier, SD seated, **LiPo → power module → POWER1** (USB alone won't boot the FMU). USB → laptop.
- Console: PX4 **nsh over USB** or the QGC **MAVLink Console** widget (prompt shown as `nsh>`).
- Kit folder open on the host: `Docs/audit/cb_test_kit/`.

### 0.3 Putting a file on the SD
- **A — mount the SD on the host**, copy into `\inofly\` (power the unit down first), or
- **B — QGC MAVLink-FTP** to `/fs/microsd/inofly/`.

SD paths:
```
/fs/microsd/inofly/manifest.bin          (POST reads this)
/fs/microsd/inofly/update_manifest.bin   (secure_boot verify_update reads this)
/fs/microsd/mavlink/mavlink-signing-key.bin  (PAIR001 key)
```

---

# Section A — Root of trust & registered checksums (host)  (§7.1 a.i.c/d, a.ii)

These are shown once on the host to establish the chain before the on-unit tests.

## A1. Root of trust — the retained verification key  (§7.1 a.i.c / a.i.d)
```bash
# host — show the retained RSA-2048 public verification key
openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -noout -text | findstr /C:"Public-Key"
     → Public-Key: (2048 bit)
```
**Talking point:** one RSA-2048 keypair is the root of trust. The **private key stays offline** at the manufacturer; this **public key is retained for the CB** and is what the flight module uses to verify every signature and to bind the audit log (step 11). *(a.i.a Level-1 determination is architectural — see the Compliance Document / Annexure E; nothing to run.)*

## A2. Registered checksums — code and data, separate SHA-256  (§7.1 a.ii.a/b/c)
```bash
# host — the registered checksums that were submitted for this build
type Docs\audit\cb_test_kit\good_manifest.json    # look for code_checksum + data_checksum
```
**Expect:** two **independent SHA-256** values — `code_checksum` (2078…) and `data_checksum` (a3e9…) — and `"algorithm": "SHA-256"`. These are the registered checksums the drone re-computes and matches at POST (steps 1, 4, 5). Code and data are checksummed separately so parameters/data can be revised in a future signed release. *(a.ii.d "stored securely, not updatable without the manufacturer" is proven live in steps 2–4; a.ii.e "CB may sign the checksums" is a CB action.)*

---

# Section B — On the unit (H2–H15)

## 1. POST passes on boot  (§7.1 a.iii.a/b — reason 0)   [H3/H4]
Ensure the good manifest is on SD:
```
copy  cb_test_kit\good_manifest.bin  → SD  /fs/microsd/inofly/manifest.bin
```
Power-cycle (POST autostarts), then:
```
nsh> listener firmware_integrity_status
     → check_passed: True, failure_reason: 0
```
**Expect:** boot log `Pre-operational self-test passed`; real `code_hash`/`data_hash` match the manifest (live libtomcrypt hashing on real flash).

## 2. Tamper → POST fails → arming blocked  (§7.1 a.iii.d / a.iv — reason 2)   [H5]
```
copy  cb_test_kit\tampered_manifest.bin  → SD  /fs/microsd/inofly/manifest.bin
```
Power-cycle:
```
nsh> listener firmware_integrity_status   → check_passed: False, failure_reason: 2
nsh> commander arm                         → denied (Preflight Fail: Firmware integrity check failed)
```
**Expect:** POST FAILS `reason=2` (manifest CRC), arming blocked, `POST_RESULT` FAILURE logged.
**Restore:** copy `good_manifest.bin` back, power-cycle, POST PASS.

## 3. Attacker-signed manifest → POST fails  (§7.1 a.iv / b.ii — reason 3)   [H13.A]
```
copy  cb_test_kit\attacker_manifest.bin  → SD  /fs/microsd/inofly/manifest.bin
```
Power-cycle:
```
nsh> listener firmware_integrity_status   → check_passed: False, failure_reason: 3
```
**Expect:** POST FAILS `reason=3`. CRC is valid here — only the RSA-PSS check against the embedded manufacturer key fails, proving the signature branch is live and that only manufacturer-signed data is trusted. Arming blocked, FAILURE logged.
**Restore:** `good_manifest.bin`, POST PASS.

## 4. Firmware changed → code-hash mismatch  (§7.1 a.iii.b — reason 4)   [H14.A]
```
copy  cb_test_kit\wrong_code_hash_manifest.bin  → SD  /fs/microsd/inofly/manifest.bin
```
Power-cycle:
```
nsh> listener firmware_integrity_status   → check_passed: False, failure_reason: 4
```
**Expect:** boot log `Firmware code check FAILED - code changed since signing`; `reason=4`. A **validly signed** manifest whose `code_hash` doesn't match the live flash — the on-silicon hash compare. Arming blocked, FAILURE logged.
**Restore:** `good_manifest.bin`, POST PASS.

## 5. Parameter data changed → data-hash mismatch  (§7.1 a.iii.b / c — reason 5)   [H14.B]
```
copy  cb_test_kit\wrong_data_hash_manifest.bin  → SD  /fs/microsd/inofly/manifest.bin
```
Power-cycle:
```
nsh> listener firmware_integrity_status   → check_passed: False, failure_reason: 5
```
**Expect:** boot log `Flight-parameter check FAILED - parameters changed since signing`; `reason=5` (code_hash correct, data_hash wrong — the compliance-parameter table integrity check). Arming blocked, FAILURE logged.
**Restore:** `good_manifest.bin`, POST PASS.

## 6. Compliance parameters cannot be changed  (§7.1 c.v / c.vi)   [H6]
No file — run at the console:
```
nsh> param set GF_MAX_VER_DIST 200     → REJECTED (attempted=200.000 ceiling=120.000)   [audit-logged]
nsh> param set GF_MAX_VER_DIST 100     → accepted (RAM-only mission value)
nsh> param set CA_AIRFRAME 2           → REJECTED (attempted=2 registered=0 (LOCKED))    [audit-logged]
nsh> param set CA_AIRFRAME 0           → accepted (no-op)
nsh> param save
```
Power-cycle → `param show GF_MAX_VER_DIST` returns 0 (nothing persisted).
**Expect:** over-ceiling and non-registered writes rejected; a `COMPLIANCE_PARAM_VIOLATION` entry per rejected write. This proves c.v (SOP change leaves the parameter unaffected) and c.vi (an invalid change fails). Reason/behavior is the authoritative assertion; console wording is indicative.

## 7. GCS↔FM authentication — MAVLink signing  (§7.1 a.i.b — communication requirement)   [H8]
Provision a per-drone signing key (host), then test the link:
```bash
# host
py -3 tools/provisioning/provision_signing_key.py --drone-id DEMO01 --passphrase dgca_sitl_test
# → writes mavlink-signing-key.bin to SD /fs/microsd/mavlink/
```
In QGC → **Application Settings → MAVLink → Signing → Add Key**:
1. Connect with a **wrong** passphrase → **no telemetry** (FM drops mis-signed messages).
2. Connect with `dgca_sitl_test` → **full bidirectional link**.

**Expect:** only a GCS that knows the passphrase (key = `SHA256(passphrase)`) can command the drone. `MAV_SIGN_CFG=1` is a LOCKED compliance parameter (step 6) — signing cannot be turned off at runtime. This is the Annexure E communication requirement, exceeded (32-byte HMAC-SHA256 vs an 8-byte UID).

## 8. Signed firmware update accepted  (§7.1 b.i–b.iv)   [H11]
In QGC → **Secure Firmware Update** → **Browse** → `cb_test_kit\good_firmware.fwbundle`.
```
Signature Verification → green VERIFIED
click Install on Drone  → reaches ACCEPTED
```
**Expect:** `/fs/microsd/inofly/update_manifest.bin` appears (373 B, fresh); one `UPDATE_ATTEMPT` SUCCESS entry. The bundle targets board 1063, so the FC board-id gate passes and its new signed manifest carries the updated registered checksums (b.iv).

## 9. Unsigned/tampered/attacker update rejected — QGC client side  (§7.1 a.iv / b.i)   [H12.A / H13.B]
In QGC → **Clear** → **Browse** →:
- `cb_test_kit\tampered_firmware.fwbundle` → Signature **red FAILED**; Install hidden.
- `cb_test_kit\attacker_firmware.fwbundle` → Signature **red FAILED** (signed with a non-manufacturer key).

**Expect:** QGC refuses both before any upload — nothing sent to the FC.

## 10. Update gate rejects at the FC  (§7.1 a.iv / b.i)   [H12.B / H13.C / H15]
Stage a file as `update_manifest.bin`, run `secure_boot verify_update`, start each clean with `clear_update`.

**10.a CRC (reason 2)** [H12.B]:
```
copy  cb_test_kit\tampered_update_manifest.bin → SD /fs/microsd/inofly/update_manifest.bin
nsh> secure_boot verify_update
     → CRC mismatch (...) ; Staged update REJECTED (reason=2) - nothing will be flashed
nsh> secure_boot clear_update
```
**10.b Attacker signature (reason 3)** [H13.C]:
```
copy  cb_test_kit\attacker_update_manifest.bin → SD /fs/microsd/inofly/update_manifest.bin
nsh> secure_boot verify_update
     → signature is not from the manufacturer ; Staged update REJECTED (reason=3)
nsh> secure_boot clear_update
```
**10.c Wrong board_id (reason 4)** [H15]:
```
copy  cb_test_kit\wrong_boardid_update_manifest.bin → SD /fs/microsd/inofly/update_manifest.bin
nsh> secure_boot verify_update
     → board_id 1064 does not match this hardware (1063) ; Staged update REJECTED (reason=4)
nsh> secure_boot clear_update
```
**10.d Positive control (accept)**:
```
copy  cb_test_kit\good_update_manifest.bin → SD /fs/microsd/inofly/update_manifest.bin
nsh> secure_boot verify_update
     → Firmware update accepted - manufacturer signature verified
nsh> secure_boot clear_update
```
**Expect:** each negative rejected with its distinct reason code + an `UPDATE_ATTEMPT` FAILURE entry; the positive accepts. The FC re-verifies independently of QGC.

## 11. Signed audit log  (§8, and §7.1 a.iii.c / b.iii / c.ii)   [H7 / H9 / H10]
The log is exercised **throughout** — every step above wrote a signed entry.

**11.a Events logged live** — keep the QGC **Audit Log panel** open during steps 1–10.
**Expect:** entries appear live (backfill within ~5 s of connect, then in real time), newest-first, no dupes. By now the log holds: `POST_RESULT` PASS (steps 1 + restores) and FAIL reason 2/3/4/5 (steps 2–5); `COMPLIANCE_PARAM_VIOLATION` (step 6); `UPDATE_ATTEMPT` SUCCESS (step 8) and FAILURE reason 2/3/4 (step 10). This is a.iii.c (POST logged), b.iii (firmware change logged), c.ii (parameter change logged).

**11.b Persistence** — power-cycle, reopen the panel.
**Expect:** all prior entries still present (real SD, not volatile); sequence numbers monotonic and continuing.

**11.c Download** — QGC Audit Log panel → **Download Log** (`audit_log.bin`) + **Download Signature** (`audit_log.sig`), or pull both from the SD.

**11.d Decode (readable):**
```bash
py -3 tools/decode_audit_log.py audit_log.bin
```
**Expect:** each entry with IST+UTC timestamp, event type, result — e.g. `POST FAILED - manifest CRC failed [POST001]`, `Attempted to change GF_MAX_VER_DIST - rejected (protected flight parameter) [PAR001]`; every entry `CRC OK`.

**11.e Offline signature verification (origin + integrity):**
```bash
py -3 tools/verify_audit_log.py --log audit_log.bin --sig audit_log.sig \
    --key pki/manufacturer/private/manufacturer_private.pem
     → PASS: audit log signature is authentic
```
**Expect:** the whole-file SHA-256 decrypted from `.sig` with the manufacturer **private** key matches the log — proving the log came from an FM carrying this root of trust and was not edited.

**11.f Tamper is detectable:**
```bash
py -3 -c "d=bytearray(open('audit_log.bin','rb').read()); d[80]^=0xFF; open('audit_log.bin','wb').write(d)"
py -3 tools/verify_audit_log.py --log audit_log.bin --sig audit_log.sig --key pki/manufacturer/private/manufacturer_private.pem
     → FAIL: decrypted hash does not match SHA-256(log)
```
Re-download the clean log afterwards if needed.

**Console-only fallback (no QGC panel):** `secure_boot audit_status` shows the entry count on the unit; pull `audit_log.bin` + `audit_log.sig` from the SD and run 11.d/11.e/11.f on the host. The panel steps (11.a/11.b) are the only ones that need QGC; the signed-log proof does not.

> **Scope note.** This is the **security event log** (POST, updates, parameter violations), signed per-file. The *flight telemetry* log (altitude/speed flown) is a separate PX4 log — the operational record, not this file.

---

## Reason-code quick reference

| | 0 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| **POST** (`failure_reason`) | pass | manifest CRC | manifest signature | code-hash | data-hash | board-id |
| **verify_update** (separate enum) | — | CRC | signature | board-id | — | — |

## Restore-to-clean (between/after tests)
```
copy  cb_test_kit\good_manifest.bin → SD /fs/microsd/inofly/manifest.bin
nsh>  secure_boot clear_update
(power-cycle) → confirm POST PASS
```

---

## §7.1 coverage checklist (confirm every clause is demonstrated)

| §7.1 clause | Requirement | Where demonstrated | Artifact |
|---|---|---|---|
| a.i.a | Flight-module Level 1 | Architectural (Compliance Doc / Annexure E) | — |
| a.i.b | Communication requirement | **Step 7** (MAVLink signing) | signing key |
| a.i.c | Root of trust signs FM data | **A1** + step 11 (log bound to key) | pubkey |
| a.i.d | Verification key retained | **A1** | manufacturer_public.pem |
| a.ii.a | Registered checksums submitted | **A2** | good_manifest.json |
| a.ii.b | Code + data checksums separate | **A2** | good_manifest.json |
| a.ii.c | Secure Hash Algorithm (SHA-2) | **A2** (SHA-256) | good_manifest.json |
| a.ii.d | Checksums not updatable w/o mfr | **Steps 2–4** | tampered/attacker/wrong_code |
| a.ii.e | CB may sign checksums | CB action | — |
| a.iii.a | POST implemented | **Step 1** | good_manifest.bin |
| a.iii.b | POST matches checksums | **Steps 4, 5** | wrong_code / wrong_data |
| a.iii.c | POST result logged | **Step 11** | audit_log.bin/.sig |
| a.iii.d | Mismatch prevents operation + logged | **Steps 2–5** + 11 | tampered_manifest.bin |
| a.iv | Firmware-protection testing | **Steps 2–5, 9, 10** | tampered/attacker/wrong_* |
| b.i | Update signed-only | **Steps 8, 9, 10** | good/tampered/attacker bundle |
| b.ii | Verify with public key | **Steps 3, 10.b** | attacker artifacts |
| b.iii | Firmware change logged | **Steps 8, 10 → 11** | audit log UPDATE_ATTEMPT |
| b.iv | Registered checksum updated after upgrade | **Step 8** | good_firmware.fwbundle |
| b.v | CB signs updated checksums | CB action | — |
| c.i | Parameter-update authenticity | **Steps 5, 6** | wrong_data + console |
| c.ii | Parameter change logged | **Step 6 → 11** | audit log PARAM_VIOLATION |
| c.iii/iv | Registered checksum updated / CB signs | Steps 5/8 + CB action | — |
| c.v | SOP change leaves parameter unaffected | **Step 6** | (console) |
| c.vi | Invalid-signature change fails | **Steps 3, 10.b** | attacker artifacts |
| §8 | Log file signing | **Step 11** | audit_log.bin/.sig |

## H-test cross-reference (hardware acceptance)
A1/A2 ≈ host-side of H2 · 1 = H3/H4 · 2 = H5 · 3 = H13.A · 4 = H14.A · 5 = H14.B · 6 = H6 · 7 = H8 · 8 = H11 · 9 = H12.A + H13.B · 10 = H12.B + H13.C + H15 · 11 = H7 + H9 + H10. (H0/H1 = bench bring-up prerequisites, §0.)
