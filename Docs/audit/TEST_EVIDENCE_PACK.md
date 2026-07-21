# Test Evidence Pack — DGCA §7.1
## Captured evidence per compliance test (CubeOrange+ hardware)

**Purpose.** The §7.1(a.iv) firmware-protection test is conducted "in presence of Certification Body," and a formal compliance submission presents captured evidence (screenshots / console output) for each test. This pack collects the **actual recorded outputs** from the CubeOrange+ bench acceptance sessions, mapped to the demo steps (`Dn`) in [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md) and the clauses in [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md).

**Last updated:** 2026-07-10 · **Source:** `Docs/HARDWARE_ACCEPTANCE.md` bench sessions (2026-05 → 2026-06), PX4 fork noted per item.

> **How to use during the Certification Body witness session.** These are the *reference* captures proving each test passed on hardware. During the witnessed session you will re-run the same steps live (per the demo script) and the auditor compares the live output to these captures. For the formal submission, add a **screenshot** of each QGroundControl-side result (Security panel, Secure Update page, Audit Log panel) alongside the console captures below — placeholders are marked **[SCREENSHOT]**.

---

## E-D3 — POST passes on boot; integrity published (§7.1 a.iii.a/b)

**Captured (H4, PX4 fork `a7ed0be789`):**
```
nsh> listener firmware_integrity_status
TOPIC: firmware_integrity_status
  check_passed: True
  failure_reason: 0
  code_hash: [55, 191, 183, 193, 52, 241, 26, 52, ...]   → 37 bf b7 c1 34 f1 1a 34
  data_hash: [238, 95, 147, 247, 13, 139, 44, 26, ...]    → ee 5f 93 f7 0d 8b 2c 1a
  board_id: 39   (display-only truncation of 1063 & 0xFF; gate uses compiled 1063)
```
**Result:** the on-device libtomcrypt hash of live flash matched, **byte-for-byte**, what `tools/pipeline.py --elf` computed at provisioning — first end-to-end proof of real-flash hashing + OpenSSL→libtomcrypt interop on multi-megabyte ranges. **[SCREENSHOT: QGroundControl Security panel showing "Firmware Verified / green"]**

---

## E-D4 — Tamper → POST fails → arming blocked → logged (§7.1 a.iii.d, a.iv)

**Captured (H5):** one byte flipped at offset 100 in `/fs/microsd/inofly/manifest.bin` (CRC-covered region), reboot, `secure_boot start`:
```
ERROR [secure_boot] Firmware manifest is corrupt - checksum mismatch
                   (stored=0x84CEAB36 computed=0xAE12E80B)
WARN  [secure_boot] Pre-operational self-test FAILED - firmware did not
                   pass the integrity check; arming is blocked
INFO  [secure_boot] Audit event recorded (type=1 result=1, #2)
INFO  [secure_boot] Audit signature updated (256 bytes, covering 3 entries)

nsh> listener firmware_integrity_status
  check_passed: False
  failure_reason: 2
nsh> commander check    → Preflight check: FAILED
nsh> commander arm      → denied
```
**Result:** CRC mismatch caught **before** signature/hash checks (correct ordering); arming blocked; FAILURE logged. Restoring the good manifest returns POST to PASS (gate is data-driven, not sticky). **[SCREENSHOT: QGroundControl "Firmware checksum verification failed" popup]**

### E-D4-b — Organic code/data hash mismatch (reason 4/5) — the hardware-only proof (§7.1 a.iii.b)

**Captured (H14, 2026-06-04):**

| Case | Captured output | Reason |
|---|---|---|
| H14.A code | `Firmware code check FAILED - code changed since signing (1870700 bytes)`, `failure_reason: 4`, arm blocked (audit `#24`) | 4 |
| H14.B data | `Flight-parameter check FAILED - parameters changed since signing (96 bytes)`, `failure_reason: 5`; listener showed **correct** code_hash + **wrong** data_hash → confirms code→data ordering | 5 |

**Result:** a validly-signed manifest carrying a deliberately wrong hash is caught against the **real 1.87 MB flash hash** — the on-silicon hash-compute correctness, which SITL structurally cannot demonstrate.

---

## E-D6 — Unauthorized update rejected at three layers (§7.1 a.iv, b.i)

| Layer | Case | Captured result |
|---|---|---|
| Ground Control Station client-side | tampered `.fwbundle` loaded | Signature **red FAILED**; Install disabled; nothing sent to Flight Module (H12.A) **[SCREENSHOT: QGroundControl Secure Update page, red FAILED]** |
| Flight Module drone-side (CRC) | one byte flipped in staged `update_manifest.bin` | `CRC mismatch …`, `UPD001: update REJECTED (reason=2)`, one `UPDATE_ATTEMPT` FAILURE entry (H12.B) |
| Flight Module drone-side (signature) | attacker-key-signed manifest (valid CRC) | `signature is not from the manufacturer` → `Staged update REJECTED (reason=3)` — proves the signature branch is live on real libtomcrypt (H13). **reason=3** is the authoritative assertion. |
| Update board_id | manifest with board_id 1064 | `board_id 1064 does not match this hardware (1063)`, `REJECTED reason=4`; board_id 1063 → ACCEPTED (H15) |

---

## E-D7 — Compliance parameters cannot be changed (§7.1 c.v/c.vi)

**Captured (H6, nsh console):**
```
param set GF_MAX_VER_DIST 200   → REJECT  attempted=200.000 ceiling=120.000
param set GF_MAX_VER_DIST 120   → accepted (at ceiling, RAM-only)
param set SYS_AUTOSTART 4002    → REJECT  attempted=4002 registered=4001 (LOCKED)
param set SYS_AUTOSTART 4001    → accepted (no-op)
param set MAV_SIGN_CFG 0        → REJECT  registered=1 (LOCKED)

secure_boot param_status        → Violations rejected : 2
pre-arm gate                    → BLOCKED (first unset: GF_MAX_VER_DIST)
```
**Also captured (H6, QGroundControl path):** over-cap write via QGroundControl Parameters editor (`PARAM_SET`) → *"Parameter write failed: GF_MAX_VER_DIST"* — confirms the guard sits in `param_set_internal` and fires regardless of caller (nsh or MAVLink). **[SCREENSHOT: QGroundControl parameter write-failed toast]**

**Result:** CAPPED over-ceiling and LOCKED non-registered writes both rejected; caps enforced in SI units; nothing persists across reboot.

---

## E-D9 — Signed audit log: violations logged + offline verification (§7.1 a.iii.c, b.iii, c.ii; additional log-signing requirement)

**Captured (H7):** after the H6 rejections —
```
#9  EVENT_PARAM_CHANGE / FAILURE  "Attempted to change GF_MAX_VER_DIST - rejected (protected flight parameter) [PAR001]"
#10 EVENT_PARAM_CHANGE / FAILURE  "Attempted to change SYS_AUTOSTART - rejected (protected flight parameter) [PAR001]"
#7  arming gate audited: "Arming was blocked by a security check / compliance unset: GF_MAX_VER_DI" [POST001 arming gate]
```

**Captured (H5/H10 — offline verification of the on-device log):**
```
$ py tools/verify_audit_log.py --log release/sd/audit_log.bin \
      --sig release/sd/audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  log file:        release\sd\audit_log.bin  (948 bytes, 3 entries)
  expected SHA-256: 698c76f9c6b07558ed3b6b962942708290c1e7b36c9b449671247ace784f4608
  decrypted hash:   698c76f9c6b07558ed3b6b962942708290c1e7b36c9b449671247ace784f4608
PASS: audit log signature is authentic

$ py tools/decode_audit_log.py release/sd/audit_log.bin
#0  28 May 2026, 10:02:40 AM IST   POST FAILED - code hash mismatch    [POST002]
#1  29 May 2026, 02:03:07 AM IST   POST passed - firmware verified     [POST001/002/003]
#2  29 May 2026, 02:17:31 AM IST   POST FAILED - manifest CRC failed   [POST001]
Status: OK - every entry parsed and passed CRC.
```
**Result:** the on-device log — mixed PASS/FAIL, multi-event — verifies **byte-for-byte** offline with the manufacturer key; both outcomes (pass and fail) are recorded and rendered in plain English (IST/UTC). **[SCREENSHOT: QGroundControl Audit Log panel, entries listed]**

**Regenerated live (host, 2026-07-10)** on the staged bench log confirms the tool chain still passes:
```
$ py tools/verify_audit_log.py --log release/sd/audit_log.bin --sig release/sd/audit_log.sig --key .../manufacturer_private.pem
  → PASS: audit log signature is authentic   (11 entries, 3476 bytes)
```

---

## E-summary — automated evidence (§7.1 all)

**Captured (host, 2026-07-10):** `python tools/generate_compliance_report.py --run-tests`
```
Total tests: 358   Passed: 358   Failed: 0
Requirements: 13 PASS (host tests) + 3 HARDWARE_VALIDATED (POST002/003/004) + 0 FAIL
OVERALL VERDICT: PASS
```
Full matrix: [../compliance_report.txt](../compliance_report.txt).

---

## Evidence index (test → clause → source)

| Evidence | Demo | §7.1 clause | Hardware step | PX4 fork |
|---|---|---|---|---|
| E-D3 POST pass + real hashes | D3 | a.iii.a/b | H3/H4 | `a7ed0be789` |
| E-D4 tamper → block → log | D4 | a.iii.d, a.iv | H5 | `a7ed0be789` |
| E-D4-b organic hash mismatch | D4-b | a.iii.b | H14.A/B | `f3408a16e5`→bench |
| E-D6 update rejects (3 layers) | D6 | a.iv, b.i | H12/H13/H15 | bench |
| E-D7 param protection | D7 | c.v/c.vi | H6 | bench |
| E-D9 signed log + offline verify | D9 | a.iii.c, b.iii, c.ii, log signing | H5/H7/H10 | `a7ed0be789` |
| E-summary automated suite | D0 | all | — | host |

> **Screenshots to attach for the formal pack:** QGC Security panel (verified/failed), Secure Firmware Update page (green VERIFIED and red FAILED), Audit Log panel (entry list + download buttons), parameter write-failed toast, and the checksum-failed popup. These are the standard evidence figures for a §7.1 submission. Live captures can be taken during the witnessed session per [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md).
