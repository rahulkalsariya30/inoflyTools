# SITL Acceptance Checklist

End-to-end functional verification of every SITL-testable security
requirement. Run this before each hardware deployment. All steps must
pass — failures gate the hardware build.

Test environment:
- WSL2 Ubuntu 22.04 with `~/PX4-Autopilot` (inoflyPilot fork)
- QGC built at `D:\Projects\Drone\qgroundcontrol\build\`
- Headless SITL target: `make px4_sitl none_iris`
- Provisioning passphrase: `dgca_sitl_test`

Each step lists: requirement IDs covered, command/action, and the
exact pass criterion.

---

## 1. SITL builds with `secure_boot` module

- **Covers:** build sanity
- **Action:** `cd ~/PX4-Autopilot && make px4_sitl none_iris`
- **Pass:** build succeeds; `secure_boot` symbol present in
  `build/px4_sitl_default/bin/px4`.

## 2. Provision binary manifest to SITL storage

- **Covers:** PRV001
- **Action:** `py tools/provisioning/provision_sitl.py --manifest <path>`
- **Pass:** `manifest.bin` written to both headless and Gazebo SITL
  storage paths (501 bytes).

## 3. POST passes on boot

- **Covers:** POST001, ROT002
- **Action:** start SITL, then at the `pxh>` prompt: `secure_boot start`
- **Pass:** module reports `POST: PASS` and publishes
  `firmware_integrity_status` uORB with `check_passed=true`. No
  `ARMING_BLOCKED` reasons posted.

## 4. `firmware_integrity_status` uORB published

- **Covers:** POST001 wiring
- **Action:** `listener firmware_integrity_status` from `pxh>`
- **Pass:** message is published and `check_passed`, `boot_count`,
  `manifest_version`, `code_hash`, `data_hash` fields populated.

## 5. Tamper test — POST fails, arming blocked

- **Covers:** ARM001, POST001
- **Action:** flip a single byte in the SITL `manifest.bin`, restart SITL,
  `secure_boot start`, then attempt `commander arm`.
- **Pass:** POST reports failure reason (CRC or signature),
  `firmware_integrity_status.check_passed=false`, `commander arm` is
  rejected with `Preflight Fail: Firmware integrity check failed`. A
  `POST_RESULT` audit entry is written with the failure detail.

## 6. PAR001 — protected parameter writes blocked (zero-window)

- **Covers:** PAR001
- **Action:** for each parameter in the canonical 6-list:
  - `GF_MAX_VER_DIST`, `GF_MAX_HOR_DIST`, `MPC_XY_VEL_MAX`,
    `SYS_AUTOSTART`, `CA_AIRFRAME`, `MAV_SIGN_CFG`
  - From `pxh>`: `param set <NAME> <bogus value>`
- **Pass:** every write returns `READ_ONLY`. `param show <NAME>` returns
  the compiled value. MAVLink `PARAM_SET` from QGC returns
  `MAV_PARAM_ERROR_READ_ONLY`.

## 7. PAR001 — violations logged to audit log

- **Covers:** PAR001 + LOG001 wiring
- **Action:** after step 6, inspect the live audit log via QGC Audit Log
  panel.
- **Pass:** one `PARAM_CHANGE` entry per blocked write, sequence numbers
  monotonically increasing, signed (`audit_log.sig` regenerated).

## 8. PAIR001 — MAVLink signing required

- **Covers:** PAIR001
- **Action:**
  1. Provision signing key:
     `py tools/provisioning/provision_signing_key.py --drone-id <id> --passphrase dgca_sitl_test`
  2. Connect QGC with the **wrong** passphrase → confirm no telemetry.
  3. Connect QGC with the **right** passphrase → confirm full link.
- **Pass:** unsigned/wrong-key messages are silently dropped on the FC
  side; correct key gives full bidirectional link. `MAV_SIGN_CFG=1` is
  read-only (PAR001).

## 9. Audit log — Live Events panel + auto-FTP backfill

- **Covers:** LOG001 viewer, FTP transport
- **Action:** open QGC, connect to SITL, observe Audit Log panel.
- **Pass:** Live Events panel populated within ~5s of connect with all
  N entries from `audit_log.bin`. Entries sorted descending by `seq`.
  No duplicates between backfill and the live INOFLY_AL stream. New
  events arrive in real time as they occur.
- **Status (2026-04-28):** ✅ verified — 29/29 entries on connect, no
  dupes. Implemented in
  [qgroundcontrol/custom/src/AuditLogController.cpp](../qgroundcontrol/custom/src/AuditLogController.cpp)
  (auto-FTP backfill).

## 10. Audit log — offline RSA-2048 signature verification

- **Covers:** LOG001 manufacturer-side verification
- **Action:** download `audit_log.bin` and `audit_log.sig` via QGC
  Audit Log panel, then run:
  ```
  py tools/verify_audit_log.py \
      --log Docs/audit_log.bin \
      --sig Docs/audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  ```
- **Pass:** tool prints `PASS: audit log signature is authentic` and
  exits 0. Decrypted hash equals SHA-256 of the log file.

## 11. UPD001 — accept correctly signed firmware bundle

- **Covers:** UPD001 (positive path), PKG001
- **Action:** in QGC, open SecureFirmwareUpdatePage and upload
  [test_firmware.fwbundle](../test_firmware.fwbundle).
- **Pass:** QGC client-side verification passes; bundle uploaded to FC
  via MAVLink FTP; FC `FirmwareUpdateGatekeeper` reports CRC + RSA-PSS
  pass and authorizes the staged manifest. A `FW_UPDATE` audit entry is
  logged with result=accepted.

## 12. UPD001 — reject tampered/unsigned bundle at the drone

- **Covers:** UPD001 (negative path) — drone-side, not just QGC
- **Action:** upload [test_firmware_tampered.fwbundle](../test_firmware_tampered.fwbundle).
- **Pass:** QGC rejects client-side. Then bypass QGC verification (or
  use the raw upload path) and confirm the drone *still* rejects.
  `FirmwareUpdateGatekeeper` reports signature mismatch; no flash
  authorization granted; `FW_UPDATE` audit entry logged with
  result=rejected and reason code populated.

---

## Pre-hardware sign-off

All 12 steps must show ✅ before kicking off the CubeOrange+ build.
Steps 1–9 are verified as of 2026-04-28. Steps 10–12 are the remaining
gates.
