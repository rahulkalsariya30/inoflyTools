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
- **Action:** `python3 tools/provisioning/provision_sitl.py` (no flags —
  generates a manifest from the hardcoded `TEST_BUNDLE` and signs with
  `pki/manufacturer/private/manufacturer_private.pem`).
- **Pass:** `manifest.bin` written to both
  `build/px4_sitl_default/inofly/manifest.bin` and
  `build/px4_sitl_default/rootfs/inofly/manifest.bin` (373 bytes —
  the size of `security_manifest_t` after the v1.1.0 / ADR-018 split).
  Both copies must be byte-identical (md5sum-equal).
- **Note on SITL cwd:** `make px4_sitl none_iris` sets cwd to
  `build/px4_sitl_default/rootfs/`, so the live FC reads/writes
  `rootfs/inofly/`. The non-rootfs `inofly/` is a residue path from
  older `PX4_SIM_MODEL=shell` runs; it can be stale. Always inspect the
  `rootfs/inofly/` copy when checking live FC state during a walkthrough.

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

## 6. PAR001 — kind-aware enforcement (ADR-019 + ADR-020)

- **Covers:** PAR001
- **Action — CAPPED rows** (`GF_MAX_VER_DIST` 120, `GF_MAX_HOR_DIST`
  500, `MPC_XY_VEL_MAX` 15): for each:
  1. `param show <NAME>` immediately after boot → expect **0**.
  2. `param set <NAME> <value above ceiling>` → expect rejection
     with the ceiling included in the error message.
  3. `param set <NAME> <value at ceiling>` → expect accept.
  4. `param set <NAME> <value just below ceiling>` → expect accept;
     `param show <NAME>` returns that value.
  5. `param save` then reboot → `param show <NAME>` returns 0 again
     (autosave-skip works; values do not persist).
- **Action — LOCKED rows** (`SYS_AUTOSTART` 4001, `CA_AIRFRAME` 0,
  `MAV_SIGN_CFG` 1): for each:
  1. `param show <NAME>` immediately after boot → expect the
     **registered value** (4001, 0, or 1 respectively), not 0. This
     is the lazy-zero kind-aware read path.
  2. `param set <NAME> <registered value>` → expect accept (no-op);
     no audit entry.
  3. `param set <NAME> <any other value>` → expect rejection with
     detail `attempted=X registered=Y (LOCKED)`.
  4. `param save` then reboot → `param show <NAME>` still returns
     the registered value (not 0; LOCKED reads always pin).
- **Action — pre-arm gate:** with at least one **CAPPED** param
  still 0, attempt to arm via `commander arm`. The arm command itself
  only prints a generic `Arming denied: Resolve system health failures
  first` — to surface the actual blocking reason run `commander check`
  at `pxh>`; it names the failing CAPPED param. (Also useful in step 5
  to confirm POST is the blocker rather than unrelated SITL preflight
  noise like GPS fix.)
- **Pass:** `commander arm` rejected; `commander check` names a
  CAPPED param (e.g. `GF_MAX_VER_DIST`). LOCKED rows do NOT appear in
  the gate output (they always read as the registered value).

## 7. PAR001 — violations logged to audit log

- **Covers:** PAR001 + LOG001 wiring
- **Action:** after step 6 (the rejections in 6.CAPPED.2 and
  6.LOCKED.3), inspect the live audit log via QGC Audit Log panel.
- **Pass:**
  - One `COMPLIANCE_PARAM_VIOLATION` entry per **CAPPED over-cap**
    attempt, detail `attempted=X ceiling=Y`.
  - One `COMPLIANCE_PARAM_VIOLATION` entry per **LOCKED mismatched**
    write, detail `attempted=X registered=Y (LOCKED)`.
  - **No** entry for successful CAPPED within-cap sets (6.CAPPED.3/4).
  - **No** entry for LOCKED writes where `attempted == registered`
    (6.LOCKED.2 — semantic no-op).
  - Sequence numbers monotonically increasing; `audit_log.sig`
    regenerated. (ADR-019 + ADR-020: audit log records security
    events only.)

## 8. PAIR001 — MAVLink signing required

- **Covers:** PAIR001
- **Action:**
  1. Provision signing key:
     `python3 tools/provisioning/provision_signing_key.py --drone-id <id> --passphrase dgca_sitl_test`
  2. Connect QGC with the **wrong** passphrase → confirm no telemetry.
  3. Connect QGC with the **right** passphrase → confirm full link.
- **Pass:** unsigned/wrong-key messages are silently dropped on the FC
  side; correct key gives full bidirectional link. `MAV_SIGN_CFG=1` is
  capped at its compiled ceiling (PAR001 / ADR-019 — operator can
  set values ≤ ceiling, cannot exceed it).

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
  python3 tools/verify_audit_log.py \
      --log Docs/audit_log.bin \
      --sig Docs/audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  ```
- **Pass:** tool prints `PASS: audit log signature is authentic` and
  exits 0. Decrypted hash equals SHA-256 of the log file.

## 11. UPD001 — accept correctly signed firmware bundle

- **Covers:** UPD001 (positive path), PKG001
- **Prereq:** the gitignored test fixtures must be at the current bundle
  format (regenerate after any bundler format bump):
  `py -3 tools/regenerate_test_fixtures.py`. Expect
  `test_firmware.fwbundle verify=PASS` and
  `test_firmware_tampered.fwbundle verify=FAIL`.
- **Action:** in QGC, open SecureFirmwareUpdatePage and upload
  [test_firmware.fwbundle](../test_firmware.fwbundle). Then click
  **Install on Drone** (Section 4.5 — gated on `verificationState ===
  Verified`).
- **Pass:**
  - QGC client-side: signature **VERIFIED** (green).
  - Install state machine reaches **ACCEPTED** within 15s.
  - On FC SD, `rootfs/inofly/update_manifest.bin` exists, **373 bytes**,
    timestamp fresh.
  - **MD5 cross-check** — the MD5 of `update_manifest.bin` on the FC
    SD equals the MD5 of `update_manifest.bin` inside the bundle:
    ```
    py -3 -c "import zipfile,hashlib; \
        d=zipfile.ZipFile('test_firmware.fwbundle').read('update_manifest.bin'); \
        print(hashlib.md5(d).hexdigest())"
    md5sum ~/PX4-Autopilot/build/px4_sitl_default/rootfs/inofly/update_manifest.bin
    ```
    Equal MD5 proves the staged manifest is bit-identical to what the
    manufacturer signed — no MAVLink-FTP corruption.
  - One `UPDATE_ATTEMPT` audit entry with result=SUCCESS; `entry_count`
    grows by exactly 1.

## 12. UPD001 — reject tampered/unsigned bundle (both paths)

- **Covers:** UPD001 (negative path) — both QGC client-side AND drone-side
- The two paths verify different artifacts and must be exercised
  separately:

### 12.A — QGC client-side reject

- **Action:** in QGC, **Clear** any loaded bundle, then **Browse...** and
  pick [test_firmware_tampered.fwbundle](../test_firmware_tampered.fwbundle)
  (the regen tool corrupts one base64 char of the manifest signature).
- **Pass:**
  - Signature Verification turns **red FAILED**.
  - Section 4.5 "Install on Drone" is **hidden** (gated on Verified).
  - QGC never uploads to FC. `secure_boot audit_status` `entry_count`
    is unchanged.

### 12.B — FC drone-side reject (bypass QGC, tamper SD directly)

This simulates an attacker who corrupts the staged `update_manifest.bin`
on the SD card after a legitimate stage (e.g. SD card swap).

- **Prereq:** Step 11 completed, so a valid `update_manifest.bin` is
  staged on `rootfs/inofly/`.
- **Action:** flip one byte inside the CRC-covered region of
  `update_manifest.bin`:
  ```
  python3 -c "
  p='/home/$USER/PX4-Autopilot/build/px4_sitl_default/rootfs/inofly/update_manifest.bin'
  d=bytearray(open(p,'rb').read()); d[50] ^= 0xFF
  open(p,'wb').write(d)"
  ```
  Then at `pxh>`: `secure_boot verify_update`.
- **Pass:**
  - Output shows `CRC mismatch (stored=0x... computed=0x...)` and
    `UPD001: update REJECTED (reason=2)`.
  - No `signature VERIFIED` line.
  - New `UPDATE_ATTEMPT` audit entry with result=FAILURE.
  - `entry_count` grows by exactly 1.
- **Cleanup:** at `pxh>` run `secure_boot clear_update` to drop the
  failed staging state before next session.

---

## 13. Attacker-key reinforcement (recommended, not required for §1–§12 sign-off)

Steps §5 and §12.B exercise the negative path via byte-flips, which
fail at the CRC check (`reason=2`) before the signature branch even
runs. This section reinforces the model with manifests/bundles that
are **correctly signed but with a non-manufacturer (attacker) keypair**.
CRC is valid; only the RSA-PSS signature verification against the
embedded manufacturer public key fails — confirming the signature
branch isn't dead code, and surfacing the **distinct sig-mismatch
reason code (`reason=3`)** that byte-flip tests never reach.

**Prereq:** generate fresh attacker fixtures
```
py -3 tools/regenerate_attacker_fixtures.py
```
Output lands in `.attacker_fixtures/` (gitignored). Tool runs a
cross-key sanity check at generation time — if any artifact verifies
under the manufacturer public key, generation aborts.

### 13.A — POST signature-mismatch (`manifest.bin`)

- **Action:** stop SITL, back up the good `manifest.bin` from
  `rootfs/inofly/` (and the non-rootfs `inofly/` copy), drop in
  `.attacker_fixtures/attacker_manifest.bin`, restart SITL, run
  `secure_boot start`.
- **Pass:**
  - `secure_boot: manifest signature invalid` (note: signature, not CRC)
  - `POST FAILED (reason=3)` — distinct from CRC's `reason=2`
  - `firmware_integrity_status.failure_reason=3`
  - `commander check` lists `Firmware integrity check failed (reason=3)`
  - `commander arm` denied
- **Restore** good `manifest.bin`, restart, confirm POST passes again.

### 13.B — QGC client-side reject (attacker bundle)

- **Action:** in QGC, **Clear** the loaded bundle, then **Browse...**
  and pick `.attacker_fixtures/attacker_firmware.fwbundle`.
- **Pass:** identical UX to §12.A — red **FAILED — Signature invalid**,
  DGCA warning shown, Section 4.5 hidden, no FC upload.

### 13.C — FC `verify_update` signature-mismatch

- **Action:** copy `.attacker_fixtures/attacker_update_manifest.bin`
  in place of `rootfs/inofly/update_manifest.bin`, then at `pxh>`
  run `secure_boot clear_update; secure_boot verify_update`.
- **Pass:**
  - Output shows `RSA-PSS signature verification FAILED` (not CRC)
  - `UPD001: update REJECTED (reason=3)` — distinct from §12.B's `reason=2`
  - New `UPDATE_ATTEMPT` FAILURE audit entry; `detail` carries the
    reason code
- **Cleanup:** `secure_boot clear_update` + `rm rootfs/inofly/update_manifest.bin`.

### Why this matters

Without §13, the negative-path tests only exercise the CRC layer.
Several real failure modes — wrong manufacturer key flashed during
provisioning, attacker who recomputes CRC after substituting their
own signed manifest, mistakenly-signed update bundles — would not
have been exercised. A single fixture bug in
`regenerate_attacker_fixtures.py` was caught only by running §13.C
(false-passed on first run because `create_bundle()`'s
`private_key_path` defaulted to the manufacturer key for
`update_manifest.bin`). The strengthened sanity guard in the regen
tool now prevents that regression.

---

## Pre-hardware sign-off

All 12 steps must show ✅ before kicking off the CubeOrange+ build.
**All 12 steps verified end-to-end on 2026-05-17** under PX4 fork
`f3408a16e5` (inofly-par001-merge) + inoflyTools `02f221b` + inoflyGCU
QGC fork `14a61e4b2`. §13 attacker-key reinforcement also run the same
day and passes (reason=3 in both POST and `verify_update`). Next gate
is hardware Tier 1.
