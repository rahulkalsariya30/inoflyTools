# Hardware Tier 1 Acceptance Checklist

First-silicon bring-up and end-to-end functional verification of the
firmware-security stack on a real **CubeOrange+** flight controller.

---

## Day 1 bench session results (2026-05-25)

First real-silicon attempt on a CubeOrange+ unit. Status by step:

| Step | Status | Notes |
|---|---|---|
| **H0** board health on stock PX4 | ✅ PASS | 3 IMUs publishing live (icm45686×3, ms5611, ak09916), Board ID **1063** confirmed, PX4GUID `00060000000039333738333335112003d0036` |
| **H1** flash our `secure_boot` build | ✅ PASS | `ver all` → PX4 1.17.0, git-branch `inofly-par001-merge`, hash `034c577559`, our build datetime confirmed |
| **H2** provision manifest from real ELF | ✅ PASS | `pipeline.py --elf` produced 373-byte `manifest.bin`; placed at `/fs/microsd/inofly/manifest.bin`; SHA-256 cross-check OK |
| Firmware stability under `secure_boot start` | ✅ PASS | `hardfault_log check` empty — **no crash on hardware**; the security firmware itself is sound |
| POST → arming gate wired | ✅ PASS | `Preflight Fail: Firmware integrity check not run` in `commander check` confirms the gate is live |
| **H3** POST verdict visible | ⛔ **BLOCKED** by two firmware bugs below (POST runs, verdict not observable yet) |
| H4–H15 | ⏸️ Not started — gated by H3 |

PAIR001 key was provisioned on both sides (`dgca_sitl_test` →
`SHA256` fingerprint `0aec3d3c…`), key file on FC SD
(`/fs/microsd/mavlink/mavlink-signing-key.bin`, 40 B) and Active in QGC
— but BUG #2 below prevents observing the link under signing.

### Two hardware-only firmware bugs surfaced (exactly what Tier 1 is for)

#### BUG #1 — Audit logger doesn't reliably write entries on hardware (H7/LOG001)

`audit_log.bin` on the SD shows **0 entries** even after `secure_boot
start` runs to completion (firmware doesn't crash, so the
`publish_audit_event(POST_RESULT)` call at the end of `start` *does*
execute — the async work-queue write isn't reaching SD). The
`SecurityAuditLogger::init()` itself is also inconsistent — one run
printed `Audit log could not be started (non-fatal)`, another printed
`Audit log ready (0…)` — yet neither produced a logged entry.

SITL works fine (per the 2026-05-07 `project_audit_log_write_gap` fix);
the regression is hardware-specific (NuttX work-queue /
SD-write / libtomcrypt-log-signing path).

**Investigation target:** `src/modules/secure_boot/SecurityAuditLogger.cpp`
and `.hpp` — specifically `init()`, the `SubscriptionCallbackWorkItem`
registration on NuttX, file open/write to
`/fs/microsd/inofly/audit_log.bin`, and the `libtomcrypt_init()` call.

#### BUG #2 — MAVLink signing drops the USB link instead of staying exempt (H8)

`secure_boot start` enables `MAV_SIGN_CFG=1` via `ComplianceParamGuard`.
The instant signing turns on, the **USB MAVLink link drops** — QGC goes
"Comms Lost," the MAVLink shell dies mid-line, and POST output never
reaches the operator.

This **contradicts the documented design**:
[`provision_signing_key.py`](../tools/provisioning/provision_signing_key.py)
states explicitly *"MAV_SIGN_CFG=1 is locked by PAR001. **Non-USB
connections** REQUIRE matching message signing."* — i.e. USB should
**accept unsigned**. The hardware behavior does not match.

Confirmed not a key-mismatch: FC has the matching key on SD, QGC has the
matching key Active with the right passphrase. Even with both keys in
place, the USB link drops — the **USB-exemption itself** isn't honored.

**Investigation target:** the MAVLink signing config in the fork — find
where the USB mavlink instance is configured and whether its
`accept_unsigned_callback` is set (stock PX4 typically whitelists the
USB CDC instance). Either the callback is missing/disabled, or
`ComplianceParamGuard` enforces signing globally without respecting
per-link exemptions. Files to examine: `src/modules/mavlink/` (instance
setup) and the param-guard enforcement code.

### Diagnostic plumbing (not bugs — fallout from the bugs above)
- `SYS_USB_AUTO` enum has only **`0=Disabled, 1=Auto-detect, 2=MAVLink`**
  — no "force-nsh" value. Auto-detect switches to nsh only on `\r`
  *and* if no MAVLink heartbeat arrives first — so a single residual
  QGC instance defeats it. Reliable serial-nsh-via-USB requires every
  QGC process killed (Task Manager), `SYS_USB_AUTO=1`, FC power-cycle,
  PuTTY+Enter before anything sends MAVLink. Hard to win on Day 1 with
  QGC instability.
- QGC (InoflyGCS) crashed intermittently — bench tooling instability.

### Architectural finding from the audited reference doc review (open ADR decision)

Reference implementations reviewed during scoping. **Both
reference vendors store the registered checksum *inside* the
firmware/flash**, not on the SD card:
- Reference implementations store the checksum inside the
  firmware.
- They store checksums inside the
  flight controller hardware only, in internal flash.

Our current design (signed `manifest.bin` on the **SD card**) is a
documented divergence. The signature still provides integrity, but the
DGCA wording *"stored securely **in the flight module**"* is interpreted
as flash, not SD, by both reference vendors.

**Open ADR decision to make before hardware-final:**
1. **Keep SD + compensating controls** (signature + FTP write-deny on
   `manifest.bin` + BOOT007 seal) and document the compensating-control
   argument vs the in-flash reference interpretation. Lower
   implementation cost; carries "removable media" audit risk.
2. **Move `manifest.bin` into a dedicated flash region** (matching
   the audited reference). Higher implementation cost; matches reference exactly.

Does **not** block H3 either way.

### Resume plan
1. **Phase 1 — Offline (no board needed):** fix BUG #1
   (`SecurityAuditLogger.cpp` write path on NuttX) and BUG #2 (mavlink
   signing's USB `accept_unsigned` exemption). Both are likely small,
   targeted fixes once root cause is found.
2. **Phase 2 — Back to bench:** rebuild + reflash, run `secure_boot
   start` → POST verdict visible live (BUG #2 fixed → USB shell
   survives) and also in audit log (BUG #1 fixed). **H3 ✅** in
   minutes. Continue to H4–H15.
3. **Phase 3 (parallel):** write the manifest-storage ADR.

---

This is the hardware-equivalent of [SITL_ACCEPTANCE.md](SITL_ACCEPTANCE.md).
SITL proves the *wiring*; this checklist proves the parts that only exist
on real silicon — **real flash-range hashing** (libtomcrypt over the
actual STM32H743 flash), the **real STM32 96-bit board ID**, and the
**OpenSSL-signs / libtomcrypt-verifies crypto interop** that SITL never
exercises (SITL uses OpenSSL on both sides).

> **Why a separate doc from the Manufacturing Runbook.** This is the
> *engineering bring-up gate* — does the security stack work on real
> hardware at all? [MANUFACTURING_RUNBOOK.md](MANUFACTURING_RUNBOOK.md)
> is the *production provisioning process* (secure-bootloader install via
> `bl_update`, tamper-evident sealing, QMS recordkeeping) applied once
> per shipped unit. Tier 1 here runs under the **factory PX4 bootloader**
> with our **signed app fw** loaded normally via QGC. The verifying
> secure bootloader (BOOT001/BOOT006) is a separate phase — see
> "Bootloader chain" near the end.

---

## Scope and prerequisites

**Tier 1 scope (locked, ADR-021/022):** firmware-security bench bring-up
only. **No motors, no propellers, no telemetry radio.** Everything is
verified over the USB link to QGC. The drone is never armed-to-fly; the
arming we test is the *gate logic*, with props off and on the bench.

**Gate before starting:** [SITL_ACCEPTANCE.md](SITL_ACCEPTANCE.md) §1–§14
must be 100% green for the build under test. As of 2026-05-19 it is
(PX4 fork `f3408a16e5`, all reason codes 2/3/4/5 covered). Do not flash a
build to hardware that has not passed SITL.

**Test environment:**
- CubeOrange+ FMU on its carrier board, SD card seated.
- Bench power: **3S LiPo → 8S power module → POWER1** on the carrier.
  USB alone is **not** sufficient — the Mini Carrier USB rail is
  ~250 mA, below the FMU's ~2.5 A draw; the Cube will not boot reliably
  on USB power. USB is the QGC data link only.
- Laptop USB → carrier USB (QGC link + nsh console).
- Builds and provisioning tooling run in WSL2 / on the host exactly as
  in SITL; only the *targets* and *paths* change (real ELF, SD card).
- Provisioning passphrase (bench): `dgca_sitl_test`.

**⚠️ LiPo safety (every session):**
- Balance-charge in a LiPo safety bag; never leave a charge unattended.
- Fit the low-voltage alarm; stop discharge at 3.4 V/cell.
- Inspect for puffing/damage before each use.

**Crypto note.** Every POST and every signature check below is the
**first real exercise of libtomcrypt RSA-PSS / SHA-256 on NuttX**.
Manufacturer-side signing is OpenSSL (host); device-side verification is
libtomcrypt (NuttX). A passing POST on hardware is the proof these two
interoperate — something SITL (OpenSSL on both ends) cannot demonstrate.

**Hardware paths (differ from SITL's `build/.../rootfs/inofly/`):**

| Artifact | Hardware path on SD |
|---|---|
| Security manifest | `/fs/microsd/inofly/manifest.bin` |
| Audit log + sidecar | `/fs/microsd/inofly/audit_log.bin` + `.sig` |
| Staged update manifest | `/fs/microsd/inofly/update_manifest.bin` |
| MAVLink signing key | `/fs/microsd/mavlink/mavlink-signing-key.bin` |

Console: PX4 **nsh over USB CDC**, or the **QGC MAVLink Console** widget.
Where SITL says `pxh>`, hardware uses the `nsh>` / MAVLink Console prompt.

---

## SITL § → Hardware H map (what changes on real silicon)

| SITL | Hardware | What's genuinely different (not just re-run) |
|---|---|---|
| §1 build | **H1** | Build `cubeorangeplus_default`, flash via QGC |
| §2 provision | **H2** | Manifest from the **real signed ELF** (`--elf`), onto SD |
| §3 POST | **H3** | **Real flash hashing** via libtomcrypt — milestone |
| §4 uORB | **H4** | Real `code_hash`/`data_hash` values, real board ID |
| §5 tamper | **H5** | Byte-flip on the **SD** manifest → reason=2 |
| §6 PAR001 | **H6** | Real param store; CAPPED non-persist across real reboot |
| §7 audit | **H7** | Audit log persists on **real SD** across power-cycle |
| §8 PAIR001 | **H8** | Key on real SD `/fs/microsd/mavlink/` |
| §9 live panel | **H9** | FTP backfill over the real USB link |
| §10 offline verify | **H10** | Same host tool; real downloaded log |
| §11 UPD001 accept | **H11** | Stage to real SD |
| §12 UPD001 reject | **H12** | QGC-side + SD-tamper on real card |
| §13 attacker-key | **H13** | reason=3 on real libtomcrypt verify path |
| §14 reason 4/5 (stub) | **H14** | **Organic** reason 4/5 — no stub; the Tier 1 prize |
| — | **H15** | **Real board_id mismatch** (update reason=4) — new |

---

## H0. Board health on stock/current PX4 (pre-acceptance)

- **Covers:** bench bring-up sanity (not a security requirement).
- **Action:** connect LiPo → power module → POWER1; USB → laptop. Open
  QGC and let it connect.
- **Pass:** QGC connects; `AUTOPILOT_VERSION` populated; IMUs publish
  (`listener sensor_accel` shows live data); the STM32 96-bit UID is
  readable (QGC summary, or read `UID_BASE = 0x1FF1E800` / MAVLink). GPS
  fix is **not** required for Tier 1.
- **Why first:** confirms the board, carrier, power path, and USB link
  are healthy *before* attributing any failure below to the security
  stack.

## H1. Flash the `secure_boot` app firmware

- **Covers:** build sanity on the hardware target.
- **Action (WSL):** `cd ~/PX4-Autopilot && make cubepilot_cubeorangeplus_default`.
  Then in QGC: Vehicle Setup → Firmware → Load Custom Firmware → select
  the freshly built `.px4` / `.apj`.
- **Pass:** flash completes and the unit reboots; at the console
  `secure_boot status` resolves (module present). FLASH usage within
  budget (build did not overflow under `bl_update`-enabled config — keep
  `bl_update` ON; manage size by stripping modules, never by disabling
  it).

## H2. Provision the real signed manifest (from the ELF)

- **Covers:** PRV001, ADR-018 (`--elf` canonical hashing).
- **Action (WSL):** generate the manifest from the **same signed ELF**
  that produced the flashed binary, so `code_hash`/`data_hash` are taken
  over the real flash ranges:
  ```
  BUILD=~/PX4-Autopilot/build/cubepilot_cubeorangeplus_default
  python tools/pipeline.py \
      $BUILD/cubepilot_cubeorangeplus_default.px4 \
      --board-id 1063 \
      --elf $BUILD/cubepilot_cubeorangeplus_default.elf \
      --version <fw-version> \
      --output-dir release/
  ```
  - The **positional `.px4` is required** (pipeline reads version/board_id/git_hash
    from it and packages the `.fwbundle`); `--elf` is what supplies the real
    code/data flash-range hashes. **Both must come from the same build.**
  - `--board-id 1063` is the CubeOrange+ ID (confirmed: `firmware.prototype`
    `board_id: 1063`, and the bootloader flash log reported Board ID 1063). The
    device compiles `SECURE_BOOT_BOARD_ID=1063` and POST rejects a mismatch with
    **reason=6** — so the manifest must carry 1063. (It would also be picked up
    from the `.px4` automatically, but pass it explicitly.)

  Copy the resulting `release/cubepilot_cubeorangeplus_default_manifest.bin` to
  the SD card at `/fs/microsd/inofly/manifest.bin` (mount the SD on the host, or
  push via QGC MAVLink-FTP).
- **Pass:** `manifest.bin` is **373 bytes**, magic `INOFLY03`,
  `format_ver = 3`. Host-side pre-check passes before provisioning:
  ```
  python tools/provisioning/export_manifest.py <bundle>.json \
      --output /tmp/manifest.bin --verify   # → Verification: passed
  ```
- **Note:** the hashes here are computed over the ELF's `_stext →
  _compliance_params_start` (code) and `_compliance_params_start →
  _compliance_params_end` (data) flash ranges — the exact ranges POST
  re-hashes on-device in H3.

## H3. POST passes on real silicon — **milestone**

- **Covers:** POST001/002/003, ROT002 — first real hash-compute.
- **Action:** boot the unit, then `secure_boot start`.
- **Pass:** `POST: PASS`; `firmware_integrity_status.check_passed=true`;
  no `ARMING_BLOCKED` from integrity. The on-device libtomcrypt hash of
  the live flash equals the manifest's `code_hash` and `data_hash`, and
  the RSA-PSS manifest signature verifies against the embedded
  manufacturer public key.
- **Why this is the milestone:** it is the first end-to-end proof that
  (a) the flash-range hashing is correct on real silicon and (b) the
  OpenSSL→libtomcrypt crypto interop works. SITL stubs both out.

## H4. `firmware_integrity_status` published with real values

- **Covers:** POST001 wiring on hardware.
- **Action:** `listener firmware_integrity_status`.
- **Pass:** published with `check_passed`, `boot_count`,
  `manifest_version`, and **non-zero real** `code_hash`/`data_hash`
  matching the manifest. `boot_count` increments across power-cycles
  (real persistence).

## H5. Tamper test — POST fails, arming blocked (reason=2)

- **Covers:** ARM001, POST001.
- **Action:** power down, flip one byte in `/fs/microsd/inofly/manifest.bin`
  on the SD card, reboot, `secure_boot start`, then `commander arm`
  (props OFF, bench).
- **Pass:** POST fails with `reason=2` (CRC) — the byte-flip corrupts the
  CRC before any signature/hash check; `check_passed=false`; `commander
  arm` rejected with `Preflight Fail: Firmware integrity check failed`; a
  `POST_RESULT` FAILURE audit entry is written. Restore the good manifest
  and confirm POST passes again.

## H6. PAR001 — kind-aware enforcement (ADR-019 + ADR-020)

- **Covers:** PAR001 on real param storage.
- **Action — CAPPED** (`GF_MAX_VER_DIST` 120, `GF_MAX_HOR_DIST` 500,
  `MPC_XY_VEL_MAX` 15): per [SITL §6](SITL_ACCEPTANCE.md): boots to 0;
  over-cap rejected with ceiling in message; at/under-cap accepted;
  **`param save` then real power-cycle → reads 0 again** (autosave-skip
  holds against genuine NVM persistence, not just a SITL restart).
- **Action — LOCKED** (`SYS_AUTOSTART` 4001, `CA_AIRFRAME` 0,
  `MAV_SIGN_CFG` 1): boots to the registered value (lazy-zero read);
  `param set` to the registered value is an accepted no-op; any other
  value rejected with `attempted=X registered=Y (LOCKED)`; survives a
  real power-cycle pinned to the registered value.
- **Action — pre-arm gate:** with a CAPPED param still 0, `commander arm`
  is denied; `commander check` names the failing CAPPED param. LOCKED
  rows never appear in the gate.
- **Pass:** as SITL §6, confirmed against real NVM persistence.

## H7. PAR001 — violations logged to audit log (persists on SD)

- **Covers:** PAR001 + LOG001 wiring.
- **Action:** after the H6 rejections, inspect the audit log (QGC panel,
  or pull `/fs/microsd/inofly/audit_log.bin`).
- **Pass:** one `COMPLIANCE_PARAM_VIOLATION` per over-cap (CAPPED) and per
  mismatched (LOCKED) write, detail = **parameter name** only; **no**
  entry for within-cap or registered-value no-op writes; seq numbers
  monotonic; `audit_log.sig` regenerated. **Power-cycle and confirm the
  entries are still present** — real SD persistence, not a tmpfs.

## H8. PAIR001 — MAVLink signing required

- **Covers:** PAIR001 on hardware.
- **Action:** provision the signing key to
  `/fs/microsd/mavlink/mavlink-signing-key.bin`:
  ```
  python tools/provisioning/provision_signing_key.py --drone-id <id> --passphrase dgca_sitl_test
  ```
  Connect QGC with the **wrong** passphrase (no telemetry), then the
  **right** passphrase (full link).
- **Pass:** wrong/unsigned messages silently dropped FC-side; correct key
  gives full bidirectional link; `MAV_SIGN_CFG=1` enforced.

## H9. Audit log — live panel + auto-FTP backfill (over USB)

- **Covers:** LOG001 viewer, FTP transport.
- **Action:** open QGC Audit Log panel on connect.
- **Pass:** live panel populates within ~5 s (backfill retries up to 5×,
  5 s apart — the 2026-05-24 hardening); all entries from
  `audit_log.bin` shown, sorted descending by `seq`, no dupes between
  backfill and the 10 Hz `INOFLY_AL` stream; new events appear live.

## H10. Audit log — offline RSA-2048 signature verification

- **Covers:** LOG001 manufacturer-side verification.
- **Action:** download `audit_log.bin` + `audit_log.sig` via QGC, then:
  ```
  python tools/verify_audit_log.py \
      --log audit_log.bin --sig audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  ```
- **Pass:** `PASS: audit log signature is authentic`, exit 0. Decode is
  human-readable IST/UTC (AUDIT_FORMAT_VER 2):
  `python tools/decode_audit_log.py audit_log.bin`.

## H11. UPD001 — accept correctly signed bundle

- **Covers:** UPD001 positive path, PKG001.
- **Prereq:** regenerate fixtures at the current bundle format
  (`py -3 tools/regenerate_test_fixtures.py`).
- **Action:** in QGC SecureFirmwareUpdatePage, upload
  `test_firmware.fwbundle`, then **Install on Drone** (gated on
  `verificationState === Verified`).
- **Pass:** client-side VERIFIED (green); install reaches **ACCEPTED**;
  `/fs/microsd/inofly/update_manifest.bin` exists (373 B, fresh
  timestamp); SHA-256 of the staged file equals the bundle's
  `update_manifest.bin`; one `UPDATE_ATTEMPT` SUCCESS audit entry.

## H12. UPD001 — reject tampered/unsigned (both paths)

- **12.A QGC client-side:** load `test_firmware_tampered.fwbundle` →
  Signature **red FAILED**; Install button hidden; no FC upload;
  `entry_count` unchanged.
- **12.B FC drone-side:** with a valid manifest staged (H11), flip one
  byte in the CRC-covered region of
  `/fs/microsd/inofly/update_manifest.bin`, then `secure_boot
  verify_update` → `CRC mismatch ...`, `UPD001: update REJECTED
  (reason=2)`, one `UPDATE_ATTEMPT` FAILURE entry. Cleanup:
  `secure_boot clear_update`.

## H13. Attacker-key reinforcement (reason=3, signature mismatch)

- **Covers:** confirms the **libtomcrypt** RSA-PSS branch rejects a
  correctly-CRC'd, attacker-signed artifact (CRC passes; only the
  signature-vs-embedded-pubkey check fails).
- **Prereq:** `py -3 tools/regenerate_attacker_fixtures.py`
  (`.attacker_fixtures/`, gitignored).
- **Action:** per [SITL §13](SITL_ACCEPTANCE.md):
  - **13.A POST:** swap `attacker_manifest.bin` onto the SD, boot,
    `secure_boot start` → `POST FAILED (reason=3)`, `failure_reason=3`,
    arm denied. Restore good manifest.
  - **13.B QGC:** load `attacker_firmware.fwbundle` → red FAILED.
  - **13.C verify_update:** stage `attacker_update_manifest.bin`,
    `secure_boot verify_update` → `RSA-PSS signature verification FAILED`,
    `reason=3`. Cleanup `clear_update`.
- **Pass:** reason=3 on all three — proving the signature branch is live
  on real hardware, not dead code.

## H14. Organic `code_hash` / `data_hash` mismatch (reason 4/5) — **Tier 1 prize**

> This is the test SITL **structurally cannot** run. In SITL the POSIX
> branches of `_verify_code_hash`/`_verify_data_hash` short-circuit to
> `return true` (no flash to slice), so SITL §14 forces reasons 4/5 with
> a *stub flip* and only proves the reason-code plumbing. On hardware the
> hash-compute path is **real**, so we provoke reasons 4/5
> **organically** — a manifest whose hash field doesn't match the live
> flash — with **no code change**. This is the only place the
> hash-compute correctness itself is proven.

**Key subtlety — must stay reason=4/5, not collapse to reason=2/3.**
POST checks the manifest's CRC (reason=2) and RSA-PSS signature
(reason=3) *before* comparing hashes (reason=4/5). `code_hash` is inside
the signed payload, so a raw hex edit of the hash field would fail at the
**signature** check (reason=3), never reaching the hash comparison. To
land on reason=4/5 the manifest must be **validly signed but carry a
deliberately wrong hash**. Two ways:

- **Easiest:** generate a manifest from a *different but real* ELF (e.g.
  a prior build) via `pipeline --elf`, then provision it onto a unit
  running the *current* build. CRC + signature pass; the flash hash won't
  match → **reason=4** (code differs; code is checked first).
- **To isolate reason=5:** the manifest needs the *correct* `code_hash`
  but a *wrong* `data_hash`, then re-signed with the manufacturer key.
  This needs a small fixture helper (does not exist yet — see
  "Tooling to add" below) that takes the real manifest, keeps
  `code_hash`, swaps `data_hash`, and re-signs + re-CRCs. Keep its output
  in the gitignored fixtures dir only.

- **14.A code_hash (reason=4):** provision the wrong-`code_hash`
  validly-signed manifest, `secure_boot start`.
  - **Pass:** `ERROR secure_boot: firmware code hash mismatch`;
    `POST FAILED (reason=4)`; `failure_reason=4`; `commander check`
    lists reason=4; arm denied; one `POST_RESULT` FAILURE audit entry.
- **14.B data_hash (reason=5):** provision the correct-`code_hash` /
  wrong-`data_hash` validly-signed manifest, `secure_boot start`.
  - **Pass:** `ERROR secure_boot: firmware data hash mismatch`;
    `POST FAILED (reason=5)`; `failure_reason=5`; reason=5 in `commander
    check`; arm denied; one `POST_RESULT` FAILURE entry. (Reaching
    reason=5 also re-confirms the code→data check ordering on hardware.)
- **Restore:** re-provision the correct manifest (H2) and confirm POST
  PASS before continuing.

## H15. Real board_id mismatch (update path, reason=4)

- **Covers:** the update gatekeeper's `board_id` check
  ([`FirmwareUpdateAuthorization.msg`](../qgroundcontrol) reject enum
  4 = board_id mismatch) against the **real** STM32-derived board_id.
- **Why hardware-only:** SITL's board_id is synthetic, so this reject
  code is never exercised against a genuine target ID.
- **Action:** build/stage a validly-signed `update_manifest.bin` whose
  `board_id` is a *different* valid CubeOrange+/other-board value, then
  `secure_boot verify_update`.
- **Pass:** `UPD001: update REJECTED (reason=4)` (board_id mismatch, a
  *separate* enum from the POST reason=4 hash code — see SITL §14 Notes);
  one `UPDATE_ATTEMPT` FAILURE entry. Cleanup `clear_update`.

---

## Bootloader chain (BOOT001 / BOOT005 / BOOT006) — separate phase

Tier 1 above runs under the **factory PX4 bootloader** with our signed
app fw loaded via QGC. It does **not** install or test the verifying
secure bootloader. That belongs to production provisioning and is already
specified — do not duplicate it here:

> **Note (ADR-022 executed 2026-05-24).** The app fw no longer bundles
> the bootloader in ROMFS (it was moved to
> `boards/cubepilot/cubeorangeplus/bootloader_artifact/` to recover ~103 KB
> of FLASH). This is *why* the Tier 1 app fw flashes cleanly under the
> factory bootloader with no bootloader baggage. The secure bootloader is
> installed separately from SD (below).

- Secure-bootloader install: copy
  `bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin` to the SD,
  then `bl_update /fs/microsd/cubepilot_cubeorangeplus_bootloader.bin`;
  followed by BOOT001 positive/negative signature-enforcement tests:
  [MANUFACTURING_RUNBOOK.md](MANUFACTURING_RUNBOOK.md) Steps 4–7.
- Architectural rationale: [ARCHITECTURE.md §12 ADR-013/014/015](ARCHITECTURE.md).

**Open decision for the team:** whether to (a) prove the secure
bootloader on this same Tier 1 bench unit immediately after H1–H15, or
(b) keep bootloader bring-up as its own Phase 5b hardware milestone on a
dedicated unit (so a `bl_update` mistake never blocks app-fw Tier 1
testing). Recommendation: **(b)** — finish H1–H15 under the factory
bootloader first; the app-fw security stack is independently valuable and
the bootloader install is the one irreversible-ish step (DFU is
software-refused afterward).

---

## Tooling to add before running H14/H15

These don't exist yet; they're small and fixture-only (gitignored output):

- **`tools/make_hash_mismatch_manifest.py`** — take a real signed
  manifest, swap `code_hash` *or* `data_hash` to a wrong value, re-sign
  with the manufacturer key, re-CRC. Needed to isolate H14.B (reason=5)
  cleanly. H14.A can use a prior-build ELF instead, but this helper makes
  both sub-tests deterministic.
- **`tools/make_wrong_boardid_manifest.py`** (or a `--board-id` override
  on the existing pipeline) — produce a validly-signed update manifest
  with a non-matching `board_id` for H15.

Add a cross-key/cross-hash sanity guard at generation time (as
`regenerate_attacker_fixtures.py` does) so a buggy fixture can't
false-pass by accidentally matching the running flash.

---

## Pre-fielding sign-off

Tier 1 is complete when **H0–H15 pass on a real CubeOrange+** under the
build that passed SITL_ACCEPTANCE, with results (date, PX4/inoflyTools/QGC
commit hashes, board UID) recorded here. H3 + H14 are the load-bearing
new evidence over SITL: they prove the real hash-compute path and the
OpenSSL→libtomcrypt interop. After Tier 1, the next milestone is the
secure-bootloader chain (Phase 5b) and then per-unit production
provisioning per the Manufacturing Runbook.

| Step | Result | Date | Notes |
|---|---|---|---|
| H0 board health | ⬜ | | |
| H1 flash secure_boot | ⬜ | | |
| H2 provision real manifest | ⬜ | | |
| H3 POST pass (real hash) | ⬜ | | **milestone** |
| H4 uORB real values | ⬜ | | |
| H5 tamper → reason=2 | ⬜ | | |
| H6 PAR001 enforcement | ⬜ | | |
| H7 PAR001 audit (SD persist) | ⬜ | | |
| H8 PAIR001 signing | ⬜ | | |
| H9 live panel + backfill | ⬜ | | |
| H10 offline sig verify | ⬜ | | |
| H11 UPD001 accept | ⬜ | | |
| H12 UPD001 reject (A+B) | ⬜ | | |
| H13 attacker-key reason=3 | ⬜ | | |
| H14 organic reason 4/5 | ⬜ | | **Tier 1 prize** |
| H15 board_id reason=4 | ⬜ | | |
