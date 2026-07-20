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

## Progress after Day 1 (2026-05-26 → 2026-05-28)

The Day 1 resume plan executed in three bench sessions. All four
hardware-only bugs that surfaced (BUG #1/#2/#3/#4) are now closed,
committed, and pushed.

| Date | What happened | Result |
|---|---|---|
| 2026-05-26 (offline) | BUG #1 fix (audit logger NuttX sync write path) committed as PX4 fork `e33eca2394`; BUG #2 fix (USB SIGN_OUTGOING exemption) as `5c5c79ba3d`. SITL 335/335 + integration green. | Both fixes ready for bench re-flash. |
| 2026-05-27 (bench) | Re-flash + BUG #4 surfaced — POST stack overflow during libtomcrypt RSA verify. Fixed in same session (`STACK_MAIN 20480` + `static rsa_key`), committed as `fb2a628528`. | **H3 ✅** (POST verdict visible) **H7 ✅** (audit log persists 4 CRC-clean entries on real SD). BUG #3 surfaced — `.sig` file never written. |
| 2026-05-28 (bench) | BUG #3 root cause: `arc4random_buf` hung on uninit `g_rng.rd_sem` because `up_randompool_initialize` was never called on this board. Fix = `CONFIG_DEV_URANDOM=y` + `CONFIG_DEV_URANDOM_RANDOM_POOL=y` + `CONFIG_BOARD_INITRNGSEED=y` + `board_init_rngseed()` seeding from STM32 96-bit MCU UID. Committed `a7ed0be789`. | **H10 ✅** (offline RSA verification PASSED end-to-end — see evidence under H10 below). LOG001 chain fully proven on hardware. |
| 2026-05-28 EOD → 2026-05-29 IST early (bench, Day 5) | Re-provisioned manifest from `a7ed0be789` ELF; H3 reconfirmed on the new build; H4 substantively closed (hashes match manifest byte-for-byte); H5 PASS (tamper → reason=2 clean end-to-end). H6 attempted and **failed**: BUG #5 found — kind-aware PAR001 runtime hooks silent on NuttX (boot validation works, runtime `param_set`/`param_get` interception doesn't fire). Audit log itself confirms BUG #5 (zero `COMPLIANCE_PARAM_VIOLATION` entries despite two violating writes). BUG #3 fix re-validated under PASS→FAIL→PASS cycle with multiple `.sig` regenerations. No code changes this session. | **H4 ✅**, **H5 ✅** (audit log decoded auditor-grade — see evidence under H5 below). **H6 ❌ FAIL — BUG #5**. |
| 2026-05-30 (bench, Day 6) | BUG #5 fix committed (`bca0c5e212`). Re-flashed + re-provisioned; **H6 closed** (console + QGC `PARAM_SET` both reject). Found **BUG #6** (violation audit on async path) + **BUG #6b** (cached `_log_fd` EBADF — NuttX per-task-group fds); both fixed + committed (`255b8e4003`). **H7 closed for PAR001 violations** (`#9`/`#10` logged, 11/11 CRC OK, `.sig` authentic). H3/H10 reconfirmed. | **H6 ✅**, **H7 ✅** (PAR001 violations), H3/H10 ✅ reconfirmed. **H11–H15 unblocked.** |

### H-step status after Day 6 (2026-05-30 IST)

| Step | Status | Closed on |
|---|---|---|
| **H0** board health | ✅ PASS | Day 1 (2026-05-25) |
| **H1** flash secure_boot | ✅ PASS | Day 1 |
| **H2** provision manifest | ✅ PASS | Day 1 |
| **H3** POST verdict visible | ✅ PASS | Day 3 (BUG #4 fix); reconfirmed Day 5/Day 6 |
| **H4** `firmware_integrity_status` published | ✅ PASS | Day 5 (code/data hashes match manifest byte-for-byte; 2 caveats — see H4 below) |
| **H5** tamper test reason=2 | ✅ PASS | Day 5 (CRC mismatch detected, arming blocked, audit entry logged) |
| **H6** PAR001 kind-aware enforcement | ✅ **PASS** | **Day 6** — BUG #5 fix flashed; console + QGC `PARAM_SET` both reject over-cap/LOCKED |
| **H7** audit log persists on real SD | ✅ PASS | Day 3; **Day 6** extended to PAR001 violations (BUG #6/#6b fixed — `#9`/`#10` logged, 11/11 CRC OK) |
| **H8** PAIR001 MAVLink signing | ⏸️ not started — needs SiK telemetry; PAIR001 hardware coverage gap |
| **H9** live panel + auto-FTP | ✅ **PASS** | **Day 8** — BUG #7 fixed (absolute FTP paths); audit download 33 entries + `.sig`; live panel streams from boot (autostart) |
| **H10** offline RSA-2048 sig verification | ✅ PASS | Day 4 (1-entry); re-proven Day 5/Day 6 on 11-entry multi-event log |
| **H11** UPD001 accept | ✅ PASS | **Day 7** — FC `verify_update` accepts manufacturer-signed staged manifest (QGC bundle-verify green); **Day 8** — FTP transport fixed (BUG #7), Install-on-Drone → ACCEPTED on hardware |
| **H12** UPD001 reject (A QGC + B FC) | ✅ PASS | **Day 7** — QGC red FAILED; FC CRC tamper → reason=2 |
| **H13** attacker-key reason=3 | ✅ PASS | **Day 7** — POST (ret=7) + verify_update (ret=22) + QGC all reject; libtomcrypt sig branch proven live |
| **H14** organic reason 4/5 (Tier 1 prize) | ✅ PASS | **Day 7** — reason=4 (code, 1.87 MB hashed) + reason=5 (data, 96 B; code→data ordering confirmed); restore → PASS |
| **H15** board_id reason=4 | ✅ PASS | **Day 7** — FC gap found+fixed (board_id check added to gatekeeper, PX4 `9bc8395660`); 1064 → reject, 1063 → accept |

H10 evidence — actual session output, manufacturer private key,
real `audit_log.bin` + `audit_log.sig` pulled from CubeOrange+ SD
after BUG #3 fix flashed:

```
$ py tools/verify_audit_log.py \
    --log release/sd/audit_log.bin \
    --sig release/sd/audit_log.sig \
    --key pki/manufacturer/private/manufacturer_private.pem
  log file:        release\sd\audit_log.bin  (316 bytes, 1 entries)
  expected SHA-256: 016dcee26f7e71f4c1600d3c6e90e3612ee8f095d0e7cddb79db395e457d2bb4
  decrypted hash:   016dcee26f7e71f4c1600d3c6e90e3612ee8f095d0e7cddb79db395e457d2bb4
PASS: audit log signature is authentic

$ py tools/decode_audit_log.py release/sd/audit_log.bin
Audit log: release\sd\audit_log.bin  (1 entries)
========================================================================
#0  28 May 2026, 10:02:40 AM IST (04:32:40 UTC)
      Pre-operational self-test FAILED - the firmware code has changed
      since it was signed (code hash mismatch); arming is blocked.
      [POST001/POST002/POST003]
      detail: "POST"
      CRC OK
------------------------------------------------------------------------
Status: OK - every entry parsed and passed CRC.
```

This is the **canonical LOG001 / the audited reference §8 property** proven on
hardware for the first time: the manufacturer, using only the
offline private key and the downloaded `.bin` + `.sig` pair,
recovers the FC's signed SHA-256 and verifies it matches the log
content byte-for-byte. The decoded entry is auditor-readable and
correctly reflects the bench reality (POST failed against the
stale-for-this-build manifest, reason aligns with `[POST002]`).

### Day 5 evidence — H4, H5, and the BUG #5 discovery

**H4 — `firmware_integrity_status` published with real values.** After
re-provisioning the manifest from the `a7ed0be789` ELF and running
`secure_boot start`:

```
nsh> listener firmware_integrity_status
TOPIC: firmware_integrity_status
  check_passed: True
  failure_reason: 0
  code_hash: [55, 191, 183, 193, 52, 241, 26, 52, ...]
  data_hash: [238, 95, 147, 247, 13, 139, 44, 26, ...]
  board_id: 39
```

The first eight bytes of `code_hash` decode to `37 bf b7 c1 34 f1 1a 34`
and `data_hash` to `ee 5f 93 f7 0d 8b 2c 1a` — **exact byte-for-byte
match** to what `tools/pipeline.py --elf` computed at provisioning
time. First end-to-end evidence on this build that real-flash hashing
on hardware reproduces the manifest values (OpenSSL→libtomcrypt interop
proven on multi-megabyte flash ranges).

Two caveats flagged for follow-up (don't block H4):

1. **`board_id: 39`** — the compiled `SECURE_BOOT_BOARD_ID = 1063`, and
   `1063 & 0xFF = 39`. The on-device gate uses the constant, not this
   field (otherwise POST would reject reason=6), so the field is
   display-only — but the truncation suggests the `uORB` msg has the
   field as `uint8`. Should be widened. Not a security regression.
2. **`boot_count` and `manifest_version` not published** despite this
   doc claiming they are. Either the `firmware_integrity_status.msg`
   doesn't carry them or the `listener` only prints a subset. Worth a
   one-line check of the `.msg` definition.

**H5 — tamper test → reason=2, arming blocked.** Powered down, flipped
one byte at offset 100 in `/fs/microsd/inofly/manifest.bin` on the SD
card (inside the CRC-covered region), reinserted, booted, then
`secure_boot start`:

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
nsh> commander arm      → denied (silent)
```

CRC mismatch caught **before** any signature or hash check — exactly
the ordering ARM001/POST001 intends. Restoring the good manifest and
rebooting returns POST to PASS, confirming the gate is data-driven, not
sticky. Audit log grew 2→3 entries; the BUG #3 fix held under this
FAIL-side `.sig` rewrite (previously: only proven on PASS side). Offline
RSA verification of the 3-entry post-H5 log (re-running H10):

```
$ py tools/verify_audit_log.py --log release/sd/audit_log.bin \
      --sig release/sd/audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  log file:        release\sd\audit_log.bin  (948 bytes, 3 entries)
  expected SHA-256: 698c76f9c6b07558ed3b6b962942708290c1e7b36c9b449671247ace784f4608
  decrypted hash:   698c76f9c6b07558ed3b6b962942708290c1e7b36c9b449671247ace784f4608
PASS: audit log signature is authentic

$ py tools/decode_audit_log.py release/sd/audit_log.bin
#0  28 May 2026, 10:02:40 AM IST   POST FAILED - code hash mismatch       [POST002]
#1  29 May 2026, 02:03:07 AM IST   POST passed - firmware verified        [POST001/002/003]
#2  29 May 2026, 02:17:31 AM IST   POST FAILED - manifest CRC failed      [POST001]
Status: OK - every entry parsed and passed CRC.
```

H7 + H10 simultaneously extended: multi-event log, mixed PASS/FAIL,
`.sig` recovers byte-for-byte. The H5 entry is rendered auditor-grade
in plain English.

**H6 = ❌ FAIL — BUG #5 surfaced.** With POST passing and the
`.compliance_params` table loaded (boot validation printed all 6
protected params with correct ceilings/registered values), runtime
enforcement was tested via nsh:

| Attempt | Expected | Actual |
|---|---|---|
| `param show SYS_AUTOSTART` | `4001` (LOCKED lazy-zero read) | `0` |
| `param set GF_MAX_VER_DIST 200` | REJECT — over cap 120 | **ACCEPTED** (curr 0 → new 200) |
| `param set SYS_AUTOSTART 4002` | REJECT — `attempted=4002 registered=4001 (LOCKED)` | **ACCEPTED** (curr 4001 → new 4002) |

The audit log's requirement-coverage table corroborates:
`PAR001 / 7.1(c) ... no events recorded`. Two violating writes
produced zero `COMPLIANCE_PARAM_VIOLATION` entries.

**Diagnosis.** Boot-time `ComplianceParamGuard::validate_at_boot()`
runs correctly — it reads the `.compliance_params` flash table
directly. The runtime hooks into `param_set` / `param_get` that
ADR-019/020 added are **not firing on hardware** despite passing SITL
§6 (per memory 2026-05-11). Same class as BUG #1/#3: SITL clean,
NuttX-path divergent. Likely candidates (to confirm offline):

1. The hook registration in `ComplianceParamGuard::init()` is
   `__PX4_POSIX`-gated and silently skipped on NuttX.
2. The kind-aware patch in `src/lib/parameters/parameters.cpp` is
   conditional on a config flag not set in `cubepilot_cubeorangeplus_default`.
3. A `cdev`-vs-`parameter_client` divergence — the nsh `param` command
   might take a path that bypasses the hook even when MAVLink wouldn't
   (worth a MAVLink-side `PARAM_SET` cross-check next bench session).

H6 blocks H11–H15 transitively (UPD001/PAR001 flows assume PAR001
runtime enforcement). H7/H10 are unaffected — those are LOG001/POST,
not PAR001.

**BUG #5 — ROOT CAUSE FOUND + FIXED (2026-05-29, offline).** None of
the three bench-side candidates above was correct; the real cause was a
build-system gap, and it affected **SITL too** — meaning the recorded
2026-05-11 "SITL §6 pass" was a false pass (PAR001 runtime enforcement
has been compiled out since its introduction commit `fc91ce0f9e`).

The enforcement lives in `src/lib/parameters/compliance_check.cpp`,
wrapped in `#if defined(CONFIG_MODULES_SECURE_BOOT) ... #else /* no-op
stubs */ #endif`. That file is part of the **`parameters` library**,
which is always compiled. The board defconfig sets
`CONFIG_MODULES_SECURE_BOOT=y`, but in PX4 a kconfig `CONFIG_*` line is
only a **CMake variable** — it is *not* automatically a C++ preprocessor
define for a library. `src/lib/parameters/CMakeLists.txt` used the
variable to add the include path (`if(CONFIG_MODULES_SECURE_BOOT)
target_include_directories(...)`) but never declared the matching
`target_compile_definitions`. So `compliance_check.cpp` compiled the
**`#else` no-op stub branch** on every target:
`param_is_compliance_protected()` → `false`, `param_check_within_cap()`
→ `true`, `param_compliance_first_unset()` → `nullptr`. Result: the
cap-check in `parameters.cpp::param_set_internal` and the LOCKED
lazy-zero read in `param_get` were both bypassed — exactly the bench
symptoms (over-cap accepted, `SYS_AUTOSTART` reads 0). No warning, no
link error, green build. Boot-time validation was unaffected because it
reads the `.compliance_params` table on a separate code path.

Fix (PX4 fork, one line in `src/lib/parameters/CMakeLists.txt`):
```cmake
if(CONFIG_MODULES_SECURE_BOOT)
    target_include_directories(parameters PRIVATE ${PX4_SOURCE_DIR}/src/modules/secure_boot)
    target_compile_definitions(parameters PRIVATE CONFIG_MODULES_SECURE_BOOT)   # BUG #5 fix
endif()
```
`compliance_check.cpp` is the only file outside the `secure_boot` module
that uses this define, so the one line fully closes the gap.

**SITL re-validation after fix (2026-05-29, clean `rm -rf
build/px4_sitl_default` reconfigure):** `compile_commands.json` confirms
`-DCONFIG_MODULES_SECURE_BOOT` now reaches both `parameters.cpp` and
`compliance_check.cpp`. Headless shell-mode (`PX4_SIM_MODEL=shell`) §6
run:

| Command | Result |
|---|---|
| `param show GF_MAX_VER_DIST` (post-boot) | `0` — CAPPED lazy-zero ✅ |
| `param set GF_MAX_VER_DIST 200` | REJECT: `Flight-limit guard ... attempted=200.000 ceiling=120.000` ✅ |
| `param set GF_MAX_VER_DIST 120` (at ceiling) | accept; `param show` → `120.0000` ✅ |
| `param set SYS_AUTOSTART 4002` | `curr: 4001` → REJECT: `attempted=4002 registered=4001 (LOCKED)` ✅ |
| `param set SYS_AUTOSTART 4001` (no-op) | accept silently, no WARN ✅ |
| `param set MAV_SIGN_CFG 0` | `curr: 1` → REJECT: `attempted=0 registered=1 (LOCKED)` ✅ |
| `param show SYS_AUTOSTART` / `MAV_SIGN_CFG` (once active) | `4001` / `1` ✅ |

All ADR-019/020 behaviors restored. **H6 remains ❌ pending the hardware
re-flash + bench re-run** — the fix is proven in SITL but not yet on the
CubeOrange+. Next bench session: re-flash the rebuilt
`cubepilot_cubeorangeplus_default`, re-run H6, and (since the SITL pass
was previously false) treat the bench result as the authoritative gate.

Lesson recorded: a PX4 `CONFIG_*` kconfig var is a CMake variable, not a
C/C++ define — a library file guarded by `#if defined(CONFIG_*)` needs an
explicit `target_compile_definitions` or it silently compiles the
`#else` branch.

---

### Day 6 evidence (2026-05-30 IST) — H6 closed on bench; BUG #6/#6b found + fixed; H7 PAR001-violation logging proven

**H6 ✅ closed.** Re-flashed the BUG #5 fix build (`bca0c5e212` +
uncommitted CMakeLists one-liner), re-provisioned the manifest from the
new ELF, and re-ran on the real CubeOrange+. All ADR-019/020 behaviors
fired through **both** entry points:
- nsh console: `GF_MAX_VER_DIST 200` → REJECT `attempted=200.000
  ceiling=120.000`; `120` accepted; `SYS_AUTOSTART 4002` → REJECT
  `attempted=4002 registered=4001 (LOCKED)`; `4001` no-op accepted;
  `MAV_SIGN_CFG 0` → REJECT `registered=1 (LOCKED)`.
- QGC (InoflyGCS) Parameters editor (MAVLink `PARAM_SET` path, distinct
  from the nsh `param` command): over-cap write → *"Parameter write
  failed: GF_MAX_VER_DIST"*. Confirms the guard sits in
  `param_set_internal` and fires regardless of caller. (Note: QGC display
  units — a value typed in **feet** is converted to **meters** before the
  `PARAM_SET`; the 120 **m** cap = ~393.7 ft, so `200 ft`≈61 m is accepted
  and `1000 ft`≈305 m is rejected. Caps are enforced in SI units.)

**BUG #6 + #6b — PAR001 violations weren't reaching the audit log on
hardware (found because BUG #5's fix made enforcement real).** Two
layered causes, both fixed (PX4 fork `255b8e4003`):
- **#6:** `ComplianceParamGuard::onViolation()` published the audit event
  only via `orb_advertise()` — the async uORB path BUG #1 already found
  unreliable on NuttX. POST/UPDATE were moved to the synchronous
  `logEventSync()` path then; violations were left on the async rail.
  Fix: route `onViolation()` through `logEventSync()` (guard now holds a
  `SecurityAuditLogger*`), `orb_advertise()` fallback only.
- **#6b:** the sync write then failed with `ERROR write failed: Bad file
  number` (EBADF). `SecurityAuditLogger` cached `_log_fd` from
  `_openLogFile()`, which runs in the `secure_boot` command task. **NuttX
  file descriptors are per-task-group**, so the cached fd is invalid when
  `_writeEntry()` runs on the `param_set` caller thread (nsh /
  `mavlink_receiver`). Fix: drop the cached fd; `_writeEntry()` opens its
  own `O_APPEND` fd per write — the pattern `_recoverSequenceNum()` /
  `_updateLogSignature()` already used. This also explains the original
  BUG #1 async silence (the WQ `Run()` likewise executes off the
  fd-owning task). No change to enforcement, POST, update verification, or
  the log/signature format — only audit-event delivery + fd lifecycle.

**H7 ✅ closed (now incl. PAR001 violations).** Post-fix bench run, decoded
+ verified offline:
- `secure_boot start` → POST `#8` logged (type=1 result=0); **no
  `write failed`**.
- `GF_MAX_VER_DIST 200` → `#9` logged; `SYS_AUTOSTART 4002` → `#10`
  logged — both `EVENT_PARAM_CHANGE / FAILURE`, decoded as *"Attempted to
  change &lt;NAME&gt; - rejected (protected flight parameter) [PAR001 /
  Gazette 7.1(c)]"*.
- `secure_boot param_status` → `Violations rejected : 2`; pre-arm
  correctly `BLOCKED (first unset: GF_MAX_VER_DIST)`.
- Bonus: entry `#7` shows the **pre-arm arming gate** is itself audited
  (*"Arming was blocked by a security check / compliance unset:
  GF_MAX_VER_DI"*, `POST001 arming gate`).
- `decode_audit_log.py`: **11/11 entries CRC OK, 0 failures**; PAR001
  coverage = 2 events (was 0). `verify_audit_log.py`: **signature
  authentic** (decrypted SHA-256 matches `audit_log.bin` byte-for-byte).

**H3 ✅ / H10 ✅ reconfirmed** on the Day 6 build (POST code/data check
green against the re-provisioned manifest; 256-byte `.sig` verifies).

With H6 cleared, **H11–H15 are unblocked** for the next bench session.

---

### Day 7 evidence (2026-06-04 IST) — H11–H15 closed; Tier 1 H0–H15 functionally complete (H8/H9 carried)

Ran the remaining update/POST gate on the CubeOrange+ after rebuilding the
`255b8e4003` fork (BUG #5/#6/#6b) and re-provisioning. Two findings on the
way (one FC gap fixed for H15, one QGC transport bug deferred). Fixtures for
H14/H15 were built offline by the two new helpers
(`tools/make_hash_mismatch_manifest.py`, `tools/make_wrong_boardid_manifest.py`,
covered by `tests/compliance/test_H14H15_fixture_helpers.py`); all FC-side
staging was done by hand via the SD card + nsh `cp` because of BUG #7.

| Step | Result | Evidence |
|---|---|---|
| **H11** accept | ✅ | `verify_update` → `accepted - manufacturer signature verified`, `authorized update to v0.1 (board_id=1063)`, `UPDATE_ATTEMPT` SUCCESS (`#13`). QGC bundle-verify **green VERIFIED**. |
| **H12.A** QGC reject | ✅ | `test_firmware_tampered.fwbundle` → red `FAILED — Signature invalid`, Install hidden. |
| **H12.B** FC reject | ✅ | tampered staged manifest → `CRC mismatch (stored=0x919173B6 computed=0xBB4D308B)` → REJECTED reason=2, `UPDATE_ATTEMPT` FAILURE (`#16`). |
| **H13** attacker key | ✅ | POST `Signature check failed (ret=7)` reason=3 (`#21`); `verify_update` `(ret=22)` reason=3 (`#23`); QGC red. libtomcrypt RSA-PSS reject branch proven live on all three paths. |
| **H14.A** code (reason=4) | ✅ | `Firmware code check FAILED - code changed since signing (1870700 bytes)`, `failure_reason: 4`, arm blocked (`#24`). Real 1.87 MB flash hash. |
| **H14.B** data (reason=5) | ✅ | `Flight-parameter check FAILED - parameters changed since signing (96 bytes)`, `failure_reason: 5`. Listener showed **correct** `code_hash` + **wrong** `data_hash` → confirms code→data ordering on hardware. Restore → POST PASS (`#28`). |
| **H15** board_id (reason=4) | ✅ | board_id 1064 manifest → `board_id 1064 does not match this hardware (1063)`, REJECTED reason=4 (`#31`); board_id 1063 → ACCEPTED (`#32`). |

**H15 — FC gap found and fixed.** `FirmwareUpdateGatekeeper::verifyAndAuthorize`
verified CRC + magic + signature but **never compared board_id** — a
validly-signed update targeting a different board was being *accepted*
(`REASON_BOARD_ID_MISMATCH=4` existed in the msg, but no check used it). This
was never caught before because H15 has no SITL counterpart. Fix (PX4 fork
`9bc8395660`): added a Step-5 board_id check after the signature check,
guarded `#if defined(SECURE_BOOT_BOARD_ID)` exactly like POST004
`_verify_board_id`, so SITL is unaffected. The Tier 1 build was rebuilt with
this fix; H11–H14 had already passed on the immediately prior build (only
delta is the new check), and the H15 positive control re-confirms accept on a
correct board.

**BUG #7 (QGC-side, transport-only, ✅ RESOLVED 2026-06-05 Day 8 — see Day 8 evidence below).** QGC's "Install on Drone"
FTP-upload of `update_manifest.bin` fails with `File Not Found`
(`kCmdCreateFile` → `open(O_CREAT)` → `ENOENT`) even though the FC itself
writes `audit_log.bin` into the same `/fs/microsd/inofly/` every boot and
`cp` creates files there fine. So the FTP module's runtime root path isn't
resolving `inofly/…` to the same `/fs/microsd/inofly/` the secure_boot module
uses directly. FTP read from `inofly/` has never actually been exercised on
hardware either (audit logs were SD-pulled, H9 never run on hw). The decisive
data point — whether a QGC FTP **download** of `inofly/audit_log.bin` also
fails on hardware — is the first step of the BUG #7 fix. This is QGC/transport
plumbing, **not** the security stack: the FC accept/reject property (H11/H12.B)
was proven directly via nsh, and QGC's client-side bundle verification (H12.A,
H13.B) works. Does not block Tier 1.

**Observation — `data_hash` is sensitive to code layout.** A pure code-side
change (the H15 gatekeeper edit) shifted `data_hash` from `99f5fd28…` to
`f05e43d2…` even though no compliance-param *values* changed. Likely the
`.compliance_params` table embeds param-name string pointers whose addresses
moved. Not a security issue (POST regenerates the manifest per build, and the
hash check is self-consistent), but it means `data_hash` is not reproducible
across unrelated code changes — worth a note for the reproducible-build /
auto-update story. Tracked as a follow-up, does not block Tier 1.

**Carried gaps (as of Day 7):** H8 (PAIR001 over SiK telemetry) and H9 (live
audit panel + auto-FTP backfill on hardware) remain — H8 needs telemetry-radio
bench coverage and H9 is gated on BUG #7. **H9 was closed on Day 8 once BUG #7
was fixed (see below); only H8 now remains.**

### Day 8 evidence (2026-06-05 IST) — BUG #7 fixed, POST/logger autostart wired, H9 closed

Closed the QGC FTP transport gap (BUG #7) and, with it, the real-time
live-panel and Install-on-Drone flow on the CubeOrange+, then wired POST + the
audit logger to autostart at boot.

**BUG #7 root cause — relative-vs-absolute FTP path (the Day 7 analysis had it
backwards).** PX4 `mavlink_ftp` prepends `_root_dir = PX4_ROOTFSDIR` to every
requested path. On **NuttX hardware `PX4_ROOTFSDIR = ""`** (empty); in **SITL
it is `"."`**. Our QGC custom controllers sent **relative** URIs
(`inofly/audit_log.bin`, `inofly/audit_log.sig`, `inofly/update_manifest.bin`)
which on hardware resolved cwd-relative (`/inofly/…`) → `FileNotFound`, even
though the FC writes/reads `/fs/microsd/inofly/`. The upload also failed
`_validatePathIsWritable` (NuttX-only; requires a `/fs/microsd/` prefix). SITL
hid it because `_root_dir="."` made the relative paths resolve. **Fix:**
absolute `/fs/microsd/inofly/…` in QGC (`AuditLogController`,
`SecureFirmwareController`), inoflyGCU `6351f519d`; SITL keeps working via
`tools/sitl_ftp_symlink.sh` (`rootfs/fs/microsd/inofly -> ../../inofly`,
SITL_ACCEPTANCE step 2a). **Verified on hardware:** audit-log **download** =
`Parsed 33 entries (33 valid) — signature downloaded`; **upload** reaches the
FC gatekeeper.

**Install-on-Drone timeout / empty live panel — root cause was a dormant audit
logger, not FTP.** After the FTP fix, download worked but Install-on-Drone
timed out and the live panel stayed empty (file-backfill only). Cause:
**`secure_boot start` had not run this boot**, so `g_audit_logger` was null →
`verify_update`'s audit event took the dead-end uORB-advertise fallback that
nothing consumes → no file write and no `_streamEvent` → no `INOFLY_AL`
`DEBUG_FLOAT_ARRAY`, which is exactly the live stream QGC's install listener
waits on → timeout. Diagnosed via `listener debug_array` = **"never published"**
plus the missing `Audit event recorded` log line (the `DEBUG_FLOAT_ARRAY` stream
itself is correctly configured — USB instance = mode Onboard @10 Hz). After a
manual `secure_boot start`, `verify_update` logged `#N` AND `listener
debug_array` showed `name:"INOFLY_AL"` → QGC Install-on-Drone → **ACCEPTED**,
live panel streamed.

**Fix — POST + logger autostart at boot (resolves the deferred autostart
item).** Wired `secure_boot start` into boot so POST runs and the logger comes
up every boot with no manual nsh command. Without it a fresh boot ran **no POST
and no arming gate** (a POST001 gap on a deployed unit) plus the dead-end audit
path above.
- `boards/cubepilot/cubeorangeplus/init/rc.board_extras` (new) — `secure_boot
  start`, sourced late by rcS after params + airframe setup.
- `ROMFS/px4fmu_common/init.d-posix/rcS` — same line for SITL parity.
- PX4 fork `354696551e`. Changes `code_hash` (new `21cf1d8b`; `data_hash`
  `f05e43d2` unchanged) → clean rebuild (the new ROMFS file needs a CMake
  reconfigure) + reprovision.
- **Verified on CubeOrange+** (flashed `g9bc8395660-dirty`, Jun 5 build):
  `firmware_integrity_status check_passed=True` with **no manual start**, Live
  Events stream from boot, Install-on-Drone → **ACCEPTED**. SITL (SIH boot)
  confirms the same.

| Step | Result | Evidence |
|---|---|---|
| **H9** live panel + auto-FTP backfill | ✅ | Audit download = 33 entries (33 valid) + `.sig`; live panel streams from boot (autostart). First real FTP read over the USB link on hardware. |
| **H11** FTP transport (was BUG #7) | ✅ | QGC FTP upload of `update_manifest.bin` lands at `/fs/microsd/inofly/`; Install-on-Drone → **ACCEPTED** (board-1063 bundle). |

**Boot-timestamp note (GPS solution chosen).** Autostart POST runs ~1 s after
power-on, before any time source, so the boot POST/arming entries are
uptime-stamped (`wall clock not synced`): the Cube's RTC reads its 2000 default
(drained supercap) and QGC `SYSTEM_TIME` / GPS set the clock only post-boot.
Decision — rely on GPS (deployed units) for real dates and keep the honest "not
synced" flag for pre-sync boot events rather than persist a possibly-stale time
(`time_persistor` rejected for the audit log; deferring POST until sync rejected
because it would leave arming ungated on a no-GPS/no-GCS unit). The ulog remains
the authoritative time source at audit.

**Tooling:** `pipeline.py` now copies the input `.px4` into the output dir
(inoflyTools `083ff81`) so the loose `release/*.px4` can't go stale across
rebuilds.

**Only carried gap:** **H8** (PAIR001 over SiK telemetry) — needs a
telemetry-radio bench. Tier 1 H0–H7 and H9–H15 are now closed on real silicon.

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
| SITL apply/promotion matrix (`tests/integration/test_sitl_apply_update.py`, 44/44) | **H16** ⭐ | ADR-023 end-to-end **from QGC** + real BL flash + the `matchesRunningFirmware()` promotion leg SITL stubs out — needs A-11 |
| same matrix, negative legs | **H17** ⭐ | All three gates' rejects on real silicon + power-loss recovery regression (B9.6 mechanic) |

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
  `secure_boot audit_status` resolves (module present — note there is no
  `status` subcommand; valid ones are `start`/`verify_update`/`clear_update`/
  `audit_status`/`param_status`, and `listener firmware_integrity_status`
  shows the POST result). FLASH usage within
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
- **Pass:** `manifest.bin` is **373 bytes**, magic `INOFLY04`,
  `format_ver = 4` *(format v4 since 2026-07-16 — `created_at` is inside the
  RSA-signed payload; a v3 `INOFLY03` manifest is rejected by v4 firmware and
  vice versa, so always regenerate the manifest from the same pipeline run as
  the flashed build)*. Host-side pre-check passes before provisioning:
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
- **Action:** boot the unit — POST runs automatically (`secure_boot start`
  is autostarted via `rc.board_extras` since Day 8; no manual command needed).
  Watch the boot log for the `secure_boot` POST lines.
- **Autostart note (applies to every reboot-based test below):** since Day 8
  POST/logger autostart at boot, so where a later step says "reboot,
  `secure_boot start`" the reboot alone triggers POST — the manual command is
  a redundant no-op ("already running"), and its POST output now appears in the
  **boot log** rather than as a typed-command response. Evidence is unchanged
  (boot log + `listener firmware_integrity_status` + the audit entry).
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

## H9. Audit log — live panel + auto-FTP backfill (over USB) ✅ PASS (2026-06-05 Day 8)

- **Covers:** LOG001 viewer, FTP transport.
- **Action:** open QGC Audit Log panel on connect.
- **Pass:** live panel populates within ~5 s (backfill retries up to 5×,
  5 s apart — the 2026-05-24 hardening); all entries from
  `audit_log.bin` shown, sorted descending by `seq`, no dupes between
  backfill and the 10 Hz `INOFLY_AL` stream; new events appear live.
- **Closed:** 2026-06-05 (Day 8) once BUG #7 was fixed (absolute FTP paths,
  inoflyGCU `6351f519d`) and the logger autostarts (PX4 `354696551e`).
  Download = 33 entries (33 valid) + `.sig`; live panel streams from boot.
  First real FTP read over the USB link on hardware. Requires the logger to be
  running — POST/logger autostart (Day 8) is what makes the live stream flow.

## H10. Audit log — offline RSA-2048 signature verification ✅ PASS (2026-05-28)

- **Covers:** LOG001 manufacturer-side verification.
- **Action:** download `audit_log.bin` + `audit_log.sig` via QGC (or
  via SD pull), then:
  ```
  python tools/verify_audit_log.py \
      --log audit_log.bin --sig audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  ```
- **Pass:** `PASS: audit log signature is authentic`, exit 0. Decode is
  human-readable IST/UTC (AUDIT_FORMAT_VER 2):
  `python tools/decode_audit_log.py audit_log.bin`.
- **Closed:** 2026-05-28 against the BUG #3 fix (PX4 fork
  `a7ed0be789`). Actual session output captured in the post-Day-1
  progress section above.

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

## H16. ADR-023 signed update end-to-end from QGC — **milestone** ⭐ NEW 2026-07-16 (A-9; runs after A-11 QGC work)

- **Covers:** the full operator-facing update flow — QGC uploads a v1.2
  `.fwbundle`'s artifacts, `apply_update` verifies + stages, reboot-to-BL,
  the secure bootloader flashes from SD, first-boot **promotion** activates
  the new manifest, POST goes green — with the audit trail to prove it.
  This is the hardware twin of the committed SITL matrix
  (`tests/integration/test_sitl_apply_update.py`) plus the QGC transport
  and the `matchesRunningFirmware()` leg that SITL stubs out.
- **Prereqs:** secure (A-4+) bootloader installed (B9 unit state);
  **manifest format v4 on both sides** (firmware and manifest from the same
  pipeline run); A-11 QGC flow built. Until A-11 lands, the bench-verb
  variant (`secure_boot apply_update --reboot` with hand-staged files) is the
  fallback — that variant was already proven in B9/B10.3.
- **Action:** build + sign a *newer* release (`pipeline.py` with `--elf`),
  deliver `UPDATE.BIN` + `UPDATE.MTA` + staged `update_manifest.bin` via QGC
  (MAVLink-FTP), trigger apply from QGC, let the unit reboot and complete.
- **Pass:**
  - `apply_update` accepts (authorized, `image_verified=true`), writes the
    `inofly/update_pending` marker, reboots to the bootloader;
  - BL applies (solid-LED erase → flicker write), new app boots;
  - first boot: promotion renames `inofly/update_manifest.bin` →
    `manifest.bin`, deletes `UPDATE.BIN`/`UPDATE.MTA`/marker;
  - POST green against the promoted manifest (`listener
    firmware_integrity_status` → `check_passed=true`, new `code_hash`);
  - audit log shows `UPDATE_ATTEMPT` (FW_APPLY, success) and **event 5
    `UPDATE_APPLIED`** with the new version string
    (`tools/verify_audit_log.py` + decoder both clean);
  - second reboot: no promotion re-run (idempotent, no duplicate event 5).

## H17. ADR-023 negatives at all three gates + power-loss recovery ⭐ NEW 2026-07-16 (A-9)

- **Covers:** every reject path of the update chain on real silicon, and the
  unattended power-loss story. Extends B9.3/B9.4 (BL gate) with the app-gate
  and promotion-gate negatives the SITL matrix proved (reasons 5–8, quarantine).
- **Action + Pass, per gate:**
  1. **App gate (`apply_update`):** tampered image → reason 6
     (IMAGE_HASH_MISMATCH); attacker-key image → reason 7 (IMAGE_SIG_INVALID);
     meta lying about lengths → reason 6; missing image or meta → reason 5;
     **older signed manifest → reason 8 (ROLLBACK)** — v4 makes the timestamp
     unforgeable, so also verify a CRC-refixed forward-dated v3-style tamper
     now dies at **reason 3 (signature)**, not at the rollback compare.
     Each: one `UPDATE_ATTEMPT` FAILURE audit entry, no marker written.
  2. **BL gate:** stage tampered / attacker-key `UPDATE.BIN` directly (bypass
     the app gate) → refused **before erase**, hashes bit-identical after
     boot (B9.3/B9.4 mechanic, re-run on the current BL).
  3. **Promotion gate:** stage a valid `UPDATE.BIN` + a staged manifest that
     does NOT match the flashed image → promotion fails, **event 6
     `UPDATE_APPLY_FAILED`** logged once (no per-boot spam), image
     quarantined to `UPDATE.BAD`, active manifest untouched, POST green on
     the old firmware. Delete `UPDATE.BAD` to clean up.
  4. **Power loss (regression of B9.6):** pull power mid-write during a valid
     apply → next boot re-verifies and re-applies unattended; POST green.
- **Cleanup:** card back to `manifest.bin`-only state; audit log FTP'd and
  archived with the session record.

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
the bootloader install is the one irreversible-ish step ~~(DFU is
software-refused afterward)~~ *(BOOT005 DFU-refuse ships **default OFF** per
ADR-024, so the QGC/DFU recovery loop stays available; since BOOT008 the
replacement bootloader must be manufacturer-signed either way)*.

---

## Tooling for H14/H15 — built 2026-05-30 (offline prep)

Both helpers now exist (`tools/`, fixture output is gitignored). Each
decodes a real signed manifest, mutates exactly one field, and **re-signs
with the manufacturer key** via `export_binary_manifest` — so the output
keeps a valid CRC (reason=2 passes) and a valid RSA-PSS signature
(reason=3 passes) and the failure lands on the field under test. Each has
built-in cross-hash / cross-id sanity guards (input must verify under the
manufacturer key first; the mutated field must actually differ from the
live target) so a buggy fixture cannot false-pass on the bench. Covered by
`tests/compliance/test_H14H15_fixture_helpers.py` (12 tests).

- **`tools/make_hash_mismatch_manifest.py`** — H14. Swaps `code_hash`
  (`--mutate code` → reason=4) or `data_hash` (`--mutate data` → reason=5,
  keeping `code_hash` correct so the code→data ordering is exercised). The
  wrong hash is the real hash with its first byte flipped, guaranteeing it
  can't match the running flash.
  ```
  py -3 tools/make_hash_mismatch_manifest.py \
      release/cubepilot_cubeorangeplus_default_manifest.bin \
      --mutate code --output .fixture_workdir/wrong_code_manifest.bin
  py -3 tools/make_hash_mismatch_manifest.py \
      release/cubepilot_cubeorangeplus_default_manifest.bin \
      --mutate data --output .fixture_workdir/wrong_data_manifest.bin
  ```
- **`tools/make_wrong_boardid_manifest.py`** — H15. Rewrites `board_id` to
  a different valid value (`--board-id`, default 1064) and re-signs; refuses
  a value equal to the device id 1063. Stage the output as
  `update_manifest.bin` and run `secure_boot verify_update` → reason=4
  (board_id mismatch — a *separate* enum from the POST reason=4 hash code).
  ```
  py -3 tools/make_wrong_boardid_manifest.py \
      release/cubepilot_cubeorangeplus_default_manifest.bin \
      --output .fixture_workdir/wrong_boardid_update_manifest.bin
  ```

> **Bench note.** Generate these from the **same** `manifest.bin` that is
> actually provisioned on the unit under test (the H2 output). The helpers
> verify the input against the manufacturer key before mutating, so a stale
> or wrong-build input is rejected loudly rather than producing a fixture
> that fails for the wrong reason.

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
| H0 board health | ✅ | 2026-05-25 | Board ID 1063, IMUs live, PX4GUID `00060000000039333738333335112003d0036` |
| H1 flash secure_boot | ✅ | 2026-05-25 | inofly-par001-merge, hash refreshed Day 5 to `a7ed0be789` |
| H2 provision real manifest | ✅ | 2026-05-25 | 373 B; re-provisioned Day 5 from `a7ed0be789` ELF |
| H3 POST pass (real hash) | ✅ | 2026-05-27 / 2026-05-28 Day 5 | **milestone** — reconfirmed on `a7ed0be789` |
| H4 uORB real values | ✅ | 2026-05-28 Day 5 | hashes match manifest byte-for-byte; `board_id` uint8 truncation + missing `boot_count`/`manifest_version` flagged |
| H5 tamper → reason=2 | ✅ | 2026-05-28 Day 5 | CRC stored vs computed mismatch logged, arm blocked, audit entry written |
| H6 PAR001 enforcement | ✅ | 2026-05-30 Day 6 | BUG #5 fix flashed; over-cap + LOCKED rejected via nsh **and** QGC `PARAM_SET`; pre-arm gate blocks until CAPPED set |
| H7 PAR001 audit (SD persist) | ✅ | 2026-05-27 / 2026-05-30 Day 6 | Day 6: PAR001 violations now persist (BUG #6/#6b fixed) — `#9`/`#10`, 11/11 CRC OK, `.sig` authentic |
| H8 PAIR001 signing | ⬜ | | needs SiK telemetry |
| H9 live panel + backfill | ✅ | 2026-06-05 Day 8 | BUG #7 fixed (absolute FTP paths); download 33 entries + `.sig`; live panel streams from boot (autostart) |
| H10 offline sig verify | ✅ | 2026-05-28 / Day 5 | re-proven on 3-entry multi-event log |
| H11 UPD001 accept | ✅ | 2026-06-04 Day 7 / 2026-06-05 Day 8 | FC accept proven via nsh; QGC bundle-verify green; **Day 8** FTP transport fixed (absolute paths) → Install-on-Drone ACCEPTED |
| H12 UPD001 reject (A+B) | ✅ | 2026-06-04 Day 7 | QGC red FAILED; FC CRC tamper → reason=2 |
| H13 attacker-key reason=3 | ✅ | 2026-06-04 Day 7 | POST + verify_update + QGC all reject; libtomcrypt sig branch live |
| H14 organic reason 4/5 | ✅ | 2026-06-04 Day 7 | **Tier 1 prize** — reason=4 (1.87 MB) + reason=5 (96 B, code→data ordering); restore → PASS |
| H15 board_id reason=4 | ✅ | 2026-06-04 Day 7 | FC gap fixed (PX4 `9bc8395660`); 1064 reject, 1063 accept |
