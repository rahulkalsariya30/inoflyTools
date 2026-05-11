# Drone Security Compliance Plan
# DGCA UAS Type Certification — Level 1 (Firmware Manufacturer)

Last updated: 2026-05-04

> **🟡 PARTIALLY AMENDED — 2026-05-04 (architecture pivot).** The
> Phase 5b plan was originally OTP-pubkey + RDP Level 2 burn
> (BOOT002 / BOOT003). Those two requirements are **retired** because
> the CubeOrange+ carriers we ship have no externally accessible BOOT0
> button — OTP write and RDP burn require BOOT0 + SWD access during
> factory provisioning, which is operationally infeasible without
> breaking Hex's factory seal. They are replaced by an ArduPilot-style
> bootstrap-trust chain plus tamper-evident sealing. See
> [Docs/ARCHITECTURE.md §12 ADR-013/014/015](Docs/ARCHITECTURE.md) for
> the architectural decisions and rationale.
>
> **Convention used in this document:** retired material is rendered
> in `~~strikethrough~~` immediately followed by a ✅ **CURRENT** block
> describing what we are actually doing. This preserves traceability —
> a reviewer can see what was retired, what replaced it, and why. The
> same convention is used in `Docs/ARCHITECTURE.md`.

---

## Role

We are the **firmware manufacturer**. We sign firmware, store checksums, and
enforce integrity at boot. We are NOT the Certification Body (CB).

---

## Architecture — Single Keypair

Based on the the audited reference-audited compliance documents (the audited reference/the audited reference):

| Component | Key | Purpose |
|-----------|-----|---------|
| Manufacturer (build machine) | **Private key** | Signs firmware, manifests, update bundles; decrypts log .sig files |
| Flight Controller (firmware) | **Public key** | Verifies signatures at runtime; encrypts log file hashes (LOG001) |

- Only ONE keypair (RSA-2048 — amended 2026-05-06, ADR-016; was RSA-3072 originally) for the entire system
- Private key NEVER leaves the manufacturer's build environment (HSM / offline)
- Public key embedded in firmware as C header (`manufacturer_pubkey.h`) — used by app firmware
- RSA enables both signing (firmware) AND encryption (log hashes) with one keypair

~~**Hardware root of trust (CubeOrange+ / STM32H7) — Phase 5 target:**~~
- ~~Full public key (~422 bytes DER) written to STM32 OTP (write-once, hardware-locked)~~
- ~~Bootloader reads public key **from OTP** on every boot — no key embedded in bootloader code~~
- ~~RDP Level 2 (irreversible) blocks DFU writes, SWD/JTAG, and external flash read~~
- ~~Together, OTP + RDP make the root of trust immutable post-factory~~
- ~~See BOOT001 / BOOT002 / BOOT003 below~~

⚠️ **AMENDED 2026-05-04 (ADR-013).** The OTP + RDP plan is retired —
the CubeOrange+ carriers we use have no accessible BOOT0, making OTP
write / RDP burn operationally infeasible without breaking the Hex
factory seal.

✅ **CURRENT — Bootstrap-trust + tamper-evident sealing (CubeOrange+ / STM32H7), Phase 5b target:**
- RSA-2048 manufacturer pubkey is **embedded in the bootloader binary**
  (and continues to be embedded in the app fw for UPD001 / manifest
  verification). Single source of truth: `pki/manufacturer/public/manufacturer_public.pem`.
- Bootloader integrity is provided by:
  1. **Bootstrap-trust:** the only path that writes sector 0 is
     `bl_update`, initiated from a *running, manufacturer-signed* app
     fw whose ROMFS contains the signed bootloader image (BOOT006).
  2. **Software DFU-refuse:** the secure bootloader refuses to enter
     DFU mode (BOOT005), so an attacker with USB cannot route around
     `bl_update`.
  3. **Tamper-evident sealing:** airframe + Cube enclosure are sealed
     with serialized seals before shipping (BOOT007); reaching SWD/JTAG
     to bypass `bl_update` requires visibly breaking the seal.
- See BOOT001 / BOOT005 / BOOT006 / BOOT007 below. (BOOT002 and BOOT003
  retained as struck-through historical entries for traceability.)

---

## Requirement IDs

| ID     | Requirement                              | DGCA Clause       | Status        |
|--------|------------------------------------------|-------------------|---------------|
| ROT001 | Manufacturer RSA-2048 keypair            | RoT (Mfr)         | ✅ Done        |
| ROT002 | Public key embedded in firmware           | RoT (Mfr)         | ✅ Done        |
| CHK001 | SHA-256 checksums (code + data separate)  | Checksum           | ✅ Done        |
| SIG001 | Manifest signed with manufacturer key     | Signing            | ✅ Done        |
| PKG001 | Signed firmware update bundle             | Secure Update      | ✅ Done        |
| PRV001 | Binary manifest provisioned to drone      | Provisioning       | ✅ Done        |
| POST001| Power On Self Test — CRC + RSA-PSS verify  | POST               | ✅ Done        |
| POST002| POST — verify actual code hash (NuttX)    | POST               | ✅ Code done (hw test pending) |
| POST003| POST — verify actual data hash (NuttX)    | POST               | ✅ Code done (hw test pending) |
| POST004| POST — verify board ID matches hardware   | POST               | ✅ Code done (hw test pending) |
| ARM001 | Arming blocked if POST failed             | Arming Gate        | ✅ Done        |
| PAR001 | Compliance parameter protection (static ceiling + cap-semantics, ADR-019) | Param Protection   | ⏳ Cap-semantics rewrite pending; static-compilation chain unchanged |
| LOG001 | Per-file RSA signed audit log              | Audit Logging      | ✅ Done (SITL)  |
| UPD001 | Drone rejects unsigned firmware update    | Secure Update      | ✅ Done        |
| PAIR001| GCS-FC pairing (MAVLink signing)          | GCS Locking        | ✅ Done (SITL)  |
| BOOT001| Verifying bootloader — checks firmware signature on boot and pre-flash. ⚠️ **AMENDED 2026-05-04 (ADR-013):** bootloader integrity is now provided by bootstrap-trust (BOOT006) + software DFU-refuse (BOOT005) + tamper-evident seal (BOOT007), not by RDP L2. The verifying-bootloader check itself (BOOT001) is unchanged and still load-bearing. | Secure Boot | ⏳ Planned |
| ~~BOOT002~~ | ~~Manufacturer public key in STM32 OTP (hardware-locked)~~ ⚠️ **RETIRED 2026-05-04 (ADR-013).** ✅ **CURRENT:** pubkey is embedded in the bootloader binary; OTP is not used. | ~~Root of Trust~~ | 🚫 Retired |
| ~~BOOT003~~ | ~~RDP Level 2 burn — chip-level DFU/debug lockdown~~ ⚠️ **RETIRED 2026-05-04 (ADR-013).** ✅ **CURRENT:** Path A is closed by software DFU-refuse (BOOT005); SWD/JTAG access is gated by tamper-evident sealing (BOOT007). | ~~Tamper Resist~~ | 🚫 Retired |
| BOOT004| Flash encryption (AES) — productization / Level 2/3 only         | Confidentiality | ⏳ Deferred (ADR-004) |
| BOOT005| Software DFU-refuse in the secure bootloader (closes Path A)     | Secure Boot     | ⏳ Planned (Phase 5b) |
| BOOT006| `bl_update` / ROMFS-bundled secure bootloader (install path; bootstrap-trust root) | Secure Boot | ⏳ Planned (Phase 5b) |
| BOOT007| Tamper-evident sealing + STM32 96-bit UID + seal-serial tracking (compensating control for the physical-attacker class) | Tamper Resist | ⏳ Planned (Phase 5b) |

---

## Requirement Details

### POST002 — Verify actual code hash (NuttX)
Hash the firmware .text section at runtime using linker symbols `_stext/_etext`
(flash start/end addresses) and compare against `manifest.code_hash`.
The .text section includes code AND .rodata (read-only data, including
compiled compliance parameter values from PAR001).
- **Implementation:** `FirmwareIntegrityChecker::_verify_code_hash()` — libtomcrypt SHA-256
- **Pipeline:** `--elf` option hashes the FLASH range `[_stext .. _compliance_params_start)` (ADR-018; supersedes `--code-bin`, kept with deprecation warning)
- **SITL:** Stubbed (returns true) — no flash to hash in simulation
- **Status:** Code complete, pending first hardware build and test

### POST003 — Verify actual data hash (NuttX)
Hash the initialized data section's flash copy at `_eronly` (size = `_edata - _sdata`)
and compare against `manifest.data_hash`. This is the .data section stored in flash
that gets copied to RAM at boot — NOT the SD card parameter file (which changes
legitimately during calibration). Security-critical parameters are statically compiled
into .rodata (covered by POST002's code hash).
- **Implementation:** `FirmwareIntegrityChecker::_verify_data_hash()` — libtomcrypt SHA-256
- **Pipeline:** `--elf` option hashes the FLASH range `[_compliance_params_start .. _compliance_params_end)` (ADR-018; supersedes `--data-bin`, kept with deprecation warning)
- **SITL:** Stubbed (returns true)
- **Status:** Code complete, pending first hardware build and test

### POST004 — Verify board ID matches hardware
Compare `manifest.board_id` against `SECURE_BOOT_BOARD_ID` (compile-time define
read from `firmware.prototype` by CMake). For CubeOrange+: 1063.
- **Implementation:** `FirmwareIntegrityChecker::_verify_board_id()` — simple uint16 compare
- **Board-agnostic:** CMake reads board_id from any board's `firmware.prototype`
- **SITL:** Stubbed (returns true) — `SECURE_BOOT_BOARD_ID` not defined in SITL builds
- **Status:** Code complete, pending first hardware build and test

### PAR001 — Compliance parameter protection (static ceiling + cap-semantics)

> **Enforcement model amended 2026-05-11 (ADR-019).** Earlier wording
> in this section described "zero-window protection" — `param_set`
> blocked entirely for compliance-protected params. That model has
> been replaced by **cap-semantics**: the compiled value is now a
> *ceiling*, not a frozen value. The set of protected parameters and
> the static-compilation mechanism (the ceiling lives in the
> `.compliance_params` flash table covered by `data_hash`) are
> unchanged. See ADR-019 in `Docs/ARCHITECTURE.md §12` for the full
> rationale.

Safety-critical compliance parameters have a **registered ceiling**
statically compiled into the firmware binary. The ceiling cannot be
changed at runtime from any GCS; the operator may set any value
**at-or-below** the ceiling for the current flight, but values are
not persisted across reboots.

**Protected parameters** (from audited docs, Section 3.1b):
- Max Altitude AGL → `GF_MAX_VER_DIST`
- Max Speed → `MPC_XY_VEL_MAX`
- Fence Range → `GF_MAX_HOR_DIST`
- Frame Type → `SYS_AUTOSTART`
- Frame Configuration → `CA_AIRFRAME`
- MAVLink Signing Mode → `MAV_SIGN_CFG` (PAIR001)
- Additional client-specific parameters (table is extensible)

**Approach — cap-semantics at the parameter library level:**
A single table in `compliance_params.h` lists every parameter to
protect (name, description, type, **ceiling value**). Enforcement
runs directly in PX4's parameter system (`src/lib/parameters/`), not
by polling:

- **Boot:** every compliance-protected param is seeded to **0** in
  `user_config[param]` (the RAM-side runtime value). The compiled
  ceiling stays in the `.compliance_params` flash table.
- **`param_set v`** — for a compliance-protected param:
  - if `v ∈ (0, ceiling]`: accepted; `user_config[param] = v`; **no
    audit-log entry** (this is normal operator action).
  - if `v > ceiling`: rejected with
    `MAV_PARAM_ERROR_VALUE_OUT_OF_RANGE` (or PX4 equivalent);
    rejection message **includes the ceiling**: *"cannot set VERT_MAX
    to 50.0 — compliance ceiling is 10.0"*; fires a
    `COMPLIANCE_PARAM_VIOLATION` event into the SecurityAuditLogger
    (LOG001).
- **`param_get`** — returns the RAM-side `user_config[param]` (so
  flight code consumes whatever the operator set for this flight),
  *not* the compiled ceiling.
- **`param_reset_internal` / `param_reset_all_internal`** — for
  compliance params, set `user_config[param] = 0` (was: blocked
  entirely under the prior zero-window model).
- **`param_save_default` / autosave** — **skip** compliance-protected
  params, so operator-set values never persist to flash. Reboot
  always returns the param to 0.
- **Pre-arm hook (Commander)** — **block arming** if any
  compliance-protected param is currently 0; the arming-rejection
  message names the offending param(s).

`ComplianceParamGuard` keeps its audit-only role: registers the
violation callback for over-cap attempts, provides `param_status`
diagnostics. Adding a new protected parameter still requires only
one row in `compliance_params.h` — no code changes.

**Violation logging:** *Only* over-cap `param_set` attempts are
logged (as `COMPLIANCE_PARAM_VIOLATION` via LOG001). Successful
within-cap operator sets are not audit-log events — the audit log
records security events; a within-cap operator action is not one.

**Audit-log vs flight-telemetry-log distinction.** The audit log no
longer captures what *value* the operator chose for a flight; only
that no over-cap attempts happened. The actual altitude / speed /
fence range flown is captured in PX4's flight telemetry log, and
that is the authoritative compliance record at audit time. Two log
streams with different purposes; do not conflate.

**Why static compilation of the ceiling + cap-semantics:** Static
compilation eliminates the need for signature-gated writes to the
ceiling itself — the registered ceiling literally cannot be changed
without re-flashing manufacturer-signed firmware (and any change to
the `.compliance_params` table would shift `data_hash`, failing
POST003 on the next boot). Cap-semantics on top of that gives the
operator the per-flight flexibility real missions need, without
weakening the regulatory ceiling.

### LOG001 — Per-file RSA signed audit log (the audited reference Section 8)
All security events are logged to persistent storage (SD card) as 132-byte
binary entries. Each entry has CRC32 integrity checking. The entire log file
is signed using per-file RSA-2048 encryption.

**Per-file RSA signing (the audited reference Section 8 — implemented):**
1. FC writes 132-byte entries to `audit_log.bin` (signature field zeroed, CRC32 only)
2. After each entry write, FC computes SHA-256 of the complete `audit_log.bin`
3. FC encrypts the 32-byte hash with the embedded RSA-2048 **public key** (PKCS#1 v1.5)
4. Encrypted hash (256 bytes) saved as `audit_log.sig` alongside the log
5. Manufacturer verifies offline: decrypts `.sig` with **private key**, compares SHA-256 hashes
6. GCS downloads both `.bin` log and `.sig` via MAVLink FTP (two buttons in Audit Log panel)

**Why RSA for log signing:** the audited reference Section 8 requires public-key encryption
of the log hash. RSA-2048 supports encryption with the public key (ECDSA
does not). Using the same RSA-2048 keypair for both firmware signing and
log signing keeps the architecture to a single keypair.

**No per-entry signing:** Previous implementation used per-entry ECDSA
signatures with a provisioned private key. This has been replaced by
per-file RSA, which matches the audited the audited reference approach and eliminates the
need for a private key on the FC.

Events logged:
- POST result (pass/fail + reason) on every boot
- Firmware update attempt (version, timestamp, result)
- Arming block (reason, timestamp)
- Parameter change attempt on protected params (PAR001)

### UPD001 — Drone rejects unsigned firmware update
The flight controller verifies the manufacturer signature on a firmware
bundle before accepting a flash operation. Any unsigned or wrongly-signed
firmware is rejected at the drone level (not just at the QGC level).

### PAIR001 — GCS-FC pairing via MAVLink signing (the audited reference Section 3.2.4)
Only authorized GCS software can communicate with the drone. Implemented
using PX4's built-in MAVLink v2 message signing (both PX4 and QGC have
native support).

**Authentication, not strict pairing:** the protocol is shared-secret HMAC.
Any GCS that knows the passphrase can command the drone. The 1:1 drone-to-
operator property depends on operator discipline — each drone must be
provisioned with a unique passphrase that the operator keeps secret.

**How it works:**
1. Operator chooses a unique passphrase per drone. The provisioning tool
   derives the 32-byte signing key as `SHA256(passphrase)` and writes it
   to the drone's SD card (`tools/provisioning/provision_signing_key.py`).
2. Key file is stored at `mavlink/mavlink-signing-key.bin` (40 bytes:
   32-byte key + 8-byte initial timestamp).
3. `MAV_SIGN_CFG=1` is locked by PAR001 — signing required on all non-USB
   connections, cannot be disabled at runtime.
4. Operator opens QGC → Settings → Telemetry → Signing Keys → Add Key,
   enters the SAME passphrase. QGC computes `SHA256(passphrase)` to derive
   the matching key. No raw key bytes ever leave the operator's head.
5. Any GCS that doesn't know the passphrase cannot derive the key, so its
   messages fail HMAC verification on the drone and are silently dropped.

**Why passphrase derivation (and not random key bytes):** QGC's "Add Key"
dialog only accepts a passphrase string. A random-byte flow would force
the operator to copy 64 hex characters between machines, which is both
error-prone and incompatible with the existing QGC UX. Both sides
computing `SHA256(passphrase)` matches QGC's behavior exactly.

**Operator-side record:** the manufacturer records only the SHA256
*fingerprint* of each provisioned drone's key (not the passphrase or raw
key) in `pki/manufacturer/signing_keys/<DRONE_ID>_signing_key.txt`. The
fingerprint lets the provisioning tool warn if the same passphrase is
reused across drone-ids.

**Why MAVLink signing instead of custom 8-byte UID:**
the audited reference describes an 8-byte UID, but MAVLink signing uses a 32-byte key (SHA-256),
which is strictly more secure. The security property is identical: only a GCS
with the matching key can control the drone. Using the existing PX4/QGC signing
infrastructure avoids building a custom authentication protocol.

**USB exemption:** `MAV_SIGN_CFG=1` (non-USB mode) allows USB connections
without signing. This enables manufacturer maintenance access via direct
USB connection, while all wireless/telemetry links require signing.

### BOOT001 — Verifying bootloader (closes Path A / DFU bypass)

**Naming note.** "Signed bootloader" in industry literature usually means a
bootloader whose own signature is verified by something below it — typically
an authenticating Boot ROM in silicon (Apple iPhone, Android with Secure SoC,
STM32MPU, STM32H5 with RSS). The STM32H743/H753 used on CubeOrange+ does
**not** have such a Boot ROM — its system bootloader is a DFU loader, not a
verifier. Our BOOT001 is therefore a **verifying bootloader** (it checks the
firmware's signature) rather than a *signed-and-verified-at-boot* bootloader.

⚠️ **AMENDED 2026-05-04 (ADR-013).** ~~The bootloader's own integrity is
guaranteed not by a runtime cryptographic check, but by RDP Level 2
(BOOT003) physically preventing replacement after factory provisioning.~~
✅ **CURRENT:** the bootloader's own integrity is guaranteed by
**bootstrap-trust + tamper-evident sealing** — sector 0 can only be
written via `bl_update` from a running, manufacturer-signed app fw
(BOOT006), DFU mode is software-refused by the secure bootloader (BOOT005),
and SWD/JTAG access requires breaking the airframe + Cube seal (BOOT007).
The mechanism differs from RDP L2; the end property — "the bootloader on
a deployed unit is the bootloader the manufacturer intended" — is the
same. We additionally sign the bootloader binary at build time so factory
tooling can verify it before programming, but no runtime check on this
signature happens on this chip.

**The gap this closes.** UPD001 protects the MAVLink-FTP secure update path
(Path B). The stock STM32 DFU bootloader (Path A — USB + BOOT button)
flashes anything unsigned because the running firmware is never involved.
With physical USB access, an attacker can today flash arbitrary firmware.

**Mitigation: patch the PX4 bootloader to verify firmware signatures.**
The bootloader becomes the verification authority for both paths:

```
On every boot — split responsibility (ADR-018):

  Bootloader (BOOT001 — signature check only):
    1. Bootloader uses its embedded RSA-2048 manufacturer pubkey
       (compiled into the bootloader binary — ADR-013)
    2. Bootloader hashes app firmware in flash (SHA-256)
    3. Bootloader verifies firmware signature using embedded pubkey
    4. PASS → jump to app firmware
       FAIL → refuse to launch, log to flash, show error indicator

  App firmware (POST002/POST003 — code/data hash check):
    5. App firmware recomputes code_hash and data_hash over the FLASH
       ranges [_stext .. _compliance_params_start) and
       [_compliance_params_start .. _compliance_params_end)
    6. Compares against the signed manifest's code_hash / data_hash
    7. PASS → publish firmware_integrity_status OK; arming allowed
       FAIL → refuse to arm, log violation to audit log

On firmware update (Path B — MAVLink-FTP):
  1. Running firmware receives signed bundle (existing UPD001 flow)
  2. Verifies signature → writes to staging region → reboots
  3. Bootloader sig-verifies new firmware before jumping (BOOT001);
     app firmware then runs the POST002/003 hash check (ADR-018)

On firmware update (Path A — DFU):
  - Production secure bootloader: software-refuses DFU mode entry (BOOT005)
  - Dev builds (no DFU-refuse): firmware lands in flash, but the
    bootloader's BOOT001 signature check fails on next boot → won't run
```

**Implementation:**
- Patch the PX4 bootloader source (separate project from main firmware,
  located in PX4-Autopilot's bootloader fork — confirm path in WSL)
- Embed libtomcrypt RSA-PSS / SHA-256 primitives in bootloader (Path C —
  libtomcrypt is already linked into NuttX; no new dependency on hardware)
- Embed manufacturer RSA-2048 pubkey directly in bootloader binary
  (compiled-in symbol, sourced from `pki/manufacturer/public/manufacturer_public.pem`)
- Hook signature verification into the boot path (firmware-launch decision)
- Sign the bootloader binary at build time using the manufacturer key
  (build-time integrity for factory tooling — no runtime check on
  STM32H743, but forward-compatible with chips that do have an
  authenticating Boot ROM)

**Residual risk (must be documented for auditor):** without external write
protection of sector 0, an attacker who can write sector 0 can replace the
bootloader with one that skips sig-check. The STM32H743 has no Boot ROM
that would catch this at the chip level. ⚠️ **AMENDED 2026-05-04:**
~~BOOT003 closes this gap at the hardware level by disabling DFU writes
entirely.~~ ✅ **The combination of BOOT005 (software DFU-refuse), BOOT006
(bootstrap-trust — `bl_update` is the only path to sector 0, and it
requires a manufacturer-signed app fw), and BOOT007 (tamper-evident seal
on the SWD path) closes this gap operationally without an RDP burn.**
BOOT001 alone is acceptable for dev boards and SITL audit demos;
production units require BOOT005 + BOOT006 + BOOT007.

### ~~BOOT002 — Manufacturer public key in OTP~~ 🚫 RETIRED 2026-05-04 (ADR-013)

> ~~STM32H7 has 1024 bytes of one-time programmable (OTP) memory
> organized as 32 blocks of 32 bytes each. We write the full RSA-3072
> public key (~422 bytes, DER SubjectPublicKeyInfo encoding) to OTP at
> factory provisioning time. Bootloader reads pubkey from OTP at boot.~~
>
> 🚫 **RETIRED 2026-05-04 (ADR-013).** OTP is no longer used for the
> public key. The forcing function is the CubeOrange+ carrier shipped
> by Hex: it has no externally accessible BOOT0 button, so writing OTP
> via the system DFU bootloader would require breaking the Hex factory
> seal. Operationally infeasible in production manufacture. The full
> rationale (alternatives reconsidered, prior-art comparison) is in
> [Docs/ARCHITECTURE.md §12 ADR-013](Docs/ARCHITECTURE.md).

✅ **CURRENT — Manufacturer pubkey embedded in bootloader binary:**
- The RSA-2048 manufacturer pubkey is compiled into the bootloader as
  a constant data symbol (DER SubjectPublicKeyInfo, ~294 bytes), sourced
  from `pki/manufacturer/public/manufacturer_public.pem` at build time.
- The same pubkey continues to be embedded in the app fw (existing
  `firmware/include/manufacturer_pubkey.h` flow) for UPD001 / manifest
  verification.
- An attacker cannot replace the bootloader-embedded pubkey without
  rewriting sector 0, which requires either (a) DFU — refused by
  BOOT005, (b) `bl_update` — requires a manufacturer-signed app fw
  (BOOT006), or (c) SWD — gated by the tamper-evident seal (BOOT007).
- `tools/provisioning/program_otp.py` is **not built** — there is no
  OTP step in the manufacturing flow. (Tool entry preserved as
  struck-through in the directory layout for traceability.)

### ~~BOOT003 — RDP Level 2 burn (production hardware lockdown)~~ 🚫 RETIRED 2026-05-04 (ADR-013)

> ~~RDP Level 2 sets STM32 option bytes such that DFU writes are
> refused, SWD/JTAG is permanently disabled, external flash readout
> returns zeros, and option-byte modifications themselves are blocked.
> Procedure: pre-burn checklist, OTP key programmed and verified, RDP
> L1 rehearsal, then `tools/provisioning/burn_rdp.py --commit ...`.
> Production-only; dev boards stay at RDP 0.~~
>
> 🚫 **RETIRED 2026-05-04 (ADR-013).** RDP burn is no longer part of
> provisioning. The forcing function is identical to BOOT002 — RDP
> burn requires BOOT0 + SWD access during factory provisioning, which
> the Hex carrier does not expose without breaking the factory seal.
> See [Docs/ARCHITECTURE.md §12 ADR-013](Docs/ARCHITECTURE.md) for the
> full rationale and alternatives reconsidered.

✅ **CURRENT — chip-level lockdown replaced by a three-part compensating control:**
- **BOOT005 (software DFU-refuse)** — secure bootloader actively
  refuses DFU mode entry, replacing the chip-level DFU disable that
  RDP L2 would have provided.
- **BOOT006 (bootstrap-trust)** — sector 0 is only writable via
  `bl_update` from a running, signed app fw, replacing the chip-level
  flash-write protection that RDP L2 would have provided.
- **BOOT007 (tamper-evident seal + serial tracking)** — physical
  access to SWD/JTAG (the remaining write path) requires visibly
  breaking the airframe + Cube seal, replacing the chip-level
  SWD-disable that RDP L2 would have provided. Detection is
  procedural (seal inspection on RMA receipt) rather than hardware.
- `tools/provisioning/burn_rdp.py` is **not built**. (Tool entry
  preserved as struck-through in the directory layout for
  traceability.)

### BOOT004 — Flash encryption (deferred — not Level 1) 🛑 Out of scope for DGCA Level 1

Reserved ID for AES-based flash encryption. **Not implemented**, and
not required for Level 1 (DGCA's `Storage Security` clause asks for
authorized-only updates of registered checksums, which our signed
chain delivers — confidentiality is not a Level 1 requirement). May be
added for productization or Level 2/3 parity. See ADR-004 in
[Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md).

### BOOT005 — Secure bootloader software DFU-refuse (closes Path A) ⭐ NEW 2026-05-04 (ADR-014)

**What this closes.** Path A is the stock STM32 DFU bootloader (USB +
BOOT pin). On the H743 there is no chip-level switch to disable DFU
without RDP Level 2, which we cannot burn (BOOT003 retired). Instead,
the **secure (signed) variant of the PX4 bootloader** contains a
software check that **refuses to enter DFU mode**.

**Mechanism (planned, ArduPilot pattern).** A build-time flag
`#define INOFLY_SECURE_BL` guards a compile-time refusal that returns
immediately from the DFU-entry decision point in the PX4 bootloader.
The flag is set in the production bootloader build target and unset
in dev builds.

**Why this works as Path A closure.**
- An attacker with USB access cannot enter DFU because the running
  bootloader refuses the entry condition. The ROM DFU loader is
  never invoked (the user code in sector 0 runs first, since BOOT0
  is not asserted on the production carrier).
- An attacker cannot replace the bootloader with one that does *not*
  refuse DFU, because writing sector 0 requires either DFU (refused)
  or `bl_update` from a manufacturer-signed app fw (BOOT006), or
  SWD/JTAG which is gated by the seal (BOOT007).

**Implementation:**
- Patch the PX4 bootloader (in `~/PX4-Autopilot/platforms/nuttx/...`,
  or wherever the bootloader source lives in the fork — confirm path
  in WSL) at the DFU-entry check.
- Provide both build targets: `cubeorangeplus_bootloader_secure` (with
  `INOFLY_SECURE_BL`) and `cubeorangeplus_bootloader_dev` (without).
- Production manufacturing flashes only the secure variant.

**Reference:** ArduPilot's secure bootloader uses the same pattern —
*"the flight controller will refuse a switch to DFU mode if it is
running a secure bootloader already"* (`Tools/scripts/signing/README.md`).

### BOOT006 — `bl_update` / ROMFS-bundled secure bootloader (install path + bootstrap-trust root) ⭐ NEW 2026-05-04 (ADR-015)

**What this is.** PX4's `bl_update` mechanism — a MAVLink command
(`flashbootloader`) that tells the running app fw to read a bootloader
image out of its own ROMFS and write it to sector 0. We bundle our
**secure bootloader binary** (the BOOT005-enabled build) as a ROMFS
asset inside every signed app fw release.

**Why this is the install path AND the trust root.**

This is both the *only* way to install/update the secure bootloader
(no factory BOOT0 access) and the *only* unprivileged path that can
ever write sector 0:

- **Only install path:** factory-flashing the bootloader requires
  BOOT0 + SWD access, which the Hex carrier does not expose. So the
  first install of the secure bootloader has to come from inside a
  running app fw — `bl_update` is exactly that mechanism.
- **Bootstrap-trust root:** because `bl_update` runs *inside* the app
  fw, and the app fw is signature-verified by the bootloader on every
  boot (BOOT001), only a manufacturer-signed app fw can ever push a
  new bootloader. An attacker without the manufacturer's RSA-2048
  private key cannot get a malicious bootloader past sector 0,
  regardless of physical access (DFU is refused; SWD requires
  breaking the seal).

**Install / update flow** (full procedure: see
`Docs/MANUFACTURING_RUNBOOK.md`):

1. Receive CubeOrange+ from Hex with stock factory bootloader.
2. **Verify factory bootloader hash** against a known-good reference
   (mitigates the "factory bootloader trusts anything" supply-chain
   trust window — checked at our facility, before first install).
3. Flash our **first signed app fw** via QGC firmware-load (the stock
   bootloader will accept it because it is the unsigned-trust window).
4. Trigger MAVLink `flashbootloader`. App fw extracts the secure
   bootloader from its ROMFS and writes it to sector 0.
5. Reboot. Secure bootloader is now active; it verifies the running
   app fw on next boot.
6. Verify by attempting an unsigned-fw load — confirm rejection.
7. Apply tamper-evident seal (BOOT007), record UID + seal serial, ship.

**Implementation:**
- `bl_update` must remain **enabled** in `cubeorangeplus_default.px4board`
  (the 2026-05-03 disable patch is reversed in Step 7 of the
  amendment plan; see project memory).
- Build pipeline: every signed app fw release embeds the matching
  signed secure-bootloader binary as a ROMFS resource. Signer signs
  app fw including ROMFS contents.
- App fw size budget gains the ROMFS-embedded bootloader (~44 KB
  baseline, ~100 KB+ with libtomcrypt RSA-PSS verification). If app
  fw overflows, manage size by stripping unused PX4 modules
  (`fw_*`, `vtol_*`, `rover_*`, `airship_*`, etc. — see project memory
  for the categorized strip list), **not** by disabling `bl_update`.

**Reference:** PX4 `bl_update` is the platform's intended mechanism;
ArduPilot uses the same pattern (`flashbootloader` via Mission Planner
/ QGC / MAVProxy). Hundreds of thousands of fielded ArduPilot units
deploy this way.

### BOOT007 — Tamper-evident sealing + serial tracking (compensating control) ⭐ NEW 2026-05-04 (ADR-013)

**What this is.** The physical-attacker class (someone who
disassembles the airframe and the Cube enclosure to reach SWD/JTAG)
is **out of scope at the cryptographic layer** under the amended
architecture. The compensating control is procedural:

- **Serialized tamper-evident seals** on the airframe joint and on
  the Cube enclosure, applied at our manufacturing facility before
  shipping. Holographic / void-pattern seals; specific vendor TBD
  (see MANUFACTURING_RUNBOOK.md).
- **STM32 96-bit UID + seal serial** recorded in QMS at manufacture.
  The pair forms a per-unit fingerprint that lets us correlate a
  returning unit back to its as-shipped state.
- **RMA inspection workflow.** Any unit returning with a broken seal
  is quarantined and **not re-flown without re-provisioning** (full
  factory reset → secure bootloader re-install → reseal → re-record
  UID + new seal serial).

**Why this is acceptable for DGCA Level 1.** Level 1 is concerned with
*authorized-only updates* of firmware and registered checksums — i.e.,
authenticity / integrity, not confidentiality. Our cryptographic chain
(BOOT001 + UPD001 + BOOT005 + BOOT006) blocks every software path. The
remaining attack surface is a physical attacker with disassembly
capability; for that class, "the seal will visibly show this happened"
is what auditors expect at Level 1, the same standard applied to
physical anti-tamper on production avionics.

**Implementation:**
- Seal procurement (vendor + part number) — TBD; documented in
  `Docs/MANUFACTURING_RUNBOOK.md`.
- QMS / serial-tracking entry per unit:
  `(STM32 96-bit UID, seal serial, manufacture date, signed app fw version)`.
- RMA workflow doc — covered in MANUFACTURING_RUNBOOK.md (or a separate
  RMA SOP if scope grows).

---

## Implementation Phases

### Phase 1 — Manufacturer Toolchain ✅ Complete
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 1.1 | ROT001 | RSA-2048 keypair generation (originally RSA-3072 — re-keyed 2026-05-06, ADR-016) |
| 1.2 | CHK001 | SHA-256 firmware checksum tool |
| 1.3 | SIG001 | Manifest signing tool |
| 1.4 | ROT002 | Public key embed tool (C header) |
| 1.5 | PKG001 | Firmware update bundle packager |

### Phase 2 — Firmware Security Module ✅ Complete
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 2.1 | PRV001 | Binary manifest export + provisioning bridge |
| 2.2 | POST001 | uORB message: firmware_integrity_status |
| 2.3 | POST001 | secure_boot module stub + uORB publication |
| 2.4 | POST001 | FirmwareIntegrityChecker: CRC + RSA-PSS verification |
| 2.5 | POST001 | SITL end-to-end integration test |
| 2.6 | ARM001  | Arming check: block if POST failed |

### Phase 3 — QGC Security Plugin ✅ Complete
| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 3.1 | POST001/ARM001 | Security status panel (live firmware_integrity_status) | ✅ Done |
| 3.2 | PKG001/UPD001  | Secure firmware update UI (upload + verify .fwbundle) | ✅ Done |
| 3.3 | LOG001         | Audit log viewer (real-time feed + full download) | ✅ Done |
| 3.4 | UPD001         | Drone-side firmware update signature rejection | ✅ Done |

### Phase 4 — Parameter Protection ✅ Complete
| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 4.1 | PAR001 | Table-driven compliance_params.h (extensible per client) | ✅ Done |
| 4.2 | PAR001 | Cap-semantics in parameter library: param_set v ≤ ceiling accepted in RAM, > ceiling rejected, boot-at-zero, autosave-skip, pre-arm gate (ADR-019) | ⏳ Pending — code rewrite of `src/lib/parameters/parameters.cpp` + pre-arm hook |
| 4.3 | PAR001 | Audit logging of parameter change violations | ✅ Done |
| 4.4 | PAR001 | Tests + compliance mapping | ⏳ Existing 26 zero-window tests being rewritten as cap-semantics tests (ADR-019) |

### Phase 5 — Hardware Deployment (CubeOrange+) 🔧 In Progress

**Hardware constraint:** 1× CubeOrange+ on hand. ~~Recommend procuring a
2nd unit before BOOT003 — RDP burn is irreversible, and a single board
means the dev unit IS the demo unit. Single-board path is workable but
tight.~~ ⚠️ **AMENDED 2026-05-04 (ADR-013):** with BOOT003 retired,
there is no irreversible step in production manufacture. A single
CubeOrange+ is acceptable for both dev and demo use; the unit can be
re-provisioned (factory reset → secure bootloader re-install → reseal)
without scrap. A second unit is still nice-to-have for parallel work
but is no longer a de-risking requirement.

| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 5.1 | POST002 | Code hash verification from flash [_stext, _etext) via libtomcrypt SHA-256 | ✅ Code done |
| 5.2 | POST003 | Data hash verification from flash [_eronly, _edata-_sdata) via libtomcrypt | ✅ Code done |
| 5.3 | POST004 | Board ID verification (SECURE_BOOT_BOARD_ID from firmware.prototype) | ✅ Code done |
| 5.4 | — | Enable CONFIG_MODULES_SECURE_BOOT + CONFIG_CRYPTO (libtomcrypt) for CubeOrange+ | ✅ Done |
| 5.5 | — | CMakeLists.txt: libtomcrypt include path + board_id compile define from prototype | ✅ Done |
| 5.6 | — | Pipeline: --board-id, --code-bin, --data-bin for hardware section hashing | ✅ Done |
| 5.7 | — | ARM toolchain installation in WSL2 | ⏳ User action |
| 5.8 | — | First hardware build + flash + test (dev bootloader, no DFU-refuse, no seal) | ⏳ Pending toolchain |
| 5.9 | LOG001 | ~~Per-file log signing~~ ✅ Done (SITL) — moved to Phase 3.3 | ✅ Done |

**Phase 5b — Bootloader gap closure (closes Path A / DFU bypass)**

⚠️ **AMENDED 2026-05-04 (ADR-013/014/015).** The original Phase 5b
plan (rows 5b.3, 5b.6, 5b.9–5b.14) revolved around OTP programming
and an irreversible RDP Level 2 burn. Both are retired (BOOT002/003).
The replacement plan is shorter — no irreversible chip step, no extra
hardware procurement to de-risk the burn — and rooted in already-supported
PX4 platform mechanisms (`bl_update`).

~~Original plan (struck for traceability):~~

| ~~Sub-phase~~ | ~~Req ID~~ | ~~Description~~ | ~~Status~~ |
|---|---|---|---|
| ~~5b.1~~ | ~~BOOT001~~ | ~~Locate PX4 bootloader source in WSL; identify flash-write entry points~~ | ~~⏳ Planned~~ |
| ~~5b.2~~ | ~~BOOT001~~ | ~~Add libtomcrypt sig-verify primitives to bootloader build~~ | ~~⏳ Planned~~ |
| ~~5b.3~~ | ~~BOOT002~~ | ~~OTP-read driver in bootloader (HAL-level access to STM32H7 OTP region)~~ | ~~⏳ Planned~~ |
| ~~5b.4~~ | ~~BOOT001~~ | ~~Hook sig-verification into bootloader boot path (POST in bootloader)~~ | ~~⏳ Planned~~ |
| ~~5b.5~~ | ~~BOOT001~~ | ~~Hook sig-verification into bootloader flash-write path~~ | ~~⏳ Planned~~ |
| ~~5b.6~~ | ~~BOOT002~~ | ~~`tools/provisioning/program_otp.py` — DRY_RUN by default, SWD/OpenOCD backend~~ | ~~⏳ Planned~~ |
| ~~5b.7~~ | ~~BOOT001~~ | ~~Validate on dev board (RDP 0): signed firmware boots, unsigned rejected~~ | ~~⏳ Planned~~ |
| ~~5b.8~~ | ~~BOOT001~~ | ~~Validate via DFU attempt (RDP 0): unsigned rejected on next boot~~ | ~~⏳ Planned~~ |
| ~~5b.9~~ | ~~—~~ | ~~Procure 2nd CubeOrange+ if budget permits (de-risks BOOT003 burn)~~ | ~~⏳ User action~~ |
| ~~5b.10~~ | ~~BOOT003~~ | ~~`tools/provisioning/burn_rdp.py` — multi-stage gate, L1 rehearsal first~~ | ~~⏳ Planned~~ |
| ~~5b.11~~ | ~~BOOT003~~ | ~~`Docs/RDP_BURN_RUNBOOK.md` — pre-burn checklist, burn steps, post-burn verify~~ | ~~⏳ Planned~~ |
| ~~5b.12~~ | ~~BOOT003~~ | ~~Rehearse full burn at RDP Level 1 (reversible, recovery-safe)~~ | ~~⏳ Planned~~ |
| ~~5b.13~~ | ~~BOOT003~~ | ~~Production burn at RDP Level 2 on demo unit (irreversible)~~ | ~~⏳ Pre-audit only~~ |
| ~~5b.14~~ | ~~ALL~~ | ~~Auditor demo dry-run on burned unit (DFU fails, SWD blocked, signed boots)~~ | ~~⏳ Pre-audit only~~ |

✅ **CURRENT — Phase 5b under amended architecture (ADR-013/014/015):**

| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 5b.1 | BOOT001 | Locate PX4 bootloader source in WSL; identify firmware-launch decision point | ✅ Done (sector 0 / 128 KB, baseline 43.8 KB — see project memory) |
| 5b.2a | BOOT001 | Path C: extend PX4 crypto enum with `CRYPTO_RSA_PSS` using already-linked libtomcrypt — no new dependency | ✅ Done (Phase 5b.2c — bootloader links at 103.6 KB / 128 KB, 21% headroom) |
| 5b.2b | BOOT001 | Embed manufacturer pubkey as DER constant in bootloader binary (sourced from `pki/manufacturer/public/manufacturer_public.pem` at build time) | ✅ Done (Path C / Phase 5b.2 — see `bootloader_keystore.h` in PX4 fork) |
| 5b.3 | BOOT001 | Hook sig-verification into bootloader boot path (verify app fw before launch) | ⏳ Planned |
| 5b.4 | BOOT001 | TOC-aware off-board signer (`tools/signer/toc_sign.py`) + compliance tests for round-trip sign/verify | ⏳ In-progress (working tree, untracked) |
| 5b.5 | BOOT005 | Software DFU-refuse — `INOFLY_SECURE_BL` build-flag-guarded refusal at the DFU-entry decision point | ⏳ Planned |
| 5b.6 | BOOT006 | Re-enable `bl_update` in `cubeorangeplus_default.px4board` (reverses 2026-05-03 disable) | ⏳ Planned (Step 7 of 2026-05-04 plan) |
| 5b.7 | BOOT006 | Bundle secure bootloader as ROMFS asset in signed app fw; signer covers ROMFS bytes | ⏳ Planned |
| 5b.8 | BOOT006 | Verify app fw fits in flash with ROMFS-embedded bootloader; if overflow, strip unused PX4 modules (categorized list in project memory) — **NOT** by disabling `bl_update` | ⏳ Planned (Step 7/8) |
| 5b.9 | BOOT001 | Validate on dev board (no seal): signed app fw boots; unsigned app fw rejected; bootloader reports the failure | ⏳ Planned |
| 5b.10 | BOOT005 | Validate DFU-refuse on dev board with `INOFLY_SECURE_BL` set: USB DFU enumeration / `dfu-util` flash attempt fails | ⏳ Planned |
| 5b.11 | BOOT006 | Validate `bl_update` round-trip: load app fw v1 → trigger `flashbootloader` → reboot → confirm new bootloader hash; unsigned app fw cannot trigger `bl_update` (rejected by BOOT001) | ⏳ Planned |
| 5b.12 | BOOT007 | Procure tamper-evident seals (vendor + PN) and document the procedure in `Docs/MANUFACTURING_RUNBOOK.md` | ⏳ Planned (deliverable: MANUFACTURING_RUNBOOK.md) |
| 5b.13 | BOOT007 | First-unit production manufacturing dry-run on demo unit: full sequence from receive → seal → ship in QMS, including UID + seal-serial recording | ⏳ Pre-audit only |
| 5b.14 | ALL | Auditor demo dry-run on a sealed unit (DFU rejected, signed app fw boots, signature enforcement verified, seal inspection demonstrated) | ⏳ Pre-audit only |

**Why this plan is shorter than the original.** No OTP programming
step, no irreversible RDP burn, no L1 rehearsal, no second-board
procurement to de-risk a permanent step. The trade is more
operational / procedural rigor (seal management + RMA workflow)
instead of a one-shot hardware step. See
[Docs/ARCHITECTURE.md §12 ADR-013](Docs/ARCHITECTURE.md) for the
full rationale and prior-art comparison (ArduPilot pattern).

### Phase 6 — Compliance Test Suite ✅ Complete
| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 6.1 | POST001 | Unit tests: manifest format, CRC, RSA-PSS, failure reasons (22 tests) | ✅ Done |
| 6.2 | ARM001  | Unit tests: arming gate source verification (5 tests) | ✅ Done |
| 6.3 | UPD001  | Unit tests: bundle rejection, manifest rejection, firmware impl (18 tests) | ✅ Done |
| 6.4 | POST004 | Board ID verification | ⏳ Hardware |
| 6.5 | ALL     | Compliance report generator (JSON + text) — 260 tests, 16 requirements | ✅ Done |

---

## Gap Summary

| Gap | Req ID | Severity | Blocking DGCA submission? |
|-----|--------|----------|--------------------------|
| ~~Code hash not verified at runtime~~ | POST002 | ~~High~~ | ✅ Code done (hw test pending) |
| ~~Data hash not verified at runtime~~ | POST003 | ~~High~~ | ✅ Code done (hw test pending) |
| ~~Board ID not verified at POST~~ | POST004 | ~~Medium~~ | ✅ Code done (hw test pending) |
| ~~No parameter protection~~ | PAR001 | ~~High~~ | ✅ Resolved (SITL) |
| ~~No audit logging on drone~~ | LOG001 | ~~High~~ | ✅ Resolved (SITL) |
| ~~Drone doesn't reject unsigned firmware~~ | UPD001 | ~~High~~ | ✅ Resolved |
| ~~GCS-FC pairing not implemented~~ | PAIR001 | ~~Medium~~ | ✅ Resolved (SITL) |
| Path A: DFU bypasses signature check | BOOT001 + BOOT005 | High | Yes (production cert) — planned Phase 5b |
| ~~No hardware-locked root of trust~~ ⚠️ amended 2026-05-04 — bootstrap-trust replaces OTP | ~~BOOT002~~ → BOOT006 | High | Yes (production cert) — planned Phase 5b |
| ~~DFU/SWD interfaces still open~~ ⚠️ amended 2026-05-04 — software DFU-refuse + seal replace RDP burn | ~~BOOT003~~ → BOOT005 + BOOT007 | High | Yes (production cert) — planned Phase 5b |

---

## Cryptographic Standards

| Usage | Algorithm | Notes |
|-------|-----------|-------|
| Signing key | RSA-2048 | NIST SP 800-57 acceptable through 2030; matches the audited reference reference (amended 2026-05-06, ADR-016 — was RSA-3072) |
| Signature scheme | RSA-PSS (SHA-256, MGF1-SHA256, salt length 32) | Modern provably-secure RSA signature, NIST SP 800-131A. Saltlen=32 is the project-wide convention applied uniformly to every signer (signer.py, toc_sign.py, export_manifest.py) and verifier (device OpenSSL/libtomcrypt, QGC BCrypt). |
| Log signing | RSA-2048 public key encryption | Per-file: FC encrypts log hash with public key (the audited reference Section 8) |
| Hash | SHA-256 | Minimum per DGCA Level 1 |
| Key encoding (storage) | PEM | |
| Key encoding (firmware) | DER SubjectPublicKeyInfo | ~294 bytes for RSA-2048 |
| Signature size | 256 bytes | Fixed (2048 / 8) |
| Corruption detection | CRC32 | For binary manifest and audit entries |
| Crypto library (SITL) | OpenSSL | Available on host OS |
| Crypto library (NuttX — app fw + bootloader) | libtomcrypt | Already linked into PX4; sized for MCU (STM32). Earlier docs said mbedTLS — never accurate; corrected 2026-05-07. |

---

## Directory Layout

```
tools/
  pipeline.py       Full release pipeline (checksum → sign → bundle → export)
  pki/              keygen.py, embed_pubkey.py
  checksum/         checksum.py
  signer/           signer.py             SIG001 — manifest signing (RSA-PSS, base64 JSON bundle)
                    toc_sign.py           BOOT001 — TOC-aware off-board signer for the verifying bootloader (RSA-PSS saltlen=32, matches libtomcrypt)
  bundler/          bundler.py
  provisioning/     export_manifest.py, provision_sitl.py, provision_signing_key.py
                    # ~~program_otp.py        BOOT002 — write pubkey to STM32 OTP (DRY_RUN default)~~ 🚫 RETIRED 2026-05-04 (ADR-013) — OTP not used
                    # ~~burn_rdp.py           BOOT003 — RDP option-byte burn (multi-stage, irreversible)~~ 🚫 RETIRED 2026-05-04 (ADR-013) — no RDP burn
  generate_security_doc.py
  generate_compliance_report.py   Compliance report generator (Phase 6.5)

firmware/
  include/          manufacturer_pubkey.h

pki/
  manufacturer/
    private/        manufacturer_private.pem  ← NEVER COMMIT
    public/         manufacturer_public.pem

tests/
  compliance/       Unit tests (pytest, 260 tests, runs in CI)
    test_ROT001_keygen.py
    test_ROT002_embed_pubkey.py
    test_CHK001_checksum.py
    test_SIG001_signer.py
    test_PKG001_bundler.py
    test_PRV001_export_manifest.py
    test_PIPE_pipeline.py
    test_LOG001_audit_log.py
    test_PAR001_param_protection.py
    test_PAIR001_gcs_pairing.py
    test_POST001_power_on_self_test.py
    test_UPD001_secure_update.py
    test_BOOT001_toc_sign_verify.py    BOOT001 — TOC-aware signer round-trip + tamper tests
  integration/      Integration tests (requires WSL2 + SITL)
    test_sitl_e2e.py

Docs/
  ARCHITECTURE.md                  Canonical architecture reference (LOCKED 2026-04-29; partially amended 2026-05-04)
  Drone_Security_Overview.docx
  THREAT_MODEL.md
  SITL_ACCEPTANCE.md               SITL gate before flashing real hardware
  MANUFACTURING_RUNBOOK.md         BOOT006/007 — receive → first install → bl_update → seal → ship (deliverable)
  # ~~RDP_BURN_RUNBOOK.md             BOOT003 — pre-burn checklist, burn steps, post-burn verify~~ 🚫 RETIRED 2026-05-04 (ADR-013) — no RDP burn
  compliance_report.json          Machine-readable compliance matrix
  compliance_report.txt           Human-readable report for auditor

.github/workflows/
  ci.yml            CI pipeline (tests + secret scan)

inoflyPilot (PX4 fork — WSL2):
  src/modules/secure_boot/
    secure_boot_main.cpp
    FirmwareIntegrityChecker.hpp/.cpp
    FirmwareUpdateGatekeeper.hpp/.cpp
    SecurityAuditLogger.hpp/.cpp
    ComplianceParamGuard.hpp/.cpp
    compliance_params.h
    security_audit_entry.h
    manufacturer_pubkey.h
    security_manifest.h
  src/lib/parameters/
    compliance_check.h/.cpp   (PAR001 cap-semantics enforcement — ADR-019)
  src/modules/mavlink/streams/
    FIRMWARE_INTEGRITY_STATUS.hpp
  src/modules/commander/HealthAndArmingChecks/checks/
    firmwareIntegrityCheck.hpp/.cpp
  msg/
    firmware_integrity_status.msg
    FirmwareUpdateAuthorization.msg
    SecurityAuditEvent.msg

inoflyGCU (QGC fork — D:\Projects\Drone\qgroundcontrol):
  custom/
    src/InoflyPlugin.h/.cpp
    src/FactGroups/SecurityFactGroup.h/.cpp
    src/FirmwarePlugin/InoflyFirmwarePlugin.h/.cpp
    src/FirmwarePlugin/InoflyFirmwarePluginFactory.h/.cpp
    res/qml/SecurityPanel.qml
    res/qml/SecureFirmwareUpdatePage.qml
    res/qml/AuditLogPanel.qml
    res/keys/manufacturer_public.pem
    src/SecureFirmwareController.h/.cpp
    src/AuditLogController.h/.cpp
```
