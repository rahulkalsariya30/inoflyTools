# Drone Security Compliance Plan
# DGCA UAS Type Certification — Level 1 (Firmware Manufacturer)

Last updated: 2026-04-28

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

- Only ONE keypair (RSA-3072) for the entire system
- Private key NEVER leaves the manufacturer's build environment (HSM / offline)
- Public key embedded in firmware as C header (`manufacturer_pubkey.h`) — used by app firmware
- RSA enables both signing (firmware) AND encryption (log hashes) with one keypair

**Hardware root of trust (CubeOrange+ / STM32H7) — Phase 5 target:**
- Full public key (~422 bytes DER) written to STM32 OTP (write-once, hardware-locked)
- Bootloader reads public key **from OTP** on every boot — no key embedded in bootloader code
- RDP Level 2 (irreversible) blocks DFU writes, SWD/JTAG, and external flash read
- Together, OTP + RDP make the root of trust immutable post-factory
- See BOOT001 / BOOT002 / BOOT003 below

---

## Requirement IDs

| ID     | Requirement                              | DGCA Clause       | Status        |
|--------|------------------------------------------|-------------------|---------------|
| ROT001 | Manufacturer RSA-3072 keypair            | RoT (Mfr)         | ✅ Done        |
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
| PAR001 | Compliance parameter protection (static)  | Param Protection   | ✅ Done (SITL)  |
| LOG001 | Per-file RSA signed audit log              | Audit Logging      | ✅ Done (SITL)  |
| UPD001 | Drone rejects unsigned firmware update    | Secure Update      | ✅ Done        |
| PAIR001| GCS-FC pairing (MAVLink signing)          | GCS Locking        | ✅ Done (SITL)  |
| BOOT001| Signed bootloader — verifies firmware sig on boot and pre-flash | Secure Boot   | ⏳ Planned     |
| BOOT002| Manufacturer public key in STM32 OTP (hardware-locked)          | Root of Trust | ⏳ Planned (HW)|
| BOOT003| RDP Level 2 burn — chip-level DFU/debug lockdown                | Tamper Resist | ⏳ Planned (HW)|

---

## Requirement Details

### POST002 — Verify actual code hash (NuttX)
Hash the firmware .text section at runtime using linker symbols `_stext/_etext`
(flash start/end addresses) and compare against `manifest.code_hash`.
The .text section includes code AND .rodata (read-only data, including
compiled compliance parameter values from PAR001).
- **Implementation:** `FirmwareIntegrityChecker::_verify_code_hash()` — mbedTLS SHA-256
- **Pipeline:** `--code-bin` option hashes extracted .text section from ELF
- **SITL:** Stubbed (returns true) — no flash to hash in simulation
- **Status:** Code complete, pending first hardware build and test

### POST003 — Verify actual data hash (NuttX)
Hash the initialized data section's flash copy at `_eronly` (size = `_edata - _sdata`)
and compare against `manifest.data_hash`. This is the .data section stored in flash
that gets copied to RAM at boot — NOT the SD card parameter file (which changes
legitimately during calibration). Security-critical parameters are statically compiled
into .rodata (covered by POST002's code hash).
- **Implementation:** `FirmwareIntegrityChecker::_verify_data_hash()` — mbedTLS SHA-256
- **Pipeline:** `--data-bin` option hashes extracted .data section from ELF
- **SITL:** Stubbed (returns true)
- **Status:** Code complete, pending first hardware build and test

### POST004 — Verify board ID matches hardware
Compare `manifest.board_id` against `SECURE_BOOT_BOARD_ID` (compile-time define
read from `firmware.prototype` by CMake). For CubeOrange+: 1063.
- **Implementation:** `FirmwareIntegrityChecker::_verify_board_id()` — simple uint16 compare
- **Board-agnostic:** CMake reads board_id from any board's `firmware.prototype`
- **SITL:** Stubbed (returns true) — `SECURE_BOOT_BOARD_ID` not defined in SITL builds
- **Status:** Code complete, pending first hardware build and test

### PAR001 — Compliance parameter protection (static compilation)
Safety-critical compliance parameters are **statically compiled** into the
firmware binary. They cannot be changed from any GCS at runtime.

**Protected parameters** (from audited docs, Section 3.1b):
- Max Altitude AGL → `GF_MAX_VER_DIST`
- Max Speed → `MPC_XY_VEL_MAX`
- Fence Range → `GF_MAX_HOR_DIST`
- Frame Type → `SYS_AUTOSTART`
- Frame Configuration → `CA_AIRFRAME`
- MAVLink Signing Mode → `MAV_SIGN_CFG` (PAIR001)
- Additional client-specific parameters (table is extensible)

**Approach — zero-window protection at the parameter library level:**
A single table in `compliance_params.h` lists every parameter to lock
(name, description, type, value). Protection is enforced directly in PX4's
parameter system (`src/lib/parameters/`), not by polling:
- `param_set_internal()` **blocks writes** to protected parameters
- `param_get()` **returns the compiled value** for protected parameters
- `param_reset_internal()` / `param_reset_all_internal()` **skip** protected parameters
- MAVLink `PARAM_SET` handler returns `MAV_PARAM_ERROR_READ_ONLY` to GCS

Protection is active from the very first parameter access (before any
module starts), with zero timing gap. An `AtomicBitset` cache provides
O(1) lookup on the control loop hot path. Adding a new protected parameter
requires only one row in `compliance_params.h` — no code changes.

`ComplianceParamGuard` (audit-only role) registers a violation callback
for logging and provides `param_status` diagnostics.

**Violation logging:** Any blocked write attempt is logged as
`EVENT_PARAM_CHANGE` via the SecurityAuditLogger (LOG001).

**Why static compilation + zero-window:** This is the approach used in the
the audited reference-audited implementation (Section 7). Eliminates the need for
signature-gated parameter writes and provides the strongest protection —
the values literally cannot be changed without re-flashing signed firmware.
No timing gap, no race condition, no bypass via MAVLink/shell/BSON import.

### LOG001 — Per-file RSA signed audit log (the audited reference Section 8)
All security events are logged to persistent storage (SD card) as 132-byte
binary entries. Each entry has CRC32 integrity checking. The entire log file
is signed using per-file RSA-3072 encryption.

**Per-file RSA signing (the audited reference Section 8 — implemented):**
1. FC writes 132-byte entries to `audit_log.bin` (signature field zeroed, CRC32 only)
2. After each entry write, FC computes SHA-256 of the complete `audit_log.bin`
3. FC encrypts the 32-byte hash with the embedded RSA-3072 **public key** (PKCS#1 v1.5)
4. Encrypted hash (384 bytes) saved as `audit_log.sig` alongside the log
5. Manufacturer verifies offline: decrypts `.sig` with **private key**, compares SHA-256 hashes
6. GCS downloads both `.bin` log and `.sig` via MAVLink FTP (two buttons in Audit Log panel)

**Why RSA for log signing:** the audited reference Section 8 requires public-key encryption
of the log hash. RSA-3072 supports encryption with the public key (ECDSA
does not). Using the same RSA-3072 keypair for both firmware signing and
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

### BOOT001 — Signed bootloader (closes Path A / DFU bypass)

**The gap this closes.** UPD001 protects the MAVLink-FTP secure update path
(Path B). The stock STM32 DFU bootloader (Path A — USB + BOOT button)
flashes anything unsigned because the running firmware is never involved.
With physical USB access, an attacker can today flash arbitrary firmware.

**Mitigation: patch the PX4 bootloader to verify firmware signatures.**
The bootloader becomes the verification authority for both paths:

```
On every boot (POST):
  1. Bootloader reads manufacturer public key from OTP (BOOT002)
  2. Bootloader hashes app firmware in flash (SHA-256)
  3. Bootloader verifies firmware signature using OTP pubkey
  4. PASS → jump to app firmware
     FAIL → refuse to launch, log to flash, show error indicator

On firmware update (Path B — MAVLink-FTP):
  1. Running firmware receives signed bundle (existing UPD001 flow)
  2. Verifies signature → writes to staging region → reboots
  3. Bootloader runs POST on new firmware before launch

On firmware update (Path A — DFU):
  - With RDP Level 2 (BOOT003): chip refuses DFU writes entirely
  - Without RDP (dev boards): firmware lands in flash, but POST in
    bootloader fails sig-check on next boot → won't run
```

**Implementation:**
- Patch the PX4 bootloader source (separate project from main firmware,
  located in PX4-Autopilot's bootloader fork — confirm path in WSL)
- Embed mbedTLS signature-verification primitives in bootloader
- Add OTP-read driver to bootloader (BOOT002 dependency)
- Hook signature verification into both boot path and flash-write path

**Residual risk (must be documented for auditor):** without RDP Level 2,
an attacker can DFU-flash a *malicious bootloader* that skips sig-check.
BOOT003 closes this at the hardware level. BOOT001 alone is acceptable
for dev boards and SITL audit demos; production units require BOOT003.

### BOOT002 — Manufacturer public key in OTP

**Where the trust anchor lives.** STM32H7 has 1024 bytes of one-time
programmable (OTP) memory organized as 32 blocks of 32 bytes each. We
write the full RSA-3072 public key (~422 bytes, DER SubjectPublicKeyInfo
encoding) to OTP at factory provisioning time.

**Why full key, not just hash:**
- We have OTP capacity to spare (~600 bytes free after the key)
- Full key in OTP means the bootloader needs **no embedded key** in its
  flash code — the bootloader is generic logic, key is locked data
- Stronger against bootloader-replacement attacks: an attacker who
  flashes a malicious bootloader cannot change the OTP key, so they
  cannot forge a working signature

**Private key is NEVER on the device.** It stays in the manufacturer's
HSM / offline secure storage. Compromise of any device yields only the
public key, which is useless for forging signatures.

**Implementation:**
- Factory provisioning script: `tools/provisioning/program_otp.py`
- Reads `pki/manufacturer/public/manufacturer_public.pem`
- Converts to DER SubjectPublicKeyInfo
- Programs OTP blocks via SWD using OpenOCD or ST-Link tool
- DRY_RUN=1 by default; explicit `--commit` flag to actually write
- Verifies OTP contents after write (read-back)

**OTP is permanent.** Each block, once written, cannot be erased. Mistakes
waste OTP slots but do not brick the chip (32 blocks available; we use
~14 for the key, leaving plenty of headroom for retries and per-device
secrets later).

### BOOT003 — RDP Level 2 burn (production hardware lockdown)

**What this closes.** RDP Level 2 sets STM32 option bytes such that:
- DFU bootloader refuses writes entirely
- SWD/JTAG debug interface permanently disabled
- External read of flash returns zeros
- Boot from RAM / system memory disabled (only user flash boots)
- Option byte modifications themselves are blocked (cannot return to L1/L0)

This is the hardware control that makes Path A truly impossible. Without
it, BOOT001 is necessary but not sufficient.

**Irreversibility — this is the most dangerous step in the project.**
Once RDP Level 2 is burned: no debugger can ever attach, no DFU recovery
possible, the chip behaves as user-flash-only forever. A mistake (wrong
firmware, wrong key in OTP, broken bootloader) bricks the unit
permanently. Scrap-rate must be assumed > 0.

**Procedure (runbook-driven, manual execution only):**
- See `Docs/RDP_BURN_RUNBOOK.md` (Phase 5 deliverable)
- Pre-burn checklist: bootloader flashed and verified, OTP key programmed
  and verified, signed firmware boots cleanly, DFU rejection rehearsed at
  RDP Level 1 first
- Burn step is `tools/provisioning/burn_rdp.py --commit --confirm-yes-i-understand-this-is-permanent`
- Post-burn verification: signed firmware still boots, unsigned firmware
  rejected, DFU returns errors, SWD does not enumerate

**Production-only.** Dev boards stay at RDP Level 0 to keep iteration cheap.
RDP Level 1 (reversible — regression to L0 erases flash but recovers the
board) is used as a rehearsal step before committing to L2.

---

## Implementation Phases

### Phase 1 — Manufacturer Toolchain ✅ Complete
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 1.1 | ROT001 | RSA-3072 keypair generation |
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
| 4.2 | PAR001 | Zero-window protection in parameter library (param_set/get/reset blocked) | ✅ Done |
| 4.3 | PAR001 | Audit logging of parameter change violations | ✅ Done |
| 4.4 | PAR001 | Tests (26 passing) + compliance mapping | ✅ Done |

### Phase 5 — Hardware Deployment (CubeOrange+) 🔧 In Progress

**Hardware constraint:** 1× CubeOrange+ on hand. Recommend procuring a 2nd
unit before BOOT003 — RDP burn is irreversible, and a single board means
the dev unit IS the demo unit. Single-board path is workable but tight.

| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 5.1 | POST002 | Code hash verification from flash [_stext, _etext) via mbedTLS SHA-256 | ✅ Code done |
| 5.2 | POST003 | Data hash verification from flash [_eronly, _edata-_sdata) via mbedTLS | ✅ Code done |
| 5.3 | POST004 | Board ID verification (SECURE_BOOT_BOARD_ID from firmware.prototype) | ✅ Code done |
| 5.4 | — | Enable CONFIG_MODULES_SECURE_BOOT + CONFIG_CRYPTO_MBEDTLS for CubeOrange+ | ✅ Done |
| 5.5 | — | CMakeLists.txt: mbedTLS include path + board_id compile define from prototype | ✅ Done |
| 5.6 | — | Pipeline: --board-id, --code-bin, --data-bin for hardware section hashing | ✅ Done |
| 5.7 | — | ARM toolchain installation in WSL2 | ⏳ User action |
| 5.8 | — | First hardware build + flash + test (RDP Level 0, dev mode) | ⏳ Pending toolchain |
| 5.9 | LOG001 | ~~Per-file log signing~~ ✅ Done (SITL) — moved to Phase 3.3 | ✅ Done |

**Phase 5b — Bootloader gap closure (closes Path A / DFU bypass)**

| Sub-phase | Req ID | Description | Status |
|-----------|--------|-------------|--------|
| 5b.1 | BOOT001 | Locate PX4 bootloader source in WSL; identify flash-write entry points | ⏳ Planned |
| 5b.2 | BOOT001 | Add mbedTLS sig-verify primitives to bootloader build | ⏳ Planned |
| 5b.3 | BOOT002 | OTP-read driver in bootloader (HAL-level access to STM32H7 OTP region) | ⏳ Planned |
| 5b.4 | BOOT001 | Hook sig-verification into bootloader boot path (POST in bootloader) | ⏳ Planned |
| 5b.5 | BOOT001 | Hook sig-verification into bootloader flash-write path | ⏳ Planned |
| 5b.6 | BOOT002 | `tools/provisioning/program_otp.py` — DRY_RUN by default, SWD/OpenOCD backend | ⏳ Planned |
| 5b.7 | BOOT001 | Validate on dev board (RDP 0): signed firmware boots, unsigned rejected | ⏳ Planned |
| 5b.8 | BOOT001 | Validate via DFU attempt (RDP 0): unsigned rejected on next boot | ⏳ Planned |
| 5b.9 | — | Procure 2nd CubeOrange+ if budget permits (de-risks BOOT003 burn) | ⏳ User action |
| 5b.10 | BOOT003 | `tools/provisioning/burn_rdp.py` — multi-stage gate, L1 rehearsal first | ⏳ Planned |
| 5b.11 | BOOT003 | `Docs/RDP_BURN_RUNBOOK.md` — pre-burn checklist, burn steps, post-burn verify | ⏳ Planned |
| 5b.12 | BOOT003 | Rehearse full burn at RDP Level 1 (reversible, recovery-safe) | ⏳ Planned |
| 5b.13 | BOOT003 | Production burn at RDP Level 2 on demo unit (irreversible) | ⏳ Pre-audit only |
| 5b.14 | ALL | Auditor demo dry-run on burned unit (DFU fails, SWD blocked, signed boots) | ⏳ Pre-audit only |

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
| Path A: DFU bypasses signature check | BOOT001 | High | Yes (production cert) — planned Phase 5b |
| No hardware-locked root of trust | BOOT002 | High | Yes (production cert) — planned Phase 5b |
| DFU/SWD interfaces still open | BOOT003 | High | Yes (production cert) — planned pre-audit |

---

## Cryptographic Standards

| Usage | Algorithm | Notes |
|-------|-----------|-------|
| Signing key | RSA-3072 | NIST SP 800-57, 128-bit security, recommended beyond 2030 |
| Signature scheme | RSA-PSS (SHA-256, MGF1-SHA256) | Modern provably-secure RSA signature, NIST SP 800-131A |
| Log signing | RSA-3072 public key encryption | Per-file: FC encrypts log hash with public key (the audited reference Section 8) |
| Hash | SHA-256 | Minimum per DGCA Level 1 |
| Key encoding (storage) | PEM | |
| Key encoding (firmware) | DER SubjectPublicKeyInfo | ~422 bytes for RSA-3072 |
| Signature size | 384 bytes | Fixed (3072 / 8) |
| Corruption detection | CRC32 | For binary manifest and audit entries |
| Crypto library (SITL) | OpenSSL | Available on host OS |
| Crypto library (hardware) | mbedTLS | Lightweight, designed for MCU (STM32) |

---

## Directory Layout

```
tools/
  pipeline.py       Full release pipeline (checksum → sign → bundle → export)
  pki/              keygen.py, embed_pubkey.py
  checksum/         checksum.py
  signer/           signer.py
  bundler/          bundler.py
  provisioning/     export_manifest.py, provision_sitl.py, provision_signing_key.py
                    program_otp.py        BOOT002 — write pubkey to STM32 OTP (DRY_RUN default)
                    burn_rdp.py           BOOT003 — RDP option-byte burn (multi-stage, irreversible)
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
  integration/      Integration tests (requires WSL2 + SITL)
    test_sitl_e2e.py

Docs/
  Drone_Security_Overview.docx
  THREAT_MODEL.md
  RDP_BURN_RUNBOOK.md             BOOT003 — pre-burn checklist, burn steps, post-burn verify
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
    compliance_check.h/.cpp   (PAR001 zero-window enforcement)
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
