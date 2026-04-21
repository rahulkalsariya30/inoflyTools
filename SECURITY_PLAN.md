# Drone Security Compliance Plan
# DGCA UAS Type Certification — Level 1 (Firmware Manufacturer)

Last updated: 2026-04-20

---

## Role

We are the **firmware manufacturer**. We sign firmware, store checksums, and
enforce integrity at boot. We are NOT the Certification Body (CB).

---

## Architecture — Single Keypair

Based on the the audited reference-audited compliance documents (the audited reference/the audited reference):

| Component | Key | Purpose |
|-----------|-----|---------|
| Manufacturer (build machine) | **Private key** | Signs firmware, manifests, update bundles at release time |
| Flight Controller (firmware) | **Public key** | Verifies firmware signature, manifest, updates at runtime |

- Only ONE keypair (ECDSA P-256) for the entire system
- Private key NEVER leaves the manufacturer's build environment
- Public key embedded in firmware as C header (`manufacturer_pubkey.h`)
- On hardware: public key stored in CRP-protected flash (Code Read Protection)

---

## Requirement IDs

| ID     | Requirement                              | DGCA Clause       | Status        |
|--------|------------------------------------------|-------------------|---------------|
| ROT001 | Manufacturer ECDSA P-256 keypair         | RoT (Mfr)         | ✅ Done        |
| ROT002 | Public key embedded in firmware           | RoT (Mfr)         | ✅ Done        |
| CHK001 | SHA-256 checksums (code + data separate)  | Checksum           | ✅ Done        |
| SIG001 | Manifest signed with manufacturer key     | Signing            | ✅ Done        |
| PKG001 | Signed firmware update bundle             | Secure Update      | ✅ Done        |
| PRV001 | Binary manifest provisioned to drone      | Provisioning       | ✅ Done        |
| POST001| Power On Self Test — CRC + ECDSA verify   | POST               | ✅ Done        |
| POST002| POST — verify actual code hash (NuttX)    | POST               | ⚠️ Hardware     |
| POST003| POST — verify actual data hash (NuttX)    | POST               | ⚠️ Hardware     |
| POST004| POST — verify board ID matches hardware   | POST               | ⚠️ Hardware     |
| ARM001 | Arming blocked if POST failed             | Arming Gate        | ✅ Done        |
| PAR001 | Compliance parameter protection (static)  | Param Protection   | ✅ Done (SITL)  |
| LOG001 | Signed audit log of security events       | Audit Logging      | ✅ Done (SITL)  |
| UPD001 | Drone rejects unsigned firmware update    | Secure Update      | ✅ Done        |

---

## Requirement Details

### POST002 — Verify actual code hash (NuttX)
Hash the firmware binary at runtime using linker symbols `_stext/_etext`
(flash start/end addresses) and compare against `manifest.code_hash`.
- **Blocked by:** Requires `BOARD_CRYPTO=y` Kconfig + mbedTLS on NuttX
- **SITL:** Stubbed (returns true) — not meaningful in simulation
- **Target:** OrangeCube / Pixhawk hardware

### POST003 — Verify actual data hash (NuttX)
Hash the parameter storage area and compare against `manifest.data_hash`.
- **Blocked by:** Need to determine PX4 parameter storage address on target hardware
- **SITL:** Stubbed (returns true)
- **Target:** OrangeCube / Pixhawk hardware

### POST004 — Verify board ID matches hardware
Read the actual board ID from hardware (BOARD_ID compile-time constant or
runtime detection) and compare against `manifest.board_id`.
- **Effort:** Small — board ID is available at compile time via `CONFIG_BOARD_ID`
- **Target:** Both SITL and NuttX

### PAR001 — Compliance parameter protection (static compilation)
Safety-critical compliance parameters are **statically compiled** into the
firmware binary. They cannot be changed from any GCS at runtime.

**Protected parameters** (from audited docs, Section 3.1b):
- Max Altitude AGL → `GF_MAX_VER_DIST`
- Max Speed → `MPC_XY_VEL_MAX`
- Fence Range → `GF_MAX_HOR_DIST`
- Frame Type → `SYS_AUTOSTART`
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

### LOG001 — Signed audit log of security events
All security events are logged to persistent storage (SD card).

**SITL implementation (current):** Per-entry ECDSA P-256 signing using a
provisioned signing key. Each 132-byte entry is individually signed.

**Hardware approach (from audited docs):** Per-file log signing — the drone
encrypts the log file hash with the public key, producing a downloadable
`.sig` file. The manufacturer verifies by decrypting with the private key
and comparing against the SHA-256 of the log file.

Events to log:
- POST result (pass/fail + reason) on every boot
- Firmware update (version, timestamp, result)
- Arming block (reason, timestamp)
- Parameter change attempt on protected params (PAR001)

### UPD001 — Drone rejects unsigned firmware update
The flight controller verifies the manufacturer signature on a firmware
bundle before accepting a flash operation. Any unsigned or wrongly-signed
firmware is rejected at the drone level (not just at the QGC level).

---

## Implementation Phases

### Phase 1 — Manufacturer Toolchain ✅ Complete
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 1.1 | ROT001 | ECDSA P-256 keypair generation |
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
| 2.4 | POST001 | FirmwareIntegrityChecker: CRC + ECDSA verification |
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

### Phase 5 — Hardware Deployment ⏳ Planned
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 5.1 | ROT002 | Public key in CRP-protected flash (Code Read Protection) |
| 5.2 | POST002/003 | Real code + data hash verification on NuttX (mbedTLS) |
| 5.3 | POST004 | Board ID verification on hardware |
| 5.4 | LOG001 | Per-file log signing (aligned with audited approach) |

### Phase 6 — Compliance Test Suite ⏳ Final
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 6.1 | POST001 | Integration test: POST pass/fail scenarios |
| 6.2 | ARM001  | Integration test: arming blocked/cleared |
| 6.3 | POST004 | Implement + test board ID verification |
| 6.4 | POST002/003 | SITL stub tests + NuttX TODO documentation |
| 6.5 | ALL    | Full compliance report generation (DGCA submission) |

---

## Gap Summary

| Gap | Req ID | Severity | Blocking DGCA submission? |
|-----|--------|----------|--------------------------|
| Code hash not verified at runtime | POST002 | High | Yes (hardware only) |
| Data hash not verified at runtime | POST003 | High | Yes (hardware only) |
| Board ID not verified at POST | POST004 | Medium | Possibly |
| ~~No parameter protection~~ | PAR001 | ~~High~~ | ✅ Resolved (SITL) |
| ~~No audit logging on drone~~ | LOG001 | ~~High~~ | ✅ Resolved (SITL) |
| ~~Drone doesn't reject unsigned firmware~~ | UPD001 | ~~High~~ | ✅ Resolved |

---

## Cryptographic Standards

| Usage | Algorithm | Notes |
|-------|-----------|-------|
| Signing key | ECDSA P-256 (secp256r1) | NIST-approved, comparable to RSA-2048 |
| Hash | SHA-256 | Minimum per DGCA Level 1 |
| Key encoding (storage) | PEM | |
| Key encoding (firmware) | DER SubjectPublicKeyInfo | 91 bytes for P-256 |
| Signature encoding | DER (ASN.1) | Max 72 bytes for P-256 |
| Corruption detection | CRC32 | For binary manifest only |
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
  provisioning/     export_manifest.py, provision_sitl.py, provision_audit_key.py
  generate_security_doc.py

firmware/
  include/          manufacturer_pubkey.h

pki/
  manufacturer/
    private/        manufacturer_private.pem  ← NEVER COMMIT
    public/         manufacturer_public.pem

tests/
  compliance/       Unit tests (pytest, runs in CI)
    test_ROT001_keygen.py
    test_ROT002_embed_pubkey.py
    test_CHK001_checksum.py
    test_SIG001_signer.py
    test_PKG001_bundler.py
    test_PRV001_export_manifest.py
    test_PIPE_pipeline.py
    test_LOG001_audit_log.py
    test_PAR001_param_protection.py
  integration/      Integration tests (requires WSL2 + SITL)
    test_sitl_e2e.py

Docs/
  Drone_Security_Overview.docx
  THREAT_MODEL.md

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
