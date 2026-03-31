# Drone Security Compliance Plan
# DGCA UAS Type Certification — Level 1 (Firmware Manufacturer)

Last updated: 2026-03-29

---

## Role

We are the **firmware manufacturer**. We sign firmware, store checksums, and
enforce integrity at boot. We are NOT the Certification Body (CB).

---

## Requirement IDs

| ID     | Requirement                              | DGCA Clause       | Status        |
|--------|------------------------------------------|-------------------|---------------|
| ROT001 | Manufacturer ECDSA P-256 keypair         | RoT               | ✅ Done        |
| ROT002 | Public key embedded in firmware          | RoT               | ✅ Done        |
| CHK001 | SHA-256 checksums (code + data separate) | Checksum          | ✅ Done        |
| SIG001 | Manifest signed with manufacturer key    | Signing           | ✅ Done        |
| PKG001 | Signed firmware update bundle            | Secure Update     | ✅ Done        |
| PRV001 | Binary manifest provisioned to drone     | Provisioning      | ✅ Done        |
| POST001| Power On Self Test — CRC + ECDSA verify  | POST              | ✅ Done        |
| POST002| POST — verify actual code hash (NuttX)   | POST              | ⚠️ TODO        |
| POST003| POST — verify actual data hash (NuttX)   | POST              | ⚠️ TODO        |
| POST004| POST — verify board ID matches hardware  | POST              | ⚠️ TODO        |
| ARM001 | Arming blocked if POST failed            | Arming Gate       | ✅ Done        |
| PAR001 | Compliance parameter protection          | Param Protection  | ❌ Not started |
| LOG001 | Signed audit log of security events      | Audit Logging     | ❌ Not started |
| UPD001 | Drone rejects unsigned firmware update   | Secure Update     | ❌ Not started |

---

## Requirement Details

### POST002 — Verify actual code hash (NuttX)
Hash the firmware binary at runtime using linker symbols `_stext/_etext`
(flash start/end addresses) and compare against `manifest.code_hash`.
- **Blocked by:** Requires `BOARD_CRYPTO=y` Kconfig + libtomcrypt on NuttX
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

### PAR001 — Compliance parameter protection
Safety-critical parameters (max altitude, geofence, speed limits) must only
be changeable with a valid manufacturer signature. Unsigned writes to these
parameters must be rejected.
- **New requirement — not yet designed**
- **Approach:** PX4 parameter callback intercept + signature verification
- **Affected params:** To be defined (COM_ARM_*, GF_MAX_HOR_DIST, etc.)

### LOG001 — Signed audit log of security events
All security events must be logged to persistent storage (SD card) and each
entry must be signed with the manufacturer RoT key.

Events to log:
- POST result (pass/fail + reason) on every boot
- Firmware update (version, timestamp, result)
- Arming block (reason, timestamp)
- Parameter change attempt on protected params (PAR001)

Log format: append-only binary file, each entry signed with ECDSA P-256.

### UPD001 — Drone rejects unsigned firmware update
The flight controller must verify the manufacturer signature on a firmware
bundle before accepting a flash operation. Any unsigned or wrongly-signed
firmware must be rejected at the drone level (not just at the QGC level).

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

### Phase 3 — QGC Secure Firmware Plugin ⏳ Next
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 3.1 | POST001/ARM001 | Security status panel (live firmware_integrity_status) |
| 3.2 | PKG001/UPD001  | Secure firmware update UI (upload + verify .fwbundle) |
| 3.3 | LOG001         | Audit log viewer (real-time feed + full download) |
| 3.4 | UPD001         | Drone-side firmware update signature rejection |

### Phase 4 — Hardware Root of Trust ⏳ Planned
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 4.1 | ROT001 | TPM 2.0 integration (replace software key) |
| 4.2 | POST002/003 | Real code + data hash verification on NuttX hardware |
| 4.3 | LOG001 | Audit log entries signed with TPM key |

### Phase 5 — Parameter Protection ⏳ Planned
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 5.1 | PAR001 | Define protected parameter list |
| 5.2 | PAR001 | PX4 parameter write intercept |
| 5.3 | PAR001 | Signature verification on protected param writes |
| 5.4 | PAR001 | Tests + compliance mapping |

### Phase 6 — Compliance Test Suite ⏳ Final
| Sub-phase | Req ID | Description |
|-----------|--------|-------------|
| 6.1 | POST001 | Integration test: POST pass/fail scenarios |
| 6.2 | ARM001  | Integration test: arming blocked/cleared |
| 6.3 | POST004 | Implement + test board ID verification |
| 6.4 | POST002/003 | SITL stub tests + NuttX TODO documentation |
| 6.5 | ALL    | Full compliance report generation (DGCA submission) |

### Phase 7 — GCS Authentication ⏳ Skipped (future consideration)
| Sub-phase | Description |
|-----------|-------------|
| 7.1 | MAVLink 2 message signing (shared secret) |
| 7.2 | GCS pairing — only paired GCS can control drone |
| 7.3 | Pairing key stored in TPM (requires Phase 4) |

---

## Gap Summary

| Gap | Req ID | Severity | Blocking DGCA submission? |
|-----|--------|----------|--------------------------|
| Code hash not verified at runtime | POST002 | High | Yes |
| Data hash not verified at runtime | POST003 | High | Yes |
| Board ID not verified at POST | POST004 | Medium | Possibly |
| No parameter protection | PAR001 | High | Yes |
| No audit logging on drone | LOG001 | High | Yes |
| Drone doesn't reject unsigned firmware | UPD001 | High | Yes |
| GCS authentication | Phase 7 | Medium | No (Level 1) |

---

## Cryptographic Standards

| Usage | Algorithm | Notes |
|-------|-----------|-------|
| Signing key | ECDSA P-256 (secp256r1) | NIST-approved |
| Hash | SHA-256 | Minimum per DGCA Level 1 |
| Key encoding (storage) | PEM | |
| Key encoding (firmware) | DER SubjectPublicKeyInfo | 91 bytes for P-256 |
| Signature encoding | DER (ASN.1) | Max 72 bytes for P-256 |
| Corruption detection | CRC32 | For binary manifest only |

---

## Directory Layout

```
tools/
  pki/              keygen.py, embed_pubkey.py
  checksum/         checksum.py
  signer/           signer.py
  bundler/          bundler.py
  provisioning/     export_manifest.py, provision_sitl.py

firmware/
  include/          manufacturer_pubkey.h

pki/
  manufacturer/
    private/        manufacturer_private.pem  ← NEVER COMMIT
    public/         manufacturer_public.pem

tests/compliance/
  test_ROT001_keygen.py
  test_ROT002_embed_pubkey.py
  test_CHK001_checksum.py
  test_SIG001_signer.py
  test_PKG001_bundler.py
  test_PRV001_export_manifest.py

inoflyPilot (PX4 fork):
  src/modules/secure_boot/
    secure_boot_main.cpp
    FirmwareIntegrityChecker.hpp/.cpp
    manufacturer_pubkey.h
    security_manifest.h
  src/modules/commander/HealthAndArmingChecks/checks/
    firmwareIntegrityCheck.hpp/.cpp
  msg/
    firmware_integrity_status.msg
```
