# Threat Model — Inofly UAS Firmware Security

**Document version:** 1.0  
**Date:** 2026-04-02  
**Scope:** DGCA Level 1 Type Certification — Firmware Manufacturer  
**Framework:** Adapted from STRIDE for embedded UAS systems

---

## 1. System Overview

The system consists of three trust zones:

| Zone | Components | Trust Level |
|------|-----------|-------------|
| **Manufacturer build environment** | Build machine, signing keys (TPM/HSM), release pipeline | Fully trusted |
| **Flight module (drone)** | PX4 firmware, NuttX RTOS, flash storage, device TPM | Trusted after POST |
| **Ground control station (GCS)** | QGroundControl + Inofly plugin, MAVLink radio link | Partially trusted |

Data flows between zones:

```
Manufacturer ──[.fwbundle]──> GCS ──[MAVLink]──> Flight Module
                                   <──[telemetry]──
```

---

## 2. Assets to Protect

| Asset | CIA Priority | Why |
|-------|-------------|-----|
| Firmware binary (code part) | Integrity | Tampered firmware = full drone compromise |
| Default parameters (data part) | Integrity | Altered flight limits = safety hazard |
| Manufacturer private key | Confidentiality | Key compromise = ability to sign malicious firmware |
| Device private key (TPM) | Confidentiality | Key compromise = ability to forge audit logs |
| Audit logs | Integrity | Tampered logs = undetectable compliance violations |
| POST result | Integrity | Falsified POST = arming with corrupted firmware |
| MAVLink telemetry | Integrity | Spoofed status = pilot trusts a compromised drone |

---

## 3. Threat Catalog

### T1 — Unauthorized firmware modification

| Field | Value |
|-------|-------|
| **Attack** | Attacker replaces firmware binary on flash storage (physical access or exploited update path) |
| **Impact** | Full drone control — arbitrary code execution on flight controller |
| **Likelihood** | Medium (requires physical access or compromised update channel) |
| **Mitigations** | CHK001 (SHA-256 checksums), SIG001 (RSA-PSS signed manifest), POST001 (boot-time verification), ARM001 (arming blocked on mismatch) |
| **Residual risk** | Low — attacker must also forge the manufacturer's RSA-3072 signature |

### T2 — Manifest tampering

| Field | Value |
|-------|-------|
| **Attack** | Attacker modifies checksums in the manifest to match their tampered firmware |
| **Impact** | POST passes with malicious firmware |
| **Likelihood** | Medium |
| **Mitigations** | SIG001 (manifest is signed — changing any field invalidates the signature), POST001 (RSA-PSS verification at every boot) |
| **Residual risk** | Low — requires manufacturer private key to re-sign |

### T3 — Manufacturer key compromise

| Field | Value |
|-------|-------|
| **Attack** | Attacker obtains the manufacturer RSA-3072 private key |
| **Impact** | Critical — can sign arbitrary firmware that passes all verification |
| **Likelihood** | Low (key stored in TPM/HSM in production; file-based only during development) |
| **Mitigations** | ROT001 (key generated in TPM/HSM for production), Phase 4.1 (hardware-bound key), key never transmitted over network |
| **Residual risk** | Medium during development (file-based key), Low in production (hardware-bound) |

### T4 — Unsigned firmware update accepted

| Field | Value |
|-------|-------|
| **Attack** | Attacker pushes a firmware update that bypasses signature verification |
| **Impact** | Malicious firmware installed on drone |
| **Likelihood** | Medium (if update path exists without verification) |
| **Mitigations** | UPD001 (drone-side rejection of unsigned updates), PKG001 (.fwbundle includes signature), QGC plugin verifies before flashing |
| **Residual risk** | Currently HIGH — UPD001 not yet implemented |

### T5 — Audit log tampering

| Field | Value |
|-------|-------|
| **Attack** | Attacker modifies or deletes audit logs on SD card to hide a security event |
| **Impact** | Compliance violation undetectable; post-incident forensics compromised |
| **Likelihood** | Medium (physical SD card access is straightforward) |
| **Mitigations** | LOG001 (each entry signed with device TPM key — cannot forge without hardware), DEV001 (device key bound to TPM — never extractable) |
| **Residual risk** | Currently HIGH — LOG001 and DEV001 not yet implemented |

### T6 — Parameter tampering

| Field | Value |
|-------|-------|
| **Attack** | Attacker modifies safety-critical parameters (max altitude, geofence, speed limits) |
| **Impact** | Drone operates outside certified flight envelope — safety hazard |
| **Likelihood** | Medium (GCS parameter write is unprotected by default) |
| **Mitigations** | PAR001 (signature-gated writes to protected parameters) |
| **Residual risk** | Currently HIGH — PAR001 not yet implemented |

### T7 — MAVLink telemetry spoofing

| Field | Value |
|-------|-------|
| **Attack** | Attacker injects false firmware_integrity_status messages to make pilot believe drone is secure |
| **Impact** | Pilot arms and flies a drone with failed POST |
| **Likelihood** | Low (requires radio proximity and MAVLink knowledge) |
| **Mitigations** | ARM001 (arming gate is on the flight controller itself, not GCS — cannot be spoofed via MAVLink), Phase 7 (MAVLink 2 message signing — deferred) |
| **Residual risk** | Low — arming decision is made on-drone, GCS display is informational only |

### T8 — Flash storage corruption

| Field | Value |
|-------|-------|
| **Attack** | Non-malicious: flash bit-rot, power loss during write, radiation effects |
| **Impact** | Manifest unreadable or corrupted — POST fails, drone won't arm |
| **Likelihood** | Low but non-zero over fleet lifetime |
| **Mitigations** | CRC32 in binary manifest (detects corruption before RSA-PSS check), POST001 reports specific failure reason (MANIFEST_CORRUPTED vs SIGNATURE_INVALID) |
| **Residual risk** | Acceptable — drone fails safe (won't arm), operator re-provisions |

### T9 — Board ID mismatch (wrong firmware on wrong hardware)

| Field | Value |
|-------|-------|
| **Attack** | Operator accidentally flashes OrangeCube firmware onto a Pixhawk (or vice versa) |
| **Impact** | Unpredictable behavior — wrong peripheral drivers, wrong sensor calibrations |
| **Likelihood** | Medium (human error during fleet management) |
| **Mitigations** | POST004 (board ID in manifest compared against hardware ID at boot) |
| **Residual risk** | Currently MEDIUM — POST004 not yet implemented |

---

## 4. Risk Summary

| Threat | Current Risk | After Full Implementation |
|--------|-------------|--------------------------|
| T1 — Firmware modification | **Low** | Low |
| T2 — Manifest tampering | **Low** | Low |
| T3 — Key compromise | **Medium** (dev) | Low (with TPM) |
| T4 — Unsigned update | **High** | Low |
| T5 — Audit log tampering | **High** | Low |
| T6 — Parameter tampering | **High** | Low |
| T7 — Telemetry spoofing | **Low** | Low |
| T8 — Flash corruption | **Low** | Low |
| T9 — Board ID mismatch | **Medium** | Low |

---

## 5. Mapping to DGCA Requirements

| Threat | Mitigating Requirement(s) | DGCA Clause |
|--------|--------------------------|-------------|
| T1 | CHK001, SIG001, POST001, ARM001 | Checksum, Signing, POST, Arming |
| T2 | SIG001, POST001 | Signing, POST |
| T3 | ROT001, DEV001 | Root of Trust |
| T4 | UPD001, PKG001 | Secure Update |
| T5 | LOG001, DEV001 | Audit Logging, Root of Trust |
| T6 | PAR001 | Parameter Protection |
| T7 | ARM001 | Arming Gate |
| T8 | POST001 (CRC32) | POST |
| T9 | POST004 | POST |

---

## 6. Assumptions and Boundaries

**In scope:**
- Firmware integrity from build to boot
- Manufacturer signing and drone-side verification
- GCS display of security status

**Out of scope (for Level 1):**
- GCS-to-drone authentication (Phase 7 — deferred)
- Network-based attacks on telemetry (covered by MAVLink 2 signing in future)
- Physical anti-tamper (hardware enclosure design)
- Supply chain security of hardware components
- Denial of service (radio jamming)

**Assumptions:**
- Manufacturer build environment is physically secured
- TPM hardware (when deployed) correctly implements key isolation
- PX4 NuttX kernel is not compromised (trusted computing base)
- SD card is accessible to an attacker with physical access to the drone
