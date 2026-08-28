# Firmware Security Implementation — Summary

| | |
|---|---|
| **Prepared by** | Inofly — Flight Module firmware manufacturer |
| **Flight controller** | CubePilot CubeOrange+ (STM32H743) |
| **Firmware** | PX4-based secured fork (`inoflyPilot`) |
| **Ground station** | QGroundControl secured fork (`inoflyGCU`) |
| **Standard** | DGCA Certification Scheme for UAS, **Section 7.1** — Level 1 (Annexure E) |
| **Status** | All Section 7.1 controls **implemented and validated on production hardware** |

## 1. What the requirement asked for

Section 7.1 requires a firmware manufacturer to prove four things: that the aircraft **will not operate on altered firmware** (7.1 a), that a **firmware update is accepted only when the manufacturer has signed it** (7.1 b), that **compliance-critical flight parameters cannot be changed** outside the manufacturer's authorised process (7.1 c), and that **on-board logs are signed** so tampering is detectable offline. Annexure E additionally requires a root of trust inside the flight module for Level 1.

## 2. What we implemented

The whole design rests on one idea: a **single manufacturer RSA-2048 signing key** is the root of trust. Its private half never leaves our offline signing environment; its public half is compiled into the flight module. The aircraft trusts only what that key has signed — its firmware, its checksums, its updates and its own log — and it holds nothing an attacker could use to forge a signature.

| Requirement | What we built | Status |
|---|---|---|
| **Root of trust** (Annexure E, Level 1) | RSA-2048 manufacturer keypair; public key embedded in both the bootloader and the application firmware. All signing and verification executes on the STM32H743 inside the flight module — no companion computer, no key in transit. | Implemented |
| **7.1 a — Firmware tamper avoidance** | A **verifying secure bootloader** checks the RSA-PSS signature of the application firmware on every power-on and refuses to launch an unsigned or modified image. | Implemented |
| **7.1 a.ii — Registered checksums** | Each release pipeline run emits **separate SHA-256 checksums for the code part and the data part**, packaged in an RSA-signed manifest provisioned onto the flight module. Registered checksums cannot be altered without invalidating the signature. | Implemented |
| **7.1 a.iii — Power-On Self-Test** | POST runs automatically at every boot: manifest CRC → manifest signature → live re-hash of code flash → live re-hash of parameter flash → board-ID check. Every result, pass **and** fail, is written to the security audit log. | Implemented |
| **7.1 a.iv — Effect of a mismatch** | Any mismatch **blocks arming** through the flight-controller health gate, is logged with a distinct failure reason, and is reported in the ground station. The aircraft cannot take off. | Implemented |
| **7.1 b — Secure firmware update** | Signature verification at **three independent layers**: the ground station verifies the bundle before offering to install; the flight module independently re-verifies the manifest and binds it by hash to the staged image; the bootloader re-verifies the image before erasing any flash. Updates are torn-write-safe and survive power loss, carry anti-rollback protection, and every attempt — accepted or rejected — is logged. The bootloader itself can only be replaced by a signed bootloader image. | Implemented |
| **7.1 c — Secure change of flight parameters** | Certified values are **compiled into a protected flash table covered by the data checksum**. Three mission caps (max altitude 120 m, fence range 500 m, max speed 15 m/s) accept operator values only up to the certified ceiling and never persist; three configuration values (airframe model, frame class, MAVLink signing required) are locked to the certified value. Every rejected attempt is audit-logged. Changing a certified value requires a new signed firmware release. | Implemented |
| **Log file signing** | The flight module writes a CRC-protected binary security log to SD and, after every write, seals it with the root of trust. We verify it offline with the private key; any edit is detected. A decoder renders it human-readable. | Implemented |
| **Ground station ↔ aircraft authentication** | MAVLink v2 message signing with a per-drone key provisioned at manufacture. A ground station without the key cannot command the aircraft over a telemetry link. Signing-required is a locked parameter; a direct USB cable connection is exempt by design, so a unit can always be serviced on the bench behind its tamper seal. | Implemented |

## 3. Delivered components

- **Flight-module firmware** — secure bootloader plus a `secure_boot` module providing POST, the arming gate, the update gate, compliance-parameter enforcement and the signed audit logger.
- **Ground station** — secure firmware-update page with client-side signature verification, a security status panel and an audit-log download/inspection panel.
- **Manufacturer tooling (offline)** — key generation, checksum generation, firmware and bootloader signing, release-bundle pipeline, drone provisioning, and offline audit-log verification and decoding.
- **Documentation set** — compliance mapping to every Section 7.1 clause, architecture and threat model, certified build identity sheet, firmware flashing SOP, manufacturing runbook and a witness-ready test runbook.

## 4. Verification performed

- **424 automated compliance tests pass**, mapped requirement-by-requirement (16 requirement IDs, zero failures, zero gaps).
- **Full hardware acceptance on CubeOrange+** — tamper detection, arming block, parameter enforcement, log signing and update rejection all demonstrated on real silicon rather than in simulation.
- **Secure-bootloader bring-up completed on hardware**, including signed bootloader replacement, a signed firmware update applied end to end on the aircraft — verify, flash, activate the new registered checksums at the next boot — and unattended recovery from power loss mid-update.
- Each attack path was exercised and observed to fail closed: tampered bundle, tampered manifest, attacker-signed artefact, modified firmware image, unsigned bootloader, and out-of-range or locked parameter writes.

## 5. Position and next steps

We act solely as the **firmware manufacturer** — we build, sign and checksum the firmware and enforce integrity on the aircraft. The Certification Body remains a separate party: it counter-signs and retains the registered checksums, confirms the production signing-key provenance, and witnesses the live test session, for which a step-by-step runbook is prepared. The remaining work before submission is to regenerate the build identity sheet from the **production** signing key in place of the current bench test key.
