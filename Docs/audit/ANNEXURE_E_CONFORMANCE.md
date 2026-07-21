# Annexure E Conformance Statement
## Flight Module security level — DGCA Certification Scheme for UAS

**Purpose.** The §7.1 compliance criteria repeatedly reference *"Level 0 or Level 1 compliance as defined in Annexure E"* and *"the communication requirement (if applicable) as defined in Annexure E."* This statement addresses Annexure E point-by-point and records our determination: **Level 1**.

**Last updated:** 2026-07-10

> **Source-text note.** The authoritative definitions are in Annexure E of the DGCA Certification Scheme itself. The requirements addressed below are reproduced from the §7.1 criteria. **The Certification Body is asked to cross-check** each item against the current authoritative Annexure E text.

---

## 1. Security-level determination

| | |
|---|---|
| Flight module architecture | **Single module.** Flight controller and (no) companion computer are one physical module — the CubeOrange+ / STM32H743. There is no second processing element. |
| Determined level | **Level 1** |
| Basis | All secure execution (signature verification, checksum computation, log-hash encryption) occurs inside the flight-module microcontroller. Public-key management is entirely within the flight-module firmware. |

## 2. Point-by-point conformance

### E.1 — Security level (Level 0 / Level 1)

> *Requirement (§7.1 a.i.a):* the flight module shall have Level 0 or Level 1 compliance.

**Conforms — Level 1.** The flight module performs firmware signature verification, POST checksum verification, and audit-log signing on-device. No security-relevant operation is delegated off-module.

### E.2 — Root of trust for Level 1 ("using, for example, TPM or TEE")

> *Requirement (§7.1 a.i.c):* the FM shall have a root-of-trust mechanism implemented (**using, for example, TPM or TEE for Level 1 compliance**) used to sign the data generated inside the FM.

**Conforms — with a hardware nuance for Certification Body confirmation.** Our root of trust is an **RSA-2048 keypair** whose public half is embedded in the verifying bootloader and application firmware, and whose private half is held offline by the manufacturer. All Flight-Module-generated compliance data (the audit log) is bound to this root (the log hash is encrypted with the embedded public key).

- The criteria phrase TPM/TEE as **"for example"** — i.e., illustrative mechanisms, not a mandate. Our mechanism provides the required property (authenticity/integrity of firmware, registered checksums, and logs) via cryptography + a verifying bootloader + tamper-evident sealing.
- **Hardware note (for Certification Body confirmation):** the STM32H743 on CubeOrange+ has **no TrustZone TEE and no on-chip TPM** (and no authenticating Boot ROM). This is a common hardware position for this class of flight controller — Level 1 is realized without a discrete TPM/TEE by managing the key within the flight-controller software and protecting the boot chain by other means. We ask the Certification Body to confirm this interpretation of "for example, TPM or TEE" is acceptable at Level 1 (industry precedent on comparable hardware indicates it is).
- Compensating controls for the absence of a hardware TEE: verifying bootloader (BOOT001), signed `bl_update` (BOOT008), bootstrap-trust (sector 0 writable only from signed app fw), and tamper-evident sealing of the SWD/JTAG path (BOOT007).

### E.3 — Verification key recorded and retained

> *Requirement (§7.1 a.i.d):* the verification key of the root of trust may be recorded and retained (also used to verify the origin of FM logs).

**Conforms.** The RSA-2048 public key is retained at `pki/manufacturer/public/manufacturer_public.pem` (DER SHA-256 fingerprint in [BUILD_IDENTITY.md §5](BUILD_IDENTITY.md)) and is the key used to verify the origin/integrity of Flight-Module-generated logs (`tools/verify_audit_log.py`).

### E.4 — Communication requirement (multi-module / 128-bit symmetric key)

> *Requirement (§7.1 a.i.b / Annexure E):* if the flight module is realized as multiple chips/modules (e.g. flight controller + companion computer), the inter-module communication must be secured using (or equivalent of) **128-bit symmetric key encryption (minimum)**.

**Not applicable — single module.** There is no companion computer and no inter-module security boundary to protect, so the 128-bit inter-module encryption requirement does not apply.

**Beyond the requirement:** the Ground Control Station ↔ Flight Module link (which *is* present) is authenticated with **MAVLink v2 message signing** — a 32-byte key derived as `SHA256(passphrase)`, HMAC-SHA256 per message (PAIR001). This exceeds a 128-bit symmetric requirement in key length and is enforced on all non-USB links (`MAV_SIGN_CFG=1`, a LOCKED compliance parameter).

### E.5 — Key management within the module

> *Requirement (Annexure E, Level 1):* management of the public key needs to be fully within the module; host processes/users must not be able to obtain the private key or inject fraudulent logs.

**Conforms.**
- The **private key is never on the module** — it is held offline by the manufacturer. There is therefore no device-resident private key for a host process or user to extract (a stronger position than a device-resident-key design).
- The **public key** is compiled into the firmware/bootloader (not user-writable without re-flashing signed firmware).
- **Fraudulent-log injection is prevented** by the per-file signing scheme: the log hash is encrypted with the embedded public key and can only be validated/opened with the manufacturer's offline private key, so a forged or edited log is detectable offline (§7 of the mapping).

## 3. Summary

| Annexure E item | Determination |
|---|---|
| Security level | **Level 1** |
| Root of trust | RSA-2048; TPM/TEE read as illustrative — Certification Body to confirm (reference precedent supports) |
| Verification key retained | Yes |
| Communication requirement (128-bit inter-module) | **N.A.** — single module; Ground Control Station link exceeds via MAVLink signing |
| Key management within module | Yes; no device-resident private key |

## 4. Items for Certification Body confirmation

1. Acceptance of a non-TPM/non-TEE root of trust at Level 1 (E.2), consistent with the reference precedent.
2. Confirmation that single-module architecture makes the inter-module communication requirement inapplicable (E.4).
3. Cross-check of every item above against the authoritative Annexure E text.
