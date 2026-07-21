# Certificate of Compliance
## DGCA UAS Type Certification — Certification Scheme Section 7.1 (Level 1)

> **Required by §7.1(a):** *"Manufacturer to produce a certificate of compliance indicating compliance with all conditions mentioned."* This document is that certificate.

---

### Document control

| | |
|---|---|
| Document title | Certificate of Compliance — Firmware Security (DGCA §7.1, Level 1) |
| Manufacturer (Flight Module provider) | Inofly |
| Role | Firmware Manufacturer — signs firmware, stores registered checksums, enforces integrity. **Not** the Certification Body. |
| Product / flight module | CubePilot CubeOrange+ flight controller (STM32H743), PX4-based firmware (inoflyPilot fork) |
| Ground control software | inoflyGCU (QGroundControl fork) |
| Certified build identity | See [BUILD_IDENTITY.md](BUILD_IDENTITY.md) — pins this certificate to a specific firmware artifact (version, git hash, code/data checksums, board_id, public-key fingerprint) |
| Companion evidence | [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md), [TEST_EVIDENCE_PACK.md](TEST_EVIDENCE_PACK.md), [ANNEXURE_E_CONFORMANCE.md](ANNEXURE_E_CONFORMANCE.md), `Docs/compliance_report.txt` |

**Version history**

| Rev | Date | Description | Prepared by | Approved by |
|---|---|---|---|---|
| Draft A | 2026-07-10 | Initial certificate for Certification Body review | _________ | _________ |

**Sign-off**

| | Name | Title | Signature | Date |
|---|---|---|---|---|
| Prepared by | | | | |
| Approved by | | | | |

> ⚠️ **Pre-issue conditions (must be closed before this certificate is signed for a production unit):** (1) the firmware must be signed with the **production** manufacturer key, not the current test key — see the Signing-Key Provenance statement below and [BUILD_IDENTITY.md](BUILD_IDENTITY.md); (2) the Certified Build Identity fields must be filled for the exact production build; (3) items marked "Certification Body to confirm" below must be resolved with the Certification Body.

---

## 1. Declaration

The Manufacturer declares that the flight-module firmware identified in [BUILD_IDENTITY.md](BUILD_IDENTITY.md) has been designed, implemented, and tested to meet the conditions of Section 7.1 of the DGCA Certification Scheme for UAS at **Level 1**, as summarized in the conformance table below and evidenced in the referenced documents.

## 2. Conditions and conformance summary

| §7.1 clause | Condition | Conformance | Evidence |
|---|---|---|---|
| a.i (a) | Flight module Level 0/1 compliance | **Conforms — Level 1.** All secure execution on the flight-module microcontroller; single module (no companion computer). | [ANNEXURE_E_CONFORMANCE.md](ANNEXURE_E_CONFORMANCE.md); mapping §1.1 |
| a.i (b) | Communication requirement (Annexure E) | **Conforms / N.A.** Single module ⇒ no inter-module link. Ground Control Station ↔ Flight Module link authenticated by MAVLink signing (PAIR001). | Annexure E §2; mapping §1.2 |
| a.i (c) | Root of trust used to sign Flight Module data | **Conforms.** RSA-2048 root of trust; audit log bound to it. See Signing-Key Provenance (§3). | mapping §1.3; TEST_EVIDENCE §D1 |
| a.i (d) | Verification key recorded and retained | **Conforms.** Public key retained (`manufacturer_public.pem`); used to verify log origin. | mapping §1.4 |
| a.ii (a) | Registered checksums submitted to Certification Body | **Conforms.** Pipeline emits signed manifest (code + data checksums). | mapping §2.1; BUILD_IDENTITY |
| a.ii (b) | Code and data checksums separate | **Conforms.** Independent SHA-256 over code range and data range. | mapping §2.2 |
| a.ii (c) | Secure Hash Algorithm (SHA2/SHA3) | **Conforms.** SHA-256 throughout; no MD5/SHA-1. | mapping §2.3 |
| a.ii (d) | Registered checksums stored securely, not updatable without manufacturer | **Conforms.** RSA-PSS-signed manifest; only a manufacturer-signed update replaces it. | mapping §2.4; TEST_EVIDENCE §D4/D6 |
| a.ii (e) | Checksums may be Certification Body-signed and retained | **Supported.** Checksums furnished to Certification Body for signing/retention (Certification Body action). | mapping §2.5 |
| a.iii (a) | POST implemented | **Conforms.** POST autostarts every boot. | mapping §3.1; TEST_EVIDENCE §D3 |
| a.iii (b) | POST matches calculated vs registered checksums | **Conforms.** Live code/data hashes compared to signed manifest. | mapping §3.2; TEST_EVIDENCE §D3 |
| a.iii (c) | POST result logged | **Conforms.** PASS and FAIL both logged (signed audit log). | mapping §3.3; TEST_EVIDENCE §D9 |
| a.iii (d) | Mismatch prevents operation and is logged | **Conforms.** Arming blocked on any POST failure; logged with reason code. | mapping §3.4; TEST_EVIDENCE §D4 |
| a.iv | Firmware protection testing (unauthorized change fails / fails POST) | **Conforms.** Demonstrated at 3 layers (Ground Control Station, Flight Module gate, boot). | mapping §4; TEST_EVIDENCE §D4/D6 |
| b (i) | Update permitted only if manufacturer-signed | **Conforms.** Ground Control Station + Flight Module + bootloader all verify signature. | mapping §5.1; TEST_EVIDENCE §D5/D6 |
| b (ii) | UAS verifies authenticity with public key | **Conforms.** libtomcrypt RSA-PSS against embedded public key. | mapping §5.2 |
| b (iii) | Firmware change recorded in logs | **Conforms.** `UPDATE_ATTEMPT` entries (success/fail). | mapping §5.3; TEST_EVIDENCE §D9 |
| b (iv) | Registered checksum updated securely after upgrade | **Conforms (staged); auto-promotion in progress.** New signed manifest replaces old only after signature verify. | mapping §5.4 (status note) |
| b (v) | Updated checksums Certification Body-signed and retained | **Supported (Certification Body action).** | mapping §5.5 |
| c (i) | Parameter update authenticity via manufacturer process | **Conforms.** Compliance params compiled into signed firmware (data_hash). | mapping §6.1; TEST_EVIDENCE §D7 |
| c (ii) | Parameter change recorded in logs | **Conforms.** `COMPLIANCE_PARAM_VIOLATION` entries. | mapping §6.2; TEST_EVIDENCE §D9 |
| c (iii/iv) | Registered checksum updated / Certification Body-signed | **Conforms / Supported.** Same mechanism as b(iv)/b(v). | mapping §6.3 |
| c (v) | SOP parameter update leaves parameter unaffected | **Conforms.** CAPPED/LOCKED enforcement; demonstrated live. | mapping §6.5; TEST_EVIDENCE §D7 |
| c (vi) | Invalid-signature parameter update fails | **Conforms.** Rejected at Ground Control Station/Flight Module/POST. | mapping §6.6; TEST_EVIDENCE §D4/D6 |
| Additional (log file signing) | Log file signing | **Conforms.** Per-file RSA public-key encryption of log hash; offline-verifiable. | mapping §7; TEST_EVIDENCE §D9 |

**Overall:** all Section 7.1 conditions are **met**, subject to the pre-issue conditions above. Automated test suite: 358/358 pass; POST002/003/004 validated on CubeOrange+ hardware (see build/test evidence).

## 3. Signing-Key Provenance statement (read together with the Certification Body)

The root of trust is a **single self-managed RSA-2048 keypair**:

- The public key is embedded in the bootloader and application firmware and is retained for the Certification Body. DER SHA-256 fingerprint of the current (test) key: `f52ab7731ca86ea15aa152b605a87369da236b76ce99e7bd09b381b7af928dd5`.
- The private key is held offline by the Manufacturer and never leaves that environment.
- The signature scheme is RSA-PSS (SHA-256, MGF1-SHA256, salt length 32).

**Signing-key provenance — for Certification Body confirmation.** A common industry approach roots the signing key in a **CCA-issued document-signing certificate** (`.PFX`, purchased from India's Controller of Certifying Authorities). Our current root of trust is instead a **self-managed raw RSA-2048 keypair** — there is no CA/CCA certificate behind it yet. We assess this satisfies the §7.1 "root of trust … used to sign the data generated inside the Flight Module" requirement (the property required is authenticity/integrity of firmware, checksums, and logs, which the RSA-2048 chain provides).

**Production decision (2026-07-10): adopt a CCA certificate for production.** For production units the manufacturer signing key will be adopted from a **CCA-issued document-signing certificate** (RSA-2048), in line with common industry practice. The bench/reference builds documented here use a self-generated test key; the production cut-over procedure — how the key is extracted from the CCA `.PFX` and wired into the (unchanged) RSA-PSS signing pipeline — is documented step-by-step in **[PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md)**. The migration is localized to the two PEM files in `pki/manufacturer/` plus a firmware/bootloader rebuild; it does not change the architecture or the signing scheme.

**Production key condition.** The key currently in the tree is a **test/development key** (its private key is present as an unencrypted PEM on the build machine). Before this certificate is issued for a production unit, the firmware must be re-signed with the **production CCA-derived** manufacturer key per [PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md), and the fingerprint above (and in [BUILD_IDENTITY.md](BUILD_IDENTITY.md)) updated accordingly.

## 4. Physical and operational controls (context)

- **Verifying bootloader (BOOT001)** checks the app-firmware signature on every boot; **signed `bl_update` (BOOT008)** verifies a bootloader image before erasing sector 0.
- **Tamper-evident sealing (BOOT007)** on airframe + Cube enclosure, with STM32 96-bit UID + seal-serial recorded per unit, is the compensating control for physical SWD/JTAG access. Procedure: [../MANUFACTURING_RUNBOOK.md](../MANUFACTURING_RUNBOOK.md).

## 5. Open items for the Certification Body

1. **CCA certificate for production** — production units will be signed with a CCA-issued RSA-2048 document-signing certificate (decided 2026-07-10; procedure in [PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md)). Certification Body to confirm this satisfies the root-of-trust provenance expectation and to receive the retained X.509 certificate chain.
2. **Certification Body counter-signing of registered checksums** — §7.1 a.ii(e)/b(v): Certification Body to sign and retain the checksums we furnish.
3. **Witnessed test session** — §7.1 a.iv requires the firmware-protection test "in presence of Certification Body"; run per [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md).
4. **Auto-promotion of staged update manifest** (§7.1 b.iv) — final implementation item (ADR-023 A-6) in progress; equivalent end state demonstrable via manufacturer provisioning today.
