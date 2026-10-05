# DGCA §7.1 Audit Package

Auditor-facing documentation and demo setup for the DGCA Certification Scheme **Section 7.1** evaluation (Level 1, Firmware Manufacturer). Start here.

## Documents

**Formal submission set** — merged, in reading order, into `Inofly_Firmware_Security_Compliance_Document.docx`:

| # | Document | For |
|---|---|---|
| — | [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) | Front matter: plain-language overview, compliance-at-a-glance, how to read the document. |
| — | [GLOSSARY.md](GLOSSARY.md) | Front matter: plain-language definitions of every term/acronym/ID. |
| 1 | [CERTIFICATE_OF_COMPLIANCE.md](CERTIFICATE_OF_COMPLIANCE.md) | The signed declaration required by §7.1(a); conformance summary + sign-off + open items for the CB. |
| 2 | [BUILD_IDENTITY.md](BUILD_IDENTITY.md) | Pins the certificate to a specific firmware artifact (version, git hash, code/data hashes, board_id, bootloader, key fingerprint). |
| 3 | [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md) | Core deliverable — every §7.1 clause mapped to how we satisfy it, with evidence pointers. |
| 4 | [ANNEXURE_E_CONFORMANCE.md](ANNEXURE_E_CONFORMANCE.md) | Level-1 determination and point-by-point Annexure E conformance (security level, root of trust, communication requirement). |
| 5 | [TEST_EVIDENCE_PACK.md](TEST_EVIDENCE_PACK.md) | Captured hardware evidence per §7.1 test (console output + screenshot placeholders). |
| 6 | [PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md) | Production procedure: extract the signing key from the CCA certificate and wire it into the pipeline. |

**Supporting / demo**

| # | Document | For |
|---|---|---|
| 7 | [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) | How the system works — components, trust model, boot/update flows, diagrams. Read first to orient. |
| 8 | [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md) | Copy-paste live-demo runbook (steps D0–D9) for the CB witness session. |
| 9 | [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) | What each tool/script does, mapped to requirement and demo step. |
| 10 | [FIRMWARE_FLASHING_SOP.md](FIRMWARE_FLASHING_SOP.md) | CB-facing Firmware Flashing SOP (mirrors the reference SOP structure): keys → OpenSSL → signature → upload → connection diagram → bootloader/firmware flashing → QGC flow → §7.1 testing tables. Hardware-only. Built standalone as `Inofly_Firmware_Flashing_SOP.docx` (`py -3 tools/build_compliance_docx.py flashing`). |

Supporting internal references (not auditor-facing but authoritative): [../ARCHITECTURE.md](../ARCHITECTURE.md) (decision log), [../SECURITY_PLAN.md](../SECURITY_PLAN.md), [../HARDWARE_ACCEPTANCE.md](../HARDWARE_ACCEPTANCE.md) (bench evidence), [../BOOTLOADER_BRINGUP.md](../BOOTLOADER_BRINGUP.md), [../compliance_report.txt](../compliance_report.txt) (test matrix).

## Test setup — verified ready (2026-07-10)

| Artifact | Location | State |
|---|---|---|
| Automated compliance report | `Docs/compliance_report.txt` / `.json` | **358 tests PASS**, overall verdict PASS |
| Signed demo firmware bundle | `test_firmware.fwbundle` | verify=PASS under manufacturer key |
| Tampered demo bundle | `test_firmware_tampered.fwbundle` | verify=FAIL (as intended) |
| Attacker-key fixtures | `.attacker_fixtures/` (gitignored) | manifest + bundle + update-manifest, all FAIL under mfr key |
| Pipeline demo outputs | `release/test_firmware_*` | signed manifest (.json), binary manifest (.bin, 373 B), bundle |
| Real audit log fixture | `release/sd/audit_log.bin` + `.sig` | 11 entries, signature **authentic**, decodes to readable PASS/FAIL POST events |

Regenerate everything before the session — see [AUDIT_DEMO_SCRIPT.md §0](AUDIT_DEMO_SCRIPT.md).

## Verified end-to-end on 2026-07-10

- Release pipeline runs clean (all 3 verification gates pass).
- `test_firmware.fwbundle` verifies **True**; `test_firmware_tampered.fwbundle` and the attacker bundle verify **False** — the accept/reject demo behaves as documented.
- `tools/verify_audit_log.py` on `release/sd/audit_log.bin` → `PASS: audit log signature is authentic`.
- `tools/decode_audit_log.py` renders timestamped PASS and FAIL POST entries.

## Two open decisions before signing (flagged for you / the CB)

1. **Signing-key provenance — DECIDED (2026-07-10): CCA certificate for production.** Verified that the current key is a **self-managed test key** (bare RSA-2048, not a certificate). Production will adopt a **CCA-issued RSA-2048 document-signing certificate**; the extraction + cut-over procedure is in [PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md). **Remaining action:** purchase the CCA cert (RSA-2048, exportable `.PFX`), run the cut-over, and update the key fingerprint in [BUILD_IDENTITY.md](BUILD_IDENTITY.md) before the certificate is signed.
2. **No hardware TEE/TPM.** The STM32H743 has neither; we realize Level 1 in software + verifying bootloader + tamper seal (same position as the reference). Flagged in [ANNEXURE_E_CONFORMANCE.md §E.2](ANNEXURE_E_CONFORMANCE.md) as a CB confirmation item.

## Status snapshot

All §7.1 controls implemented and validated on real CubeOrange+ hardware (Tier-1 acceptance H0–H15, secure-bootloader chain B1–B9). Three POST sub-requirements (POST002/003/004) show `HARDWARE_PENDING` in the automated report only because they have no *host* test — the hash-compute is exercised on real silicon in acceptance H14/H15 (see COMPLIANCE_7.1_MAPPING §8). Open work item: automatic first-boot promotion of a staged update manifest (ADR-023 A-6); the equivalent end state is demonstrable now via the manufacturer provisioning flow.
