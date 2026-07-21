# Firmware Security Architecture — Auditor Overview
## Inofly UAS — DGCA Level 1 (Firmware Manufacturer)

**Purpose.** A self-contained architecture walkthrough for the Certification Body, with the block/flow diagrams called out in the reference documents. For requirement-by-requirement mapping see [COMPLIANCE_7.1_MAPPING.md](COMPLIANCE_7.1_MAPPING.md); for the canonical internal reference (full decision log) see [../ARCHITECTURE.md](../ARCHITECTURE.md).

**Last updated:** 2026-07-10

---

## 1. System components

```
        MANUFACTURER (offline)                 GROUND (operator)              AIRCRAFT (Flight Module)
   ┌───────────────────────────┐        ┌────────────────────────┐     ┌──────────────────────────────┐
   │  RSA-2048 PRIVATE KEY      │        │  inoflyGCU (QGC fork)  │     │  CubeOrange+  (STM32H743 MCU)  │
   │  (HSM / air-gapped)        │        │  - Secure FW Update UI │     │  ┌──────────────────────────┐  │
   │                            │        │  - Security panel      │     │  │ Verifying Bootloader     │  │
   │  Release pipeline:         │        │  - Audit Log panel     │     │  │  (embedded pubkey)       │  │
   │   checksum → sign →        │        │  - MAVLink signing     │     │  └──────────┬───────────────┘  │
   │   bundle → export          │        └───────────┬────────────┘     │             ▼                  │
   │                            │                    │  MAVLink v2       │  ┌──────────────────────────┐  │
   │  Outputs:                  │   signed .fwbundle │  (signed) + FTP   │  │ App firmware             │  │
   │   - signed manifest (.json)│ ───────────────────┼──────────────────┼─▶│  secure_boot module      │  │
   │   - binary manifest (.bin) │                    │                   │  │   - POST (integrity)     │  │
   │   - .fwbundle              │                    │                   │  │   - Update gatekeeper    │  │
   │                            │◀───────────────────┼───────────────────┼──│   - Param guard          │  │
   │  RSA-2048 PUBLIC KEY ──────┼── embedded in ─────┼──────────────────▶│  │   - Audit logger (signed)│  │
   │  (retained for CB)         │   FM binaries      │  audit_log + .sig │  └──────────────────────────┘  │
   └───────────────────────────┘                    │                   │  SD: manifest.bin, audit_log,  │
                                                     │                   │      mavlink signing key       │
                                                     └───────────────────┴────────────────────────────────┘
```

**Roles.** We are the **Firmware Manufacturer**: we hold the signing key, sign firmware and manifests, and enforce integrity on the module. The **Certification Body** is a separate party that witnesses the tests and may counter-sign the registered checksums. The **operator** flashes and flies but cannot alter compliance-critical firmware or parameters.

---

## 2. The single-keypair trust model

One **RSA-2048** keypair is the root of trust for everything (firmware signing, manifest signing, update-bundle signing, and audit-log hash encryption). RSA-2048 is a widely certified choice for this class of flight controller, and a single keypair keeps key management minimal.

| Key | Location | Used for |
|---|---|---|
| **Private** | Manufacturer, offline (never leaves) | Signing firmware images, manifests, update bundles; opening (decrypting) audit-log signatures during verification |
| **Public** | Embedded in bootloader binary **and** application firmware; retained as PEM for the Certification Body | Verifying all signatures on-device; encrypting the audit-log hash |

- **Signature scheme:** RSA-PSS (SHA-256, MGF1-SHA256, salt length 32), applied uniformly by every signer and verifier.
- **Hash:** SHA-256 everywhere (SHA-2, FIPS 180-4). No MD5/SHA-1 anywhere.
- **On-device crypto:** libtomcrypt (already part of NuttX/PX4 — no new dependency). **Host/SITL crypto:** OpenSSL. The two interoperate; a passing POST on real hardware is the proof.

---

## 3. Chain of trust (secure boot)

Each layer is verified by the layer above it; the chain is anchored by (a) cryptography and (b) a tamper-evident physical seal.

```
[Tamper-evident seal: airframe + Cube enclosure]   ← visibly broken on intrusion; RMA workflow
        │                                             (compensating control for physical SWD access)
        ▼
[Bootloader binary in sector 0]                     ← contains the manufacturer PUBLIC key
        │   • sector-0 write only via signed bl_update from a running signed app fw (BOOT006/BOOT008)
        │   • verifies the app-firmware RSA-PSS signature on every boot (BOOT001) — fail-closed
        ▼
[App firmware: SIGNED by manufacturer]              ← bootloader checks this signature before launch
        │   • embeds the manufacturer public key (for manifest + update verification)
        │   • runs POST on every boot
        ▼
[manifest.bin: SIGNED by manufacturer]              ← firmware checks this signature (POST)
        │   • holds registered checksums: code_hash, data_hash, board_id
        │   • POST recomputes code/data hashes from LIVE flash and compares
        ▼
[ARM gate]                                          ← refuses to arm if any check failed → logged
```

**Trust transitivity.** Break the seal and you are visible; without it, sector 0 can only be rewritten by a manufacturer-signed application firmware pushing a manufacturer-signed bootloader — which requires the private key. From the bootloader down, every layer is RSA-PSS-verified against a public key that the layer above has already vouched for. An attacker who cannot produce a manufacturer signature cannot get unauthorized code or checksums to run.

**Terminology note for the auditor.** The STM32H743 has no authenticating Boot ROM (unlike phones or STM32H5/U5). Ours is therefore a **verifying bootloader** — it verifies the *firmware's* signature. The bootloader's own integrity is provided operationally (bootstrap-trust + seal), not by silicon. This is the same posture as the ArduPilot secure-boot pattern and is appropriate for DGCA Level 1, which requires authenticity/integrity of updates, not confidentiality.

---

## 4. Boot sequence — Power On Self-Test (POST)

This is the flow behind the reference documents' "Secure firmware booting procedure" and "POST workflow" figures.

```
      ┌─────────────────────┐
      │   Power on FM        │
      └──────────┬──────────┘
                 ▼
      ┌─────────────────────┐     signature invalid
      │ Bootloader verifies  │───────────────────────▶ refuse to launch (fail-closed), show error
      │ app-fw RSA-PSS sig    │
      │ (embedded pubkey)     │
      └──────────┬──────────┘  valid
                 ▼
      ┌─────────────────────┐
      │ App firmware boots;  │
      │ secure_boot autostart│
      └──────────┬──────────┘
                 ▼
      ┌───────────────────────────────────────────┐
      │  POST — in order, fail-closed at each step: │
      │   1. manifest present         → fail = 1    │
      │   2. manifest CRC32 + format  → fail = 2    │
      │   3. manifest RSA-PSS sig     → fail = 3    │
      │   4. code_hash  (live flash)  → fail = 4    │
      │   5. data_hash  (live flash)  → fail = 5    │
      │   6. board_id match           → fail = 6    │
      └──────────┬───────────────────────┬─────────┘
         all pass│                        │any fail
                 ▼                        ▼
      ┌─────────────────────┐   ┌──────────────────────────────┐
      │ publish integrity    │   │ publish integrity status FAIL │
      │ status = PASS        │   │ log POST_RESULT FAILURE       │
      │ log POST_RESULT PASS │   │ ARM gate blocks arming        │
      │ ARM gate allows arm  │   │ GCS shows failure + reason    │
      └─────────────────────┘   └──────────────────────────────┘
```

- **Registered checksums** live in the signed `manifest.bin` on the SD card; they cannot be altered without the private key (any edit fails CRC or signature).
- **Code vs data** are hashed separately (steps 4 and 5) so parameters/data can be revised in a future signed release independently of code.
- **Both outcomes logged** — PASS and FAIL — to the RSA-signed audit log.

---

## 5. Firmware update paths — both gated

```
   PATH B (normal, operator):  MAVLink-FTP signed .fwbundle via QGC
   ─────────────────────────────────────────────────────────────────
   GCS verifies bundle sig ──▶ Install on Drone ──▶ FM stages update_manifest.bin
        (client-side)              (only if Verified)         │
                                                              ▼
                                       FM verify_update: CRC → RSA-PSS sig → board_id
                                         reject → reason 2/3/4, UPDATE_ATTEMPT FAILURE logged
                                         accept → stage; next boot: bootloader BOOT001 + POST re-check

   PATH A (physical, USB/DFU):  raw image flash
   ─────────────────────────────────────────────────────────────────
   Even if an unsigned image is written, the verifying bootloader (BOOT001)
   refuses to launch it on the next boot; POST is the checksum backstop.
   USB sits behind the tamper-evident seal (BOOT007).

   BOOTLOADER UPDATE:  bl_update
   ─────────────────────────────────────────────────────────────────
   bl_update verifies a manufacturer RSA-PSS signature on the candidate
   bootloader BEFORE erasing sector 0 (BOOT008) — refuses unsigned/tampered.
```

Three independent fail-closed layers protect an update: **Ground Control Station client-side**, **Flight Module update gate**, and **boot-time** (bootloader + POST). The Flight Module never trusts the Ground Control Station's verdict — it re-verifies against its own embedded public key.

---

## 6. Compliance parameter protection

Compliance-critical parameter values are **compiled into the firmware** in a dedicated flash table (`.compliance_params`) that is covered by the registered `data_hash`. They cannot be changed from any Ground Control Station — a change requires a new manufacturer-signed release.

```
   .compliance_params flash table  ──covered by──▶  data_hash  ──in──▶  signed manifest
                                                                              │
   param_set from GCS ─▶ parameter library enforcement:                       ▼
        CAPPED  (ceiling): (0, ceiling] accepted RAM-only, never persisted;   POST verifies
                           > ceiling REJECTED + audit-logged; boot = 0;        data_hash on
                           arming blocked until set                            every boot
        LOCKED  (fixed):   reads registered value; any other write REJECTED
                           + audit-logged; survives power-cycle
```

| Parameter | Kind | Registered | Compliance meaning |
|---|---|---|---|
| `GF_MAX_VER_DIST` | CAPPED | 120 m | Max altitude AGL ceiling |
| `GF_MAX_HOR_DIST` | CAPPED | 500 m | Fence range ceiling |
| `MPC_XY_VEL_MAX` | CAPPED | 15 m/s | Max speed ceiling |
| `SYS_AUTOSTART` | LOCKED | 4001 | Certified airframe model |
| `CA_AIRFRAME` | LOCKED | 0 | Frame configuration |
| `MAV_SIGN_CFG` | LOCKED | 1 | MAVLink signing required |

---

## 7. Audit log signing (additional requirement)

```
   FM writes 316-byte CRC32 entries → audit_log.bin  (POST results, updates, arming blocks, param violations)
                    │
                    ▼  after every write
   SHA-256(audit_log.bin) ── encrypt with EMBEDDED PUBLIC KEY ──▶ audit_log.sig (256 bytes)
                    │
   download via QGC (FTP) or SD ──▶ OFFLINE at manufacturer/CB:
                    │
   decrypt .sig with PRIVATE KEY, compare SHA-256  ──▶  PASS = authentic & untampered
                                                        FAIL = edited/forged
```

Only the manufacturer's private key can open the signature, so the log's **origin** (produced by a Flight Module carrying this root of trust) and **integrity** (no post-hoc edits) are provable offline. Tools: `verify_audit_log.py`, `decode_audit_log.py`.

---

## 8. Hardware platform and validation status

- **Target:** CubePilot CubeOrange+, STM32H743 (2 MB flash, no authenticating Boot ROM, no accessible BOOT0 on the shipped carrier).
- **Bench acceptance (Tier 1, H0–H15):** complete on real hardware — POST on real flash, tamper/arming block, PAR001 against real NVM, signed audit log persisted on SD, update accept/reject, attacker-key and organic hash-mismatch cases. See [../HARDWARE_ACCEPTANCE.md](../HARDWARE_ACCEPTANCE.md).
- **Secure bootloader chain (B1–B9):** complete — BOOT001 positive/negative, signed `bl_update` (BOOT008), staged SD update matrix. See [../BOOTLOADER_BRINGUP.md](../BOOTLOADER_BRINGUP.md).
- **Physical control (BOOT007):** tamper-evident seal + UID/seal-serial tracking; procedure in [../MANUFACTURING_RUNBOOK.md](../MANUFACTURING_RUNBOOK.md).
- **Automated tests:** 358 compliance tests pass (`Docs/compliance_report.txt`).

---

## 9. Design choices and deviations from common industry practice (and why they are equal or stronger)

| Topic | Common industry approach | Our approach | Why acceptable for Level 1 |
|---|---|---|---|
| Root of trust | RSA-2048, keys in Flight Module | RSA-2048, single keypair, public key embedded in bootloader + firmware | Same key strength; keys never in transit |
| Ground Control Station ↔ Flight Module lock | Custom 8-byte UID | MAVLink v2 signing, 32-byte key = `SHA256(passphrase)` | Strictly stronger (HMAC-SHA256 vs 8-byte UID); uses native PX4/QGroundControl infra |
| Bootloader trust | Reliance on the flashing procedure | Verifying bootloader + bootstrap-trust + signed `bl_update` + tamper seal | Cryptographic + operational anchor; no reliance on procedure alone |
| Flash encryption (AES) | Sometimes present | **Deferred** (BOOT004) | Level 1 requires authenticity/integrity of updates, not confidentiality; our signed chain delivers that. Reserved for Level 2/3 / productization |
| Log signing | Per-file RSA, public-key hash encryption | Identical scheme | A well-established, audited-acceptable approach |

Full rationale and decision log: [../ARCHITECTURE.md §10–§12](../ARCHITECTURE.md).
