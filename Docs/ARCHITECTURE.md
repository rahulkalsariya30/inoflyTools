# Inofly UAS Firmware Security — Architecture Reference

**Status:** 🔒 LOCKED — 2026-04-29
**Scope:** DGCA Level 1 Type Certification, firmware manufacturer role
**Target hardware:** CubeOrange+ (STM32H743/H753) initially; future-portable
**Document owner:** Architecture is frozen at this revision. Material
changes require a new entry in the Architecture Decision Log (§12) and
team agreement.

---

## How to read this document

This is the **canonical architecture reference**. It captures the full
"what we built, how it fits together, and why" for the firmware security
chain. Companion docs:

| Doc | Purpose | When to read it |
|---|---|---|
| **This doc** ([ARCHITECTURE.md](ARCHITECTURE.md)) | Architecture, decisions, rationale | You want to understand the system as a whole |
| [SECURITY_PLAN.md](../SECURITY_PLAN.md) | Requirements (CHK001, BOOT001, etc.), phases, implementation status | You want to know what work is done or pending |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE threats, attack tree, defense analysis, glossary | You want to defend against specific attacks |
| [SITL_ACCEPTANCE.md](SITL_ACCEPTANCE.md) | End-to-end functional verification checklist | You're about to deploy to hardware |
| [RDP_BURN_RUNBOOK.md](RDP_BURN_RUNBOOK.md) (Phase 5b deliverable) | Step-by-step RDP Level 2 burn procedure | You're about to burn production hardware |

If a fact in those docs disagrees with this one, **this doc wins** (or
the disagreement is a doc-staleness bug — file an issue).

---

## Table of contents

1. [Architecture lockdown — what's frozen](#1-architecture-lockdown--whats-frozen)
2. [Scope and constraints](#2-scope-and-constraints)
3. [Trust model — keys, holders, mechanisms](#3-trust-model--keys-holders-mechanisms)
4. [Hardware platform — STM32H743/H753 specifics](#4-hardware-platform--stm32h743h753-specifics)
5. [The chain of trust](#5-the-chain-of-trust)
6. [What gets signed, by whom, verified where](#6-what-gets-signed-by-whom-verified-where)
7. [Boot sequence — step by step](#7-boot-sequence--step-by-step)
8. [Firmware update paths](#8-firmware-update-paths)
9. [DGCA requirement mapping](#9-dgca-requirement-mapping)
10. [Why we deviate from the audited reference (flash encryption)](#10-why-we-deviate-from-pdrlcint-flash-encryption)
11. [Comparison to other architectures](#11-comparison-to-other-architectures)
12. [Architecture Decision Log](#12-architecture-decision-log)
13. [Residual risks (acknowledged)](#13-residual-risks-acknowledged)
14. [Future hardware options](#14-future-hardware-options)

---

## 1. Architecture lockdown — what's frozen

As of 2026-04-29, the following decisions are **locked**. Any change
requires a recorded entry in §12 and team agreement.

| # | Locked decision | Rationale source |
|---|---|---|
| L1 | **Single RSA-3072 keypair** for firmware signing, manifest signing, update-bundle signing, audit-log encryption | §3, ADR-001 |
| L2 | **Manufacturer role only** — we sign artifacts; we are not the certifying body | DGCA Level 1 scope |
| L3 | **Target hardware: STM32H743/H753** (CubeOrange+) for initial deployment | §4, hardware on hand |
| L4 | **Trust anchor: RSA-3072 public key in STM32H7 OTP** (full DER pubkey, ~422 bytes) | §3, ADR-002 |
| L5 | **Bootloader is a verifier, not chip-verified** — bootloader's own integrity comes from RDP Level 2, not from runtime signature check (STM32H743 has no authenticating Boot ROM) | §4.2, ADR-003 |
| L6 | **No flash encryption (no AES-in-OTP)** for Level 1 — the audited reference-style confidentiality control is not required by DGCA Level 1 | §10, ADR-004 |
| L7 | **mbedTLS on hardware, OpenSSL on host/SITL** | PROJECT_NOTES.md, ADR-005 |
| L8 | **Audit log: per-file RSA-3072 signing**, public-key encryption of SHA-256 hash | SECURITY_PLAN.md §LOG001, ADR-006 |
| L9 | **Static parameter compilation** for compliance-critical params (zero-window protection) | SECURITY_PLAN.md §PAR001, ADR-007 |
| L10 | **MAVLink signing with `SHA256(passphrase)` key derivation** for GCS-FC pairing | SECURITY_PLAN.md §PAIR001, ADR-008 |
| L11 | **POST in app firmware on SITL; POST in bootloader on hardware** (Phase 5b) | SECURITY_PLAN.md §Phase 5b, ADR-009 |
| L12 | **Two update paths, both gated:** Path A (DFU) closed by BOOT003; Path B (MAVLink-FTP) closed by UPD001 + BOOT001 re-verify | §8, ADR-010 |
| L13 | **RDP Level 2 mandatory for production units** (not for dev boards / SITL audit demos) | §5, ADR-011 |

**What's NOT locked** (still implementation-open):
- Phase 5b code changes (BOOT001–003 patch, OTP driver, factory tooling)
- Whether to procure a 2nd CubeOrange+ before BOOT003 burn (operational, not architectural)
- Future hardware family (STM32H5/U5/MPU) — see §14

---

## 2. Scope and constraints

### 2.1 What we are building

A firmware-security-compliance framework for drone flight controllers
that meets **DGCA Level 1 Type Certification** as a **firmware
manufacturer**.

Components in scope:
- **PX4 firmware** (C/C++, NuttX RTOS) running on the flight controller
- **PX4 bootloader** (Phase 5b — patched to verify firmware signatures)
- **QGroundControl plugin** (Qt/C++) for live status, audit log viewing,
  secure firmware updates
- **Manufacturer tooling** (Python) for signing, packaging, factory
  provisioning, OTP programming, RDP burning, audit-log verification

### 2.2 Roles and trust boundaries

| Role | Who | What they hold |
|---|---|---|
| **Manufacturer (us)** | Inofly engineering | RSA-3072 **private** key (offline, HSM/secure storage). Signs all artifacts. |
| **Flight controller** | The drone hardware | RSA-3072 **public** key (in STM32H7 OTP after factory provisioning) |
| **Ground control station** | QGroundControl + Inofly plugin | MAVLink signing key (per-drone, derived from operator passphrase) |
| **Operator** | Pilot / fleet manager | MAVLink signing passphrase (shared with their drone via factory provisioning) |
| **Certifying body (CB)** | DGCA-appointed third party | (No special key — verifies our signatures using our published public key) |

**We are not the CB.** This boundary is hard. We sign and ship; the CB
inspects and certifies.

### 2.3 What's out of scope (for Level 1)

- GCS-to-drone authentication beyond MAVLink signing (Phase 7 deferred)
- Network-based attacks on telemetry (radio jamming, spoofing)
- Physical anti-tamper (hardware enclosure design)
- Supply chain security of hardware components
- Lab-grade adversaries: chip decap, advanced fault injection
- Confidentiality of firmware bytes (IP protection — see §10)

---

## 3. Trust model — keys, holders, mechanisms

### 3.1 The single-keypair decision

**One RSA-3072 keypair signs and decrypts everything.** Specifically:

| Artifact | Operation | Key used |
|---|---|---|
| Application firmware binary | RSA-PSS sign | private |
| Application firmware binary | RSA-PSS verify | public |
| `manifest.bin` (registered checksums) | RSA-PSS sign | private |
| `manifest.bin` | RSA-PSS verify | public |
| `.fwbundle` update package | RSA-PSS sign | private |
| `.fwbundle` update package | RSA-PSS verify | public |
| Audit log SHA-256 hash | PKCS#1 v1.5 encrypt | public (on FC) |
| Audit log SHA-256 hash | PKCS#1 v1.5 decrypt | private (on manufacturer side) |
| Bootloader binary | RSA-PSS sign (build-time only) | private |

**Why one keypair, not two or three:**
- Fewer keys to manage operationally
- No security gain from splitting (compromise of one key in a multi-key
  scheme is still catastrophic)
- Audit trail simplification: every artifact deployed to a device is
  signed by the same authoritative source
- RSA enables both signing AND public-key encryption with a single
  primitive — clean fit for both firmware authenticity (sign/verify)
  and audit-log confidentiality (FC encrypts hash with public key,
  manufacturer decrypts with private key)

### 3.2 Where keys live

| Key | Location | Protection |
|---|---|---|
| RSA-3072 **private** key | Manufacturer HSM / offline secure storage. **NEVER on any deployed device.** | HSM access controls, key ceremony, physical security |
| RSA-3072 **public** key (deployed) | STM32H7 OTP (write-once silicon fuses) | Hardware-immutable after provisioning |
| RSA-3072 public key (build-time) | `pki/manufacturer/public/manufacturer_public.pem` (in repo) | Public — no secrecy required |
| MAVLink signing key (per-drone) | Derived from operator passphrase as `SHA256(passphrase)` — held in QGC and in FC parameter | Operator chooses passphrase strength; key never transmitted |

**Compromise of any deployed device yields only the public key.** The
public key is, by definition, public — leaking it does not enable
forging signatures.

### 3.3 Why RSA-3072 (not RSA-2048, not ECDSA)

- **RSA-3072 vs RSA-2048:** NIST SP 800-57 recommends 3072+ bits for
  use beyond 2030. the audited reference reference uses RSA-2048; we chose
  stronger. Same RSA-PSS scheme otherwise.
- **RSA vs ECDSA:** RSA supports both signing AND public-key encryption
  with one primitive. ECDSA does not encrypt — it would require an
  additional ECIES or RSA layer for the audit-log encryption use case.
  Single-primitive simplicity won.
- **Performance is acceptable on STM32H7:** mbedTLS RSA-3072 verify on
  H743 @ 480 MHz takes ~50 ms — fine for boot-time POST. Signing is
  not done on-device.

---

## 4. Hardware platform — STM32H743/H753 specifics

### 4.1 What the chip provides

| Feature | STM32H743/H753 | What we use it for |
|---|---|---|
| **Internal flash** | 2 MB (H743) / 2 MB (H753) at `0x08000000` | Bootloader + application firmware + manifest |
| **OTP memory** | 1024 bytes (32 blocks × 32 bytes) at `0x08FFF000` | Manufacturer public key (~422 bytes DER) |
| **Option bytes** | Configuration region (separate from flash) | RDP level, BOOT pin behavior, write-protection |
| **SWD/JTAG** | Standard ARM debug | Dev-time programming and debug |
| **System bootloader (DFU)** | ROM-resident DFU loader | Field firmware update via USB (open in dev, locked in production) |
| **Cryptographic accelerator (CRYP)** | AES, DES (hardware) | Not used today (mbedTLS in software) |
| **TRNG** | Hardware random number generator | Available; not currently used for trust chain |

### 4.2 What the chip does NOT provide (and why this matters)

**STM32H743 has no authenticating Boot ROM.** This is a critical
constraint that shapes our architecture:

- The system bootloader on the H743 is a DFU loader, not a verifier
- When the chip resets, the CPU executes whatever is at the boot
  address (typically `0x08000000`) without any signature check
- There is no chip-level signature verification of the user-flashed
  bootloader on this chip family

**Consequence:** in the chain of trust, the bootloader's integrity is
NOT provided by a runtime signature check. It is provided by RDP
Level 2 (the chip refusing all external flash writes after burn).

This is a different mechanism than Apple iPhone, Android with Secure
SoC, STM32MPU (MPU family with authenticating ROM), or STM32H5 (with
RSS — Root Secure Services). Those platforms have a Boot ROM that
verifies the bootloader's signature on every boot. STM32H743 does not.

The end property — *the bootloader running on a deployed unit is the
bootloader the manufacturer intended* — is the same. The mechanism
differs.

### 4.3 OTP programming model

STM32H7 OTP is **one-time-programmable at the bit level**:
- Each bit can be flipped from 0 to 1 exactly once (a physical fuse blows)
- Bits cannot be flipped back from 1 to 0 (no erase command exists)
- Programming is via the standard flash interface (writes to OTP
  addresses), gated by an unlock sequence

**Implication for security:** an attacker cannot replace our OTP
contents with their own. They can only flip additional bits to 1,
which corrupts our public key. A corrupted key fails signature
verification — fail-closed. The attacker gains nothing.

We use ~14 of the 32 OTP blocks for the public key, leaving ~18
blocks (~576 bytes) free for future per-device data (e.g., per-device
AES key for flash encryption if BOOT004 is added later).

### 4.4 RDP Level 0/1/2 model

| Level | DFU writes | SWD/JTAG | Flash readout | Option-byte changes | Reversible? |
|---|---|---|---|---|---|
| **RDP 0** (factory default) | Allowed | Allowed | Allowed | Allowed | Yes |
| **RDP 1** | Allowed | Limited (no flash read) | Blocked | Allowed | Yes (regression L1→L0 mass-erases flash, then chip is reusable) |
| **RDP 2** | **Blocked** | **Blocked** | **Blocked** | **Blocked** | **NO — permanent.** |

**Production deployment burns RDP Level 2.** Once burned:
- DFU bootloader still runs but rejects all flash writes
- Debug probe cannot enumerate the target
- External flash readout returns zeros
- Option bytes themselves can no longer be changed (the L2 setting is
  itself frozen)

**The RDP burn is the most dangerous step in the deployment process.**
A typo in option-byte values during the L2 burn is permanent — the only
recovery is replacing the physical chip. This is why the
[RDP_BURN_RUNBOOK.md](RDP_BURN_RUNBOOK.md) (Phase 5b deliverable)
mandates an L1 rehearsal before L2 commit.

---

## 5. The chain of trust

### 5.1 The full chain (CubeOrange+ post-Phase 5b)

```
[OTP: manufacturer pubkey]              ← write-once silicon fuses
        │ read by
        ▼
[Bootloader: protected by RDP L2]       ← physically immutable post-burn
        │ contains firmware-verify logic; uses OTP pubkey
        │ verifies firmware signature on every boot
        ▼
[Firmware: SIGNED by manufacturer]      ← bootloader checks the signature
        │ contains manifest-verify logic; uses pubkey embedded in firmware
        │ verifies manifest signature on every boot (POST)
        ▼
[manifest.bin: SIGNED by manufacturer]  ← firmware checks the signature
        │ contains registered checksums (code_hash, data_hash, board_id)
        │ POST recomputes and compares
        ▼
[ARM gate]                              ← refuses to arm if any check failed
```

### 5.2 What protects each layer

| Layer | Protected by | Mechanism |
|---|---|---|
| OTP pubkey | Silicon (write-once fuses) | Hardware-immutable; no erase command; only fail-closed corruption possible |
| Bootloader code | RDP Level 2 (BOOT003) | Chip refuses external flash writes — DFU dead, SWD dead |
| Bootloader trust anchor | OTP separation | Trust anchor lives in OTP, not bootloader code — a copied bootloader cannot substitute its own key |
| Firmware code | Bootloader signature check (BOOT001) | Hashed and RSA-PSS-verified on every boot using OTP pubkey |
| Manifest | Firmware signature check (POST001) | RSA-PSS-verified on every boot using firmware-embedded pubkey (which was itself protected by the firmware sig check) |
| Arming decision | Manifest verification result | `commander` subscribes to `firmware_integrity_status` uORB; ARMING_DENIED if `check_passed=false` |

### 5.3 Trust transitivity

Each layer's trust comes from:
1. **OTP pubkey** ← silicon (root)
2. **Bootloader integrity** ← RDP L2 silicon protection (root)
3. **Firmware integrity** ← bootloader signature check, using #1
4. **Embedded-in-firmware pubkey integrity** ← #3 (embedded pubkey
   can't be modified without breaking firmware signature)
5. **Manifest integrity** ← firmware signature check, using #4
6. **Registered checksum integrity** ← #5

The chain is rooted at two points: silicon (OTP and RDP) protects the
bootstrap (#1, #2); cryptography (RSA-3072 signatures) protects
everything downstream.

### 5.4 Important note on terminology

In industry literature, "signed bootloader" usually means a bootloader
whose own signature is verified by silicon below it (an authenticating
Boot ROM). Apple iPhone, Android with Secure SoC, STM32MPU, and
STM32H5 with RSS all work this way.

**Our STM32H743 does NOT have an authenticating Boot ROM.** Our
bootloader is a **verifying bootloader** (it checks the firmware's
signature) rather than a *signed-and-verified-at-boot* bootloader. We
sign the bootloader binary at build time so factory tooling can
verify it before programming, but no runtime signature check happens
on this chip.

The bootloader's integrity is provided by:
- Factory-controlled flashing of a known-good bootloader binary
- RDP Level 2 (BOOT003) physically preventing replacement post-burn

The end property is the same; the mechanism differs from Apple/Android.

### 5.5 Why POST and RDP L2 are both needed

A natural question: if RDP Level 2 prevents anyone from writing to flash,
why do we still need POST to verify firmware integrity at every boot?
Doesn't RDP L2 already guarantee that what's in flash is what we put
there?

**Short answer: RDP L2 prevents unauthorized external writes; POST
verifies that what actually got executed matches what we expect. They
protect against different failure modes and together provide defense
in depth.**

#### Five failure modes RDP L2 cannot detect

| # | Failure mode | Why RDP L2 misses it | Why POST catches it |
|---|---|---|---|
| 1 | Legitimate firmware update landed corrupt (interrupted write, MAVLink-FTP transmission error) | RDP L2 sees an authorized internal write — no anomaly to flag | Bootloader sig-verify + POST hash recomputation fail; drone refuses to arm |
| 2 | Bit rot over fleet lifetime (cosmic ray, temperature cycling, flash wear) | RDP L2 only watches write attempts, not stored-state integrity | SHA-256 mismatch detected at every boot |
| 3 | Wrong manifest installed on right firmware (factory or fleet-management error) | Both manifest and firmware are individually signed correctly | POST004 board_id check catches the chip-vs-manifest mismatch |
| 4 | Lab-grade defeat of RDP L2 (chip decap, advanced fault injection — out of Level 1 scope) | If RDP L2 is bypassed, attacker can write flash | Bootloader still requires a manufacturer-signed firmware (signature impossible without private key) |
| 5 | Factory provisioning window (chip is at RDP 0 between firmware-flash and RDP-L2-burn) | RDP L2 isn't burned yet — no protection | POST runs on first boot; if firmware or manifest are wrong, factory tooling sees the failure before locking the chip |

#### Three structural reasons POST is required regardless

POST isn't a redundant check layered on top of RDP — it's a structural
component the rest of the system depends on:

| # | Structural role | What breaks without POST |
|---|---|---|
| A | **The arming gate's input** — `commander` reads `firmware_integrity_status` uORB to decide whether to allow arming (ARM001) | No publisher of `firmware_integrity_status` → ARM001 has nothing to gate on → drone arms with any firmware state |
| B | **The audit log's record of integrity events** — every boot writes a `POST_RESULT` entry (LOG001) | Audit log is silent on the most important security event of every flight; auditor has no boot-history record |
| C | **The auditor-visible runtime evidence** — RDP L2 is invisible from outside (no easy way to confirm it's burned without specialized tooling); POST publishes live `firmware_integrity_status` viewable in QGC | Auditor cannot see runtime proof that integrity is being verified; only static evidence remains |

#### How the layers stack

```
RDP L2          → external write paths are dead          (preventive, hardware)
   ↓
Bootloader      → firmware signature verified pre-launch (cryptographic, runtime)
   ↓
POST            → manifest + checksums + board_id        (cryptographic, runtime, auditable)
   ↓
ARM gate        → preflight refuses if POST failed       (operational)
   ↓
Audit log       → POST_RESULT recorded per boot          (evidence)
```

Each layer covers a different failure mode. Removing POST in favor of
"RDP L2 is enough" would break the arming gate (no consumer for the
integrity status), break the audit log (no `POST_RESULT` entries),
lose visibility for the auditor, lose detection of all non-malicious
corruption (bit rot, partial updates, manifest mismatches), and reduce
the chain to a single hardware layer with no runtime check on what
actually got executed.

**RDP L2 prevents unauthorized writes. POST verifies what got
executed. Both are required.**

---

## 6. What gets signed, by whom, verified where

### 6.1 Artifact catalog

| Artifact | What it is | Signed by | Verified where | Verified when |
|---|---|---|---|---|
| **Application firmware** (`px4_fmu-v6x_default.bin` or equivalent) | The PX4 firmware binary | Manufacturer (RSA-3072 PSS, offline) | Bootloader on FC (mbedTLS) | Every boot |
| **Bootloader** (`bootloader.bin`) | PX4 bootloader (Phase 5b patched version) | Manufacturer (RSA-3072 PSS, offline) | Factory programming tool (build-time only) | At factory flash; **not at runtime** on STM32H743 |
| **`manifest.bin`** | Binary blob with code_hash, data_hash, board_id, version, signature | Manufacturer (RSA-3072 PSS, offline) | Firmware POST module on FC (mbedTLS) | Every boot |
| **`.fwbundle`** (update package) | Tar of firmware + manifest + signature | Manufacturer (RSA-3072 PSS, offline) | (a) QGC plugin client-side (OpenSSL) and (b) FC `FirmwareUpdateGatekeeper` (mbedTLS) | Pre-flash, before staging |
| **Audit log** (`audit_log.bin`) | Append-only event log on FC SD card | Encrypted SHA-256 hash signed per-file | Manufacturer offline tool (`verify_audit_log.py`, OpenSSL) | After log download |

### 6.2 What is NOT signed (and why it's OK)

| Not signed | Why OK |
|---|---|
| `firmware_integrity_status` uORB messages | Internal to FC; the ARM gate runs on the FC, so spoofing this message would require already-compromised firmware (and at that point the attacker has more direct attacks) |
| MAVLink telemetry to GCS | GCS display is informational only; arming gate is on-FC, not in GCS |
| Per-event audit log entries | The whole-file signing model (LOG001) covers integrity at log-download time; per-entry signing was rejected (DEV001 risk — would require a device-resident private key) |
| Individual flight parameters (most) | Compliance-critical params are protected by static compilation (PAR001 zero-window protection), not by signature |

### 6.3 Where the public key is embedded

The same public key appears in three locations on a deployed device:

| Location | Purpose | Updateable? |
|---|---|---|
| **STM32H7 OTP** | Bootloader's trust anchor for verifying firmware | No (write-once) |
| **Bootloader binary** | Bootloader could fall back to embedded copy if OTP read failed (defense in depth — currently unused) | Yes (with new bootloader flash) |
| **Application firmware** (header file `manufacturer_pubkey.h`) | Firmware's trust anchor for verifying manifest and update bundles | Yes (with firmware update) |

All three copies are the same key. Discrepancy would mean a build error
(the build pipeline derives all copies from `pki/manufacturer/public/manufacturer_public.pem`).

---

## 7. Boot sequence — step by step

This is what happens on a CubeOrange+ post-Phase 5b on every power-on or
reset.

```
1. Power applied / reset pin released
2. CPU begins execution at the bootloader entry point in flash (0x08000000).
   This is fixed by hardware — the CPU has no way to skip the bootloader.
3. Bootloader initializes minimum required hardware (clocks, RAM).
4. Bootloader reads the manufacturer RSA-3072 public key from the OTP
   region (e.g. 0x08FFF000–0x08FFF3FF). OTP read is via memory-mapped I/O,
   internal to the chip.
5. Bootloader reads the application firmware's signature (appended at a
   known offset in the firmware image, or stored in a small metadata
   block immediately after the firmware).
6. Bootloader computes SHA-256 over the application firmware region
   (e.g. 0x08020000 to firmware_end). mbedTLS performs the hash.
7. Bootloader runs:
       RSA-PSS-Verify(pubkey_from_OTP, sha256(firmware), signature)
   mbedTLS performs the signature verification.

8a. PASS  → Bootloader executes a BX jump to the firmware reset vector
            (typically at firmware_start + 4). Firmware now controls the
            CPU. Bootloader is no longer running.

8b. FAIL  → Bootloader logs the failure to a known flash region (so QGC
            can read it via Audit Log download later), drives an
            error-LED pattern, and halts (or enters a recovery-only
            mode that ONLY accepts a signed firmware update over USB).
            The drone never arms. The chip never executes attacker code.

9. Firmware boots. The secure_boot module runs POST:
   a. Read manifest.bin from a known flash partition.
   b. RSA-PSS-Verify the manifest using the firmware-embedded pubkey.
   c. Recompute SHA-256 over the running firmware's code section,
      compare to manifest.code_hash.
   d. Recompute SHA-256 over the data section, compare to manifest.data_hash.
   e. Verify board_id in manifest matches the chip's hardware ID
      (POST004).
   f. Publish firmware_integrity_status uORB with the result.

10. The commander module (preflight checks) subscribes to
    firmware_integrity_status. If check_passed=false, it adds:
       ARMING_DENIED: Preflight Fail: Firmware integrity check failed
    Pilot cannot arm. Drone cannot take off.

11. Audit log: a POST_RESULT entry is written for both pass and fail
    outcomes (LOG001). audit_log.bin and audit_log.sig are updated.
```

**Why an attacker cannot skip this sequence:**
- Step 2: hardware-fixed; CPU starts at flash, which contains the bootloader
- Step 4: OTP read is internal to the chip; cannot be intercepted
- Step 7: bypassing this requires either (a) modifying the bootloader
  (blocked by RDP L2), (b) glitching the CPU at the verify branch
  (out of Level 1 scope), or (c) substituting the OTP pubkey
  (physically impossible — write-once fuses)
- Step 9: bypassing this requires modifying the firmware (which would
  break its bootloader-checked signature)
- Step 10: bypassing this requires modifying `commander` (same — would
  break firmware signature)

---

## 8. Firmware update paths

There are two physical paths to write new firmware to the FC. Both
must be gated.

### 8.1 Path A — DFU (USB + BOOT button)

- **Mechanism:** STM32H7 ROM-resident DFU bootloader; activated by
  holding BOOT pin high at reset; tools like `dfu-util` flash arbitrary
  bytes from a host PC.
- **Pre-Phase-5b state:** OPEN. The DFU bootloader does not verify
  signatures. Anyone with USB access can flash arbitrary firmware.
  This is the gap that motivated Phase 5b.
- **Post-BOOT001 state:** firmware lands in flash, but on next boot,
  the patched bootloader detects the signature mismatch and refuses to
  launch it. Drone won't run, but the malicious firmware is on flash.
- **Post-BOOT003 state:** RDP Level 2 disables DFU writes at the chip
  level. DFU bootloader still runs but its commands are rejected by
  silicon. Path A is fully closed.

### 8.2 Path B — MAVLink-FTP (signed `.fwbundle` via QGC)

- **Mechanism:** Operator uploads a `.fwbundle` through the QGC Secure
  Firmware Update page; QGC verifies signature client-side; QGC
  uploads to FC via MAVLink-FTP; FC `FirmwareUpdateGatekeeper`
  re-verifies before authorizing the staged manifest swap.
- **Gating:** UPD001 (this is fully implemented and SITL-verified for
  the positive path; tampered-bundle rejection is SITL acceptance step
  12, pending).
- **Post-BOOT001 state:** even if a future firmware update bug let an
  unsigned bundle through, the bootloader would catch it on next boot.
  Defense in depth.

### 8.3 The combined gating story

| Path | Gated by (today, pre-Phase-5b) | Gated by (post-Phase-5b) |
|---|---|---|
| Path A (DFU) | Nothing — OPEN GAP | BOOT001 (firmware refuses to launch) + BOOT003 (DFU dead) |
| Path B (MAVLink-FTP) | UPD001 (QGC + FC verify) | UPD001 + BOOT001 (bootloader re-verify) |

After Phase 5b, **every byte of code the CPU executes was signed by
the manufacturer's RSA-3072 private key**, regardless of which path
delivered it.

### 8.4 How updates work on a chip locked by RDP L2

A common question: "If RDP L2 blocks all flash writes, how do firmware
updates get installed?" The answer hinges on a critical distinction
RDP makes that's easy to miss.

**RDP L2 blocks EXTERNAL writes (DFU bootloader, SWD/JTAG debugger).
It does NOT block writes initiated by RUNNING TRUSTED FIRMWARE on the
chip itself.**

| Who's writing | Mechanism | Blocked by RDP L2? |
|---|---|---|
| Host PC via DFU bootloader (`dfu-util` etc.) | External — USB → ROM bootloader → flash peripheral | ✅ Yes |
| Debug probe via SWD/JTAG | External — debug interface → flash peripheral | ✅ Yes |
| Running PX4 firmware writing to flash | Internal — CPU executes flash-write instructions on the FLASH peripheral | ❌ No, allowed |

This is the same model every modern locked-down device uses (iPhone,
Android with locked bootloader, Tesla, modern automotive ECUs). The
chip is "selectively writable by entities holding the right key" —
not "completely write-protected."

#### The actual update flow on a locked chip

```
1. Manufacturer signs new firmware bundle (.fwbundle) offline with private key
2. Operator downloads .fwbundle, opens QGroundControl
3. QGC client-side verifies bundle signature (UPD001 client check)
4. QGC uploads .fwbundle to FC via MAVLink-FTP
   ↓
5. Running PX4 firmware on FC receives the bundle via FirmwareUpdateGatekeeper
6. PX4 firmware verifies the bundle signature using mbedTLS + embedded
   manufacturer pubkey (UPD001 drone-side check)
7. PX4 firmware writes the new firmware to a STAGING flash region using
   the STM32 HAL flash-write functions
   ← THIS WRITE WORKS even with RDP L2 burned, because it is initiated
     by trusted firmware already running on the CPU itself
8. PX4 firmware writes the new manifest.bin to its flash region
9. PX4 firmware sets a "boot from staged firmware on next reset" flag
10. FC reboots
   ↓
11. Bootloader runs (the same locked-down bootloader from factory)
12. Bootloader sees the staged-firmware flag, points at the new region
13. Bootloader hashes the new firmware, verifies signature against OTP pubkey
14a. PASS → bootloader launches new firmware. Update successful.
14b. FAIL → bootloader rolls back to previous firmware (A/B partition pattern)
```

The crucial security property: **the only entity that can deliver a
working firmware update is one holding the manufacturer's RSA-3072
private key.** Even though RDP L2 allows internal writes, an attacker
cannot push an update because:

- They cannot sign the bundle (no private key)
- The running firmware refuses to write the bytes if signature check
  fails (UPD001 step 6)
- The bootloader refuses to launch the new firmware if signature check
  fails (BOOT001, step 13)
- Both verifications use the OTP-resident pubkey, which cannot be
  replaced

The update path is open *for legitimate updates* and closed *for
unauthorized ones* — the property we want.

#### What CANNOT be updated post-RDP-L2

Some flash regions need additional protection beyond RDP — using
**WRP (Write Protection)**, a separate per-sector option-byte
setting that blocks ALL writers including running firmware:

| Region | Protection | Updatable post-RDP-L2? |
|---|---|---|
| Application firmware (~1.5 MB) | RDP L2 only — no WRP | ✅ Yes (via UPD001) |
| `manifest.bin` region | RDP L2 only — no WRP | ✅ Yes (via UPD001) |
| Staging region (A/B partition) | RDP L2 only — no WRP | ✅ Yes (where new firmware lands during update) |
| Audit log region | RDP L2 only — no WRP | ✅ Yes (firmware appends entries) |
| **Bootloader region (~128 KB)** | RDP L2 + **WRP** | ❌ **No — deliberately unupdatable** |
| OTP pubkey | Hardware write-once silicon fuses | ❌ No |
| RDP setting in option bytes | Frozen by RDP L2 itself | ❌ No |

The **bootloader region is intentionally permanent** on production
units. WRP-locking the bootloader sectors means even running firmware
cannot replace the bootloader. The trade-offs:

- **Pro:** the trust anchor of the chain (the bootloader that does
  verification) cannot be replaced by anyone, ever — not by an
  attacker, not even by us
- **Pro:** a compromise of the firmware-signing process cannot be
  weaponized to push a malicious bootloader to deployed units
- **Con:** if a critical bug is found in the bootloader after
  deployment, deployed units cannot be patched; affected units
  must be field-replaced

We accept this trade-off and mitigate the con by:
- Keeping the bootloader **small and simple** (~10K LOC max — much
  less code surface than firmware)
- **Extra rigorous review** on bootloader code (security-focused audit
  before factory burn)
- Designing the bootloader as a **rarely-changing** component (just
  verify-and-launch logic, no feature growth)
- Using **mbedTLS** (well-tested crypto library, not in-house code)

This is the same trade-off iPhones, Teslas, and Android devices accept
for their first-stage bootloaders. The immutable trust anchor is a
feature, not a limitation.

#### Phase 5b implication

Phase 5b's BOOT001 (verifying bootloader) and BOOT003 (RDP L2 burn)
together require the bootloader region to be WRP-locked as part of the
factory provisioning sequence. The full sequence:

1. Flash bootloader to chip
2. Flash application firmware
3. Flash manifest.bin
4. Program OTP with manufacturer pubkey (BOOT002)
5. Burn WRP on bootloader sectors (locks bootloader against all writers)
6. Burn RDP Level 2 (closes external write paths)

After step 6, the chip is in production mode: the bootloader is
permanent, OTP is permanent, RDP is permanent, and the only way to
update the application firmware is via UPD001 with a manufacturer-signed
bundle.

---

## 9. DGCA requirement mapping

This section maps DGCA requirements to our implementation. The
companion mapping with phase status is in
[SECURITY_PLAN.md §3 Requirements Matrix](../SECURITY_PLAN.md).

### 9.1 Requirement: "Registered checksums shall be stored securely in the flight module such that they cannot be updated without the authorization of the manufacturer." (DGCA §4.1.2)

This is the requirement most often misread as requiring flash
encryption. It does not. The requirement is about **authorization of
updates**, not **secrecy of checksum values**.

**How we satisfy it:**

| Sub-property | Our mechanism |
|---|---|
| Checksums **stored** in flight module | `manifest.bin` written to flash by factory provisioning (PRV001) |
| **Securely** | RSA-3072 signed by manufacturer; tamper detected by signature verification at every boot |
| **Cannot be updated without authorization** | Only the manufacturer (holder of the private key) can produce a `manifest.bin` whose signature the FC will accept. An attacker can rewrite the bytes, but the result will fail signature verification → POST fails → drone refuses to arm. |

**The auditor walk-through:**
1. Show `manifest.bin` location in flash (`hexdump`).
2. Show that any byte modification → POST fails → `firmware_integrity_status.check_passed=false` → arming blocked. (SITL acceptance step 5, ✅.)
3. Show that the only update paths for the manifest are:
   - UPD001 (signed bundle through MAVLink-FTP) — gated by signature
   - BOOT001 firmware update (signed firmware containing new manifest) — gated by signature
   - DFU (Path A) — closed by BOOT003 in production
4. Show that the trust anchor (OTP pubkey) cannot be replaced (write-once silicon).

This is a **stronger property** than the audited reference's flash encryption
approach. the audited reference hides the storage so attackers can't read or coherently
write to it. We expose the storage but cryptographically authenticate
it. Either approach satisfies the requirement.

### 9.2 Other DGCA requirements (summary)

Detailed mapping is in [SECURITY_PLAN.md](../SECURITY_PLAN.md). Quick summary:

| DGCA topic | Our requirement IDs | Status |
|---|---|---|
| Root of Trust | ROT001, ROT002, BOOT002 | ✅ Done (key infra); ⏳ BOOT002 hardware |
| Firmware checksums | CHK001 | ✅ Done |
| Signed firmware | SIG001, PKG001 | ✅ Done |
| POST | POST001/002/003/004 | ✅ Done (SITL); ⏳ hardware |
| Arming gate | ARM001 | ✅ Done |
| Secure update | UPD001 | ✅ Done; SITL steps 11/12 pending |
| Parameter protection | PAR001 | ✅ Done |
| Audit logging | LOG001 | ✅ Done |
| GCS-FC pairing | PAIR001 | ✅ Done (SITL) |
| Bootloader hardening | BOOT001/003 | ⏳ Phase 5b |

---

## 10. Why we deviate from the audited reference (flash encryption)

the audited reference reference implementations (per the audit docs in
[Docs/](../Docs/)) use AES-128 with the key stored in OTP to **encrypt
flash contents**. Our architecture deliberately does NOT include this.

### 10.1 What the audited reference does

```
[OTP: AES-128 key]   ← write-once
        │ provides decryption key for
        ▼
[Encrypted flash]    ← contents only meaningful if decrypted with OTP key
        │ also contains
        ▼
[Firmware checksums embedded in encrypted flash]
```

the audited reference's protection of registered checksums is **confidentiality-based**:
- Attacker can't read the checksums (encrypted)
- Attacker can't write coherent replacement (no AES key to encrypt with)
- CRP (RDP equivalent) blocks external flash readout

### 10.2 What we do instead

```
[OTP: RSA-3072 public key]   ← write-once
        │ used by bootloader to verify
        ▼
[Plain flash, signed firmware]   ← readable, but tampering detectable
        │ contains
        ▼
[manifest.bin — RSA-3072 signed]   ← any modification breaks signature
```

Our protection is **authenticity-based**:
- Attacker can read the checksums (they're public values — `SHA-256(firmware)`)
- Attacker can write replacement bytes, but the result fails signature verification
- RDP L2 blocks external write paths anyway

### 10.3 Why our approach is sufficient (and arguably better) for DGCA Level 1

| Property | the audited reference approach | Our approach |
|---|---|---|
| **DGCA §4.1.2 requirement (storage authorization)** | ✅ Met via confidentiality | ✅ Met via authenticity |
| **Confidentiality of firmware bytes** | ✅ Provided | ❌ Not provided (RDP L2 blocks readout, but flash bytes are not encrypted) |
| **Auditability** | Harder (auditor can't easily inspect what's in flash without the key) | Easier (auditor can `hexdump` and compare to known-good) |
| **Standard pattern** | Vendor-specific | Matches Apple/Android/UEFI signed-boot |
| **Crypto agility** | Symmetric key compromise = total loss | Asymmetric — public key leak is harmless |
| **Per-device complexity** | Each unit needs unique AES key, per-unit encrypted firmware | Single firmware image works on all units |

### 10.4 What flash encryption WOULD give us (and why we defer it)

Flash encryption protects:
- **IP / trade secrets** — competitor can't dump and reverse-engineer
- **Anti-cloning** — copied flash image won't run on a different chip

Neither is a DGCA Level 1 requirement. Both are productization
concerns we may want later as the toolkit goes vendor-facing.

**Decision (ADR-004):** Flash encryption is filed as **BOOT004**,
deferred until productization or unless DGCA Level 2/3 introduces a
confidentiality requirement. RDP Level 2 provides the practical
equivalent (flash unreadable from outside) for Level 1 deployment.

If we add BOOT004 later, the OTP has ~576 bytes of free space (after
the ~422-byte pubkey takes ~14 of 32 blocks) — plenty for a per-device
AES-256 key and metadata. The architecture is forward-compatible.

---

## 11. Comparison to other architectures

Our pattern is **immutable hardware-resident trust anchor → verifying
bootloader → signed firmware → signed config**. This is the standard
production secure-boot pattern.

| System | Trust anchor | Bootloader verified at runtime by? | Mass deployment |
|---|---|---|---|
| **Apple iPhone/iPad** | Apple Root CA pubkey in immutable Boot ROM (silicon) | Yes — Boot ROM | Billions |
| **Android Verified Boot** | OEM pubkey hash in hardware-protected storage | Yes — vendor-specific Boot ROM (varies by SoC) | Every Android device since 8.0 |
| **UEFI Secure Boot** | Platform Key X.509 cert in firmware NVRAM | Yes — UEFI firmware | Every Windows PC since Windows 8 |
| **STM32MPU ROM secure boot** | SHA-256 of pubkey in OTP WORD 24–31 | Yes — STM32MPU Boot ROM | ST's documented production flow |
| **STM32H5 with RSS** | RSS-managed trust anchor | Yes — Root Secure Services | ST's modern MCU production flow |
| **ARM Trusted Firmware (TF-A)** | Root pubkey hash in SoC fuses | Yes — BL1 (immutable) | Industry-standard ARM secure boot |
| **Inofly (this project)** on STM32H743 | RSA-3072 pubkey in STM32H7 OTP | **No** — bootloader integrity from RDP L2, not runtime sig check | DGCA Level 1 |
| **the audited reference (audit reference)** | AES-128 in OTP + RSA pubkey embedded in firmware | (Bootloader stores firmware hash; design unclear from reference) | Reference implementation |

**Key observation:** every production secure-boot system roots trust
in silicon. The mechanism varies (Boot ROM signature check vs. RDP
write-protection of the bootloader region), but the property is the
same — **the bootloader on a deployed unit is the bootloader the
manufacturer intended, and an attacker cannot replace it.**

Our STM32H743 deployment uses RDP L2 to provide that property. If we
move to STM32H5/U5 in the future (§14), we'll get the
silicon-verified-bootloader pattern as well, "for free."

This is **not a novel architecture.** It is the mainstream pattern,
validated by billions of production devices.

---

## 12. Architecture Decision Log

This section records the major architectural decisions, with date,
rationale, and alternatives considered. Append-only — supersession is
recorded as a new entry referencing the old one.

### ADR-001 — Single RSA-3072 keypair for everything (2026-04-15)

**Decision:** Use one manufacturer keypair for firmware signing,
manifest signing, update-bundle signing, AND audit-log encryption.
Private key offline at manufacturer; public key embedded in firmware
and (Phase 5b) burned to OTP.

**Alternatives considered:**
- Separate firmware-signing and log-signing keypairs — rejected. More
  keys to manage with no security gain.
- Separate per-device keys — rejected. Would require device-resident
  private keys (DEV001 risk), more complex provisioning, no audit
  precedent.

**Rationale:** Simpler operational model; RSA supports both signing
and public-key encryption; compromise scenarios are not worse with one
key than with multiple.

### ADR-002 — RSA-3072 (not RSA-2048) (2026-04-15)

**Decision:** Use RSA-3072 PSS for all signatures.

**Alternatives considered:**
- RSA-2048 (the audited reference reference uses this) — rejected. NIST
  recommends 3072+ for use beyond 2030.
- ECDSA P-256 — rejected. Doesn't support public-key encryption,
  would require additional crypto layer for audit-log use case.

**Rationale:** Future-proof against NIST lifecycle; modest
performance cost on STM32H7 (~50 ms verify); single primitive for both
signing and encryption.

### ADR-003 — Bootloader integrity from RDP L2, not runtime signature check (2026-04-29)

**Decision:** On STM32H743/H753, the bootloader is a **verifying
bootloader** (it checks firmware signatures) but is not itself
signature-verified at runtime. Bootloader integrity is provided by
RDP Level 2 (chip-level write lockdown).

**Alternatives considered:**
- Two-stage bootloader (Stage-0 verifies main bootloader) — rejected
  for STM32H743. Adds complexity for marginal benefit; Stage-0 itself
  has the same protection problem.
- Move to STM32H5 (with RSS / authenticating Boot ROM) — deferred.
  See §14. Would require new hardware procurement and BSP work.

**Rationale:** STM32H743 has no authenticating Boot ROM; runtime
bootloader signature verification is not possible on this chip. RDP
L2 provides the equivalent end property. We sign the bootloader binary
at build time for factory tooling integrity but don't claim runtime
verification of the bootloader.

### ADR-004 — Skip flash encryption (BOOT004 deferred) (2026-04-29)

**Decision:** Do not implement AES-128 (or AES-256) flash encryption
for DGCA Level 1. Defer to BOOT004 in a future phase if needed.

**Alternatives considered:**
- Add AES flash encryption matching the audited reference pattern — rejected for
  Level 1.
- Use STM32H7 hardware crypto accelerator (CRYP) for runtime flash
  decryption — deferred (BOOT004).

**Rationale:** DGCA Level 1 requires integrity/authenticity, not
confidentiality. Our signed-manifest + signed-firmware + RDP-L2 chain
already meets the storage-security requirement (§9.1). Flash
encryption is a confidentiality control useful for IP protection and
anti-cloning (productization concerns), neither in Level 1 scope.
Defers complexity (per-device key generation, per-unit encrypted
firmware, factory tooling changes) without compromising compliance.

### ADR-005 — mbedTLS on hardware, OpenSSL on host/SITL (2026-03-20)

**Decision:** Use mbedTLS for all cryptographic operations on
embedded hardware (NuttX RTOS); use OpenSSL for host-side tooling and
SITL.

**Alternatives considered:**
- mbedTLS everywhere — rejected. OpenSSL is the host-side standard,
  better Python bindings.
- OpenSSL everywhere — rejected. OpenSSL is too large for MCU flash
  budget.

**Rationale:** Both libraries implement RSA-PSS / SHA-256 with full
interoperability. mbedTLS is sized for MCU (~50 KB flash for the
relevant subset). Using both gives best-of-both.

### ADR-006 — Per-file RSA log signing, not per-entry ECDSA (2026-04-22)

**Decision:** Audit log uses per-file signing. FC writes
`audit_log.bin`, then encrypts SHA-256 of the file with the public key
(PKCS#1 v1.5). Manufacturer decrypts with private key offline to
verify.

**Alternatives considered:**
- Per-entry ECDSA signatures with a private key on the FC — rejected.
  Requires device-resident private key (DEV001 risk: extraction +
  forgery).
- Per-entry HMAC with shared secret — rejected. Same DEV001 risk for
  the secret.
- Per-file signing with a separate log-signing keypair — rejected.
  More keys to manage; covered by single-keypair decision (ADR-001).

**Rationale:** No private key on device; matches the audited reference Section 8
audit-logging pattern; simpler manufacturer-side verification flow.

### ADR-007 — Static parameter compilation for compliance-critical params (2026-04-25)

**Decision:** Bake compliance-critical parameters (geofence, speed,
altitude, frame, sign config) into firmware binary at build time.
Block `param_set` for these parameters at the parameter library level.

**Alternatives considered:**
- Signature-gated runtime writes — rejected. Race window between sig
  check and write; larger TCB; no audit precedent in the audited reference.

**Rationale:** Zero-window protection (write is rejected before any
check completes). Smaller TCB. Matches the audited reference pattern.

### ADR-008 — MAVLink signing via SHA256(passphrase) key derivation (2026-04-28)

**Decision:** Use PX4/QGC native MAVLink signing; derive 32-byte
signing key from operator passphrase as `SHA256(passphrase)`. Same
passphrase entered into provisioning tool and into QGC; both derive
the same key.

**Alternatives considered:**
- Custom 8-byte UID (the audited reference pattern) — rejected. Weaker than 32-byte
  SHA-256; would require building a custom auth layer.
- Per-drone random key + provisioning bootstrap — rejected. More
  complex operator workflow.

**Rationale:** Reuses PX4/QGC infrastructure (no custom auth layer);
SHA-256 derivation is stronger than the audited reference's 8-byte UID; simple operator
flow (one passphrase shared between provisioning tool and QGC).

### ADR-009 — POST in app firmware (SITL) and bootloader (hardware) (2026-04-29)

**Decision:** SITL has no bootloader, so POST runs in the application
firmware on SITL. On hardware (CubeOrange+), POST moves into the
bootloader (Phase 5b). The application firmware retains its POST
module for `firmware_integrity_status` publication and ARM-gate
wiring.

**Rationale:** SITL does not simulate a bootloader; running POST in
app firmware on SITL preserves end-to-end testability. Hardware POST
in bootloader is required to gate firmware launch (the bootloader is
the only entity that runs before firmware).

### ADR-010 — Two update paths, both gated (2026-04-29)

**Decision:** Path A (DFU) closed by BOOT003 (RDP L2 disables DFU
writes); Path B (MAVLink-FTP) gated by UPD001 (signed bundle) +
BOOT001 (bootloader re-verify on next boot).

**Rationale:** Defense in depth. Even a hypothetical bug in
UPD001's signature check would be caught by the bootloader. Path A
has no in-firmware mitigation possible (DFU runs from ROM, bypassing
the firmware), so chip-level lockdown (RDP L2) is the only defense.

### ADR-011 — RDP Level 2 mandatory for production (2026-04-29)

**Decision:** Production hardware (units flown in regulated airspace
or shipped to customers) must have RDP Level 2 burned. Dev boards and
SITL audit-demo units may run at RDP 0.

**Rationale:** Without RDP L2, an attacker can DFU-flash a malicious
bootloader that skips signature verification (T11 in
[THREAT_MODEL.md](THREAT_MODEL.md)). RDP L2 is the only defense. Dev
boards are exempted because the dev-vs-production distinction is
operationally enforced (dev boards stay in the lab).

### ADR-012 — Architecture lockdown (2026-04-29)

**Decision:** As of this date, the architecture documented in this
doc is **frozen**. Implementation work (Phase 5b code changes,
hardware deployment) is open; architectural changes require a new
ADR entry and team agreement.

**Rationale:** Multiple alternatives have been considered and rejected
for each major decision; further architectural drift would burn time
without commensurate benefit. The architecture is now locked, and
work focuses on shipping Phase 5b.

---

## 13. Residual risks (acknowledged)

The architecture defends against software-level attacks and
production-grade physical attacks. It does NOT defend against:

| Risk | Why we accept it | Mitigation outside Level 1 scope |
|---|---|---|
| **Manufacturer private key compromise** | Operational, not technical. Same risk class as every PKI-based ecosystem (Apple, Microsoft, Google all have this exposure). | HSM, key ceremony, access controls, periodic key rotation if compromised |
| **Lab-grade fault injection** (voltage glitch, EM injection, clock glitch at the verify branch) | Out of DGCA Level 1 threat scope. Requires equipment and expertise of nation-state-level adversary. | HSM-class silicon (e.g., STM32U5 with TrustZone-M anti-glitch) — future hardware option |
| **Chip decap and OTP rewriting** | Physically possible in a state-of-the-art lab; out of Level 1 scope. | Same — silicon with OTP tamper detection |
| **Supply chain compromise** (malicious code injected into PX4 source before signing) | Not a software-attack-against-the-device vector; mitigated operationally. | Reproducible builds, code review, controlled build host |
| **Dev boards (RDP 0)** | RDP L0 dev units have full SWD/JTAG/DFU exposure. We accept this for development; production units have RDP L2 burned. | Operational segregation (dev units never flown in regulated airspace) |
| **Confidentiality of firmware bytes** | Not a Level 1 requirement. RDP L2 provides practical readout protection. | Add BOOT004 (flash encryption) for productization or Level 2/3 |

These risks are documented for the auditor. They are **acknowledged
limitations**, not undiscovered gaps.

---

## 14. Future hardware options

The current architecture targets STM32H743/H753 (CubeOrange+). The
architecture is designed to be portable to chips with stronger
security primitives.

### 14.1 STM32H5 (mid-term option)

- **Has Root Secure Services (RSS)** — authenticating Boot ROM
- **Has TrustZone-M** — privileged/non-privileged code separation
- **Has PROC_FILTERING / OTFDEC** — on-the-fly flash decryption (for
  external SPI flash)
- **Migration impact:** bootloader could be runtime-verified by RSS
  (closing the "no Boot ROM on H743" gap); much of our architecture
  carries over unchanged.

### 14.2 STM32U5 (security-focused option)

- **TrustZone-M, anti-tamper, hardware crypto, secure firmware
  install (SFI)**
- **Most capable STM32 for security applications**
- **Migration impact:** could enable Level 2/3 features
  (anti-glitch, side-channel resistance, encrypted firmware install).

### 14.3 STM32MP1/MP2 (MPU class)

- **Linux-class processor with full secure boot via TF-A**
- **Migration impact:** very different software architecture; consider
  only for high-end products that need Linux capabilities (vision,
  ML, complex telemetry).

### 14.4 What stays the same across future hardware

Regardless of chip family, the following architectural elements
carry over:
- Single RSA-3072 keypair (or upgrade to RSA-4096 / Ed25519 if needed)
- Manifest format and signing process
- POST logic and ARM-gate wiring
- LOG001 audit-log signing approach
- PAR001 static parameter compilation
- PAIR001 MAVLink signing
- Manufacturer toolchain (signing, packaging, factory provisioning)

What changes per chip family:
- Bootloader implementation (verifier vs verified-by-Boot-ROM)
- OTP layout (different sizes, different addresses)
- Lockdown mechanism (RDP L2 vs RSS-managed lockdown vs OTP "device closed" bit)
- Whether flash encryption is hardware-supported (OTFDEC for external flash)

---

## Appendix A — Glossary

For hardware security terminology (DFU, SWD/JTAG, OTP, RDP, option
bytes, flash readout), see
[THREAT_MODEL.md §9 Glossary](THREAT_MODEL.md#9-glossary--hardware-security-terms).

For project-specific requirement IDs (CHK001, BOOT001, etc.), see
[SECURITY_PLAN.md §3 Requirements Matrix](../SECURITY_PLAN.md).

---

## Appendix B — Document history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-04-29 | Initial lockdown. Captures all architectural decisions made through ADR-012. |
| 1.1 | 2026-04-29 | Added §5.5 (Why POST and RDP L2 are both needed) and §8.4 (How updates work on a chip locked by RDP L2 — internal-vs-external writes, WRP-locked bootloader region, factory provisioning sequence). No architectural changes; expansions of existing decisions to address common auditor questions. |
