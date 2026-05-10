# Inofly UAS Firmware Security — Architecture Reference

**Status:** 🔒 LOCKED — 2026-04-29 · 🟡 PARTIALLY AMENDED — 2026-05-04 (ADR-013/014/015) · 🟡 KEY-SIZE AMENDED — 2026-05-06 (ADR-016)
**Scope:** DGCA Level 1 Type Certification, firmware manufacturer role
**Target hardware:** CubeOrange+ (STM32H743/H753) initially; future-portable
**Document owner:** Architecture is frozen at this revision. Material
changes require a new entry in the Architecture Decision Log (§12) and
team agreement.

> **🟡 Amendment notice — 2026-05-04.** Sections that describe the OTP
> trust anchor (§3.2, §4.3), RDP Level 2 bootloader protection
> (§4.4, §5.1–§5.5, §8.1, §8.4), and BOOT002/BOOT003 are **partially
> superseded** by ADR-013, ADR-014, ADR-015 in §12. The forcing
> function: CubeOrange+ has no externally accessible BOOT0 button on
> the carriers we ship; reaching SWD/DFU requires breaking the Hex
> factory seal, making OTP write, RDP burn, and WRP option-byte set
> operationally infeasible. The architecture now uses an
> **ArduPilot-style bootstrap-trust chain + tamper-evident sealing**
> in place of OTP+RDP. **The single-keypair, libtomcrypt, POST,
> ARM-gate, LOG001, PAR001, PAIR001, UPD001 decisions are unchanged.**
> (The RSA key size has since been re-tuned from 3072 to 2048 — see
> ADR-016, 2026-05-06.) Read §12.13–§12.15 for the bootstrap/sealing
> ADRs and §12.16 for the key-size amendment.
>
> **Reading convention used below.** Retired material is rendered in
> `~~strikethrough~~` (or labelled **🚫 RETIRED** for code-block
> diagrams that markdown won't strike). Each retired block is
> immediately followed by the current replacement, labelled
> **✅ CURRENT**. This preserves the original decision record (every
> reason we considered, every alternative we rejected) while making
> the actively-implemented architecture unambiguous to a reader
> skimming the doc.

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
| ~~[RDP_BURN_RUNBOOK.md](RDP_BURN_RUNBOOK.md) (Phase 5b deliverable)~~ ⚠️ **RETIRED 2026-05-04 (ADR-013)** — RDP burn no longer part of provisioning. Replaced by `MANUFACTURING_RUNBOOK.md` (deliverable). | ~~Step-by-step RDP Level 2 burn procedure~~ → bootstrap-install + tamper-evident seal procedure | You're about to ~~burn production hardware~~ ✅ provision and seal a production unit |

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
| L1 | **Single RSA-2048 keypair** for firmware signing, manifest signing, update-bundle signing, audit-log encryption (key size amended from RSA-3072 by ADR-016, 2026-05-06; single-keypair core unchanged) | §3, ADR-001, ADR-016 |
| L2 | **Manufacturer role only** — we sign artifacts; we are not the certifying body | DGCA Level 1 scope |
| L3 | **Target hardware: STM32H743/H753** (CubeOrange+) for initial deployment | §4, hardware on hand |
| L4 | ~~**Trust anchor: RSA-3072 public key in STM32H7 OTP** (full DER pubkey, ~422 bytes)~~ ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **CURRENT:** RSA-2048 public key **embedded in the bootloader binary** (and in app fw for UPD001 / manifest verification). No OTP burn — CubeOrange+ carrier has no accessible BOOT0; breaking the Hex factory seal is operationally infeasible. | §3, ADR-002, ADR-013, ADR-016 |
| L5 | ~~**Bootloader is a verifier, not chip-verified** — bootloader's own integrity comes from RDP Level 2, not from runtime signature check (STM32H743 has no authenticating Boot ROM)~~ ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **CURRENT:** bootloader is still a verifier (it checks the firmware signature on every boot — BOOT001) and is still not chip-verified at runtime. Bootloader integrity now comes from a **bootstrap-trust chain** (only path to write sector 0 is `bl_update` from a running, signed app fw) + **tamper-evident sealing** of the airframe and Cube enclosure. | §4.2, ADR-003, ADR-013 |
| L6 | **No flash encryption (no AES-in-OTP)** for Level 1 — the audited reference-style confidentiality control is not required by DGCA Level 1 | §10, ADR-004 |
| L7 | **libtomcrypt on NuttX (app fw + bootloader), OpenSSL on host/SITL** — both speak RSA-PSS / SHA-256 interoperably; libtomcrypt is the MCU-sized library already linked into PX4 (no new dependency). Earlier doc revisions said "mbedTLS on hardware"; that wording was always stale — the actual library is libtomcrypt. ADR-005 reworded 2026-05-07 to match. | PROJECT_NOTES.md, ADR-005 |
| L8 | **Audit log: per-file RSA-2048 signing**, public-key encryption of SHA-256 hash | SECURITY_PLAN.md §LOG001, ADR-006, ADR-016 |
| L9 | **Static parameter compilation** for compliance-critical params (zero-window protection) | SECURITY_PLAN.md §PAR001, ADR-007 |
| L10 | **MAVLink signing with `SHA256(passphrase)` key derivation** for GCS-FC pairing | SECURITY_PLAN.md §PAIR001, ADR-008 |
| L11 | **POST in app firmware on SITL; POST in bootloader on hardware** (Phase 5b) | SECURITY_PLAN.md §Phase 5b, ADR-009 |
| L12 | **Two update paths, both gated:** ~~Path A (DFU) closed by BOOT003~~; Path B (MAVLink-FTP) closed by UPD001 + BOOT001 re-verify ⚠️ **AMENDED 2026-05-04 (ADR-014).** ✅ **CURRENT:** Path A (DFU) closed by **software DFU-refuse** in the secure bootloader (ArduPilot pattern). Path B unchanged. | §8, ADR-010, ADR-014 |
| L13 | ~~**RDP Level 2 mandatory for production units** (not for dev boards / SITL audit demos)~~ ⚠️ **SUPERSEDED 2026-05-04 (ADR-013).** ✅ **CURRENT:** production units are protected by **tamper-evident seal** (airframe + Cube enclosure) + **serial-number tracking** (STM32 96-bit UID + seal serial recorded at manufacture) + **RMA inspection workflow**. | §5, ADR-011, ADR-013 |
| L14 | **Tamper-evident sealing on airframe + Cube enclosure** for production units (compensating control for the physical-attacker class formerly handled by RDP L2) | ADR-013, MANUFACTURING_RUNBOOK.md (deliverable) |
| L15 | **bl_update / ROMFS-bundled bootloader** is the install path: bootloader is bundled in app fw ROMFS, first install via factory PX4 bootloader → MAVLink `flashbootloader` → secure bootloader self-installs | ADR-015 |

**What's NOT locked** (still implementation-open):
- Phase 5b code changes under the amended architecture: BOOT001 stays (verifying bootloader); BOOT002 (OTP) and BOOT003 (RDP burn) are *removed* and replaced by ADR-014 (software DFU-refuse) + tamper-evident seal procurement
- Manufacturing runbook drafting (factory bootloader hash check at receipt → first install → bl_update → seal → UID + seal-serial recording)
- Bootloader DFU-refuse code change in the PX4 fork (ArduPilot-pattern check)
- App firmware size budget under bl_update enabled — strip unused PX4 modules if it overflows (see project memory: categorized strip list)
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
  provisioning, ~~OTP programming, RDP burning,~~ audit-log
  verification ✅ **CURRENT (ADR-013/014/015):** factory bootloader
  hash check on receipt, first-install via QGC + `bl_update`, secure
  bootloader build (with DFU-refuse flag), tamper-evident seal
  application, UID + seal-serial recording

### 2.2 Roles and trust boundaries

| Role | Who | What they hold |
|---|---|---|
| **Manufacturer (us)** | Inofly engineering | RSA-2048 **private** key (offline, HSM/secure storage). Signs all artifacts. |
| **Flight controller** | The drone hardware | RSA-2048 **public** key ~~(in STM32H7 OTP after factory provisioning)~~ ✅ **CURRENT (ADR-013):** embedded in bootloader + app firmware binaries |
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

**One RSA-2048 keypair signs and decrypts everything.** Specifically:

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
| RSA-2048 **private** key | Manufacturer HSM / offline secure storage. **NEVER on any deployed device.** | HSM access controls, key ceremony, physical security |
| RSA-2048 **public** key (deployed) | ~~STM32H7 OTP (write-once silicon fuses)~~ ⚠️ AMENDED 2026-05-04 (ADR-013). ✅ **CURRENT:** embedded in **bootloader binary** + **app firmware binary** (single source: `pki/manufacturer/public/manufacturer_public.pem`) | ~~Hardware-immutable after provisioning~~ → **Bootstrap-trust chain** (sector 0 only writable via `bl_update` from a running signed app fw) + **tamper-evident sealing** of airframe + Cube |
| RSA-2048 public key (build-time) | `pki/manufacturer/public/manufacturer_public.pem` (in repo) | Public — no secrecy required |
| MAVLink signing key (per-drone) | Derived from operator passphrase as `SHA256(passphrase)` — held in QGC and in FC parameter | Operator chooses passphrase strength; key never transmitted |

**Compromise of any deployed device yields only the public key.** The
public key is, by definition, public — leaking it does not enable
forging signatures.

### 3.3 Why RSA-2048 (not ECDSA, not RSA-3072)

- **RSA vs ECDSA:** RSA supports both signing AND public-key encryption
  with one primitive. ECDSA does not encrypt — it would require an
  additional ECIES or RSA layer for the audit-log encryption use case.
  Single-primitive simplicity won.
- **RSA-2048 vs RSA-3072:** RSA-2048 meets DGCA Level 1 (matches the
  the audited reference reference) and produces smaller artifacts (256-byte
  signatures vs 384, ~294-byte SPKI DER vs ~422). Smaller artifacts
  matter most in the bootloader — sector 0 is 128 KB on STM32H743 and
  every kilobyte of crypto-library footprint comes out of the
  application headroom. The original ADR-002 chose RSA-3072 for
  beyond-2030 NIST headroom; ADR-016 (2026-05-06) reverses that for
  footprint and audit-alignment reasons. The single-keypair, RSA-PSS
  (SHA-256, MGF1-SHA256, saltlen=32) scheme is unchanged.
- **Performance is acceptable on STM32H7:** libtomcrypt RSA-2048
  verify on H743 @ 480 MHz takes well under 50 ms — fine for boot-time
  POST. Signing is not done on-device.

(Earlier ARCHITECTURE.md revisions said "mbedTLS RSA-3072 verify on
H743" in this section — both halves of that line were stale: mbedTLS
was never linked, and the key size is now RSA-2048 per ADR-016.)

---

## 4. Hardware platform — STM32H743/H753 specifics

### 4.1 What the chip provides

| Feature | STM32H743/H753 | What we use it for |
|---|---|---|
| **Internal flash** | 2 MB (H743) / 2 MB (H753) at `0x08000000` | Bootloader + application firmware + manifest |
| **OTP memory** | 1024 bytes (32 blocks × 32 bytes) at `0x08FFF000` | ~~Manufacturer public key (~422 bytes DER)~~ ⚠️ AMENDED 2026-05-04 (ADR-013) — **not used; pubkey lives in bootloader binary instead** |
| **Option bytes** | Configuration region (separate from flash) | ~~RDP level, BOOT pin behavior, write-protection~~ ⚠️ AMENDED 2026-05-04 (ADR-013) — **not modified by our provisioning; option bytes left at factory defaults** |
| **SWD/JTAG** | Standard ARM debug | Dev-time programming and debug |
| **System bootloader (DFU)** | ROM-resident DFU loader | Field firmware update via USB (open in dev, locked in production) |
| **Cryptographic accelerator (CRYP)** | AES, DES (hardware) | Not used today (libtomcrypt in software handles all device-side crypto) |
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
NOT provided by a runtime signature check.

~~It is provided by RDP Level 2 (the chip refusing all external flash
writes after burn).~~ ⚠️ **AMENDED 2026-05-04 (ADR-013).**
✅ **CURRENT:** It is provided by a **bootstrap-trust chain** (the only
path to write sector 0 is `bl_update` initiated from running,
manufacturer-signed app firmware) plus **tamper-evident sealing** of
the airframe and Cube enclosure (preventing the otherwise-required
SWD/JTAG access an attacker would need).

This is a different mechanism than Apple iPhone, Android with Secure
SoC, STM32MPU (MPU family with authenticating ROM), or STM32H5 (with
RSS — Root Secure Services). Those platforms have a Boot ROM that
verifies the bootloader's signature on every boot. STM32H743 does not.

The end property — *the bootloader running on a deployed unit is the
bootloader the manufacturer intended* — is the same. The mechanism
differs.

### 4.3 ~~OTP programming model~~ 🚫 RETIRED — see ADR-013

> **🚫 RETIRED 2026-05-04 (ADR-013).** OTP is no longer used for the
> trust anchor. The carrier we ship has no externally accessible BOOT0
> button; reaching SWD to run the OTP-programming sequence requires
> breaking the Hex factory seal. Original analysis preserved below for
> traceability.

~~STM32H7 OTP is **one-time-programmable at the bit level**:~~
- ~~Each bit can be flipped from 0 to 1 exactly once (a physical fuse blows)~~
- ~~Bits cannot be flipped back from 1 to 0 (no erase command exists)~~
- ~~Programming is via the standard flash interface (writes to OTP
  addresses), gated by an unlock sequence~~

~~**Implication for security:** an attacker cannot replace our OTP
contents with their own. They can only flip additional bits to 1,
which corrupts our public key. A corrupted key fails signature
verification — fail-closed. The attacker gains nothing.~~

~~We use ~14 of the 32 OTP blocks for the public key, leaving ~18
blocks (~576 bytes) free for future per-device data (e.g., per-device
AES key for flash encryption if BOOT004 is added later).~~

#### ✅ CURRENT — public-key deployment under ADR-013

The manufacturer RSA-2048 public key is **embedded in the bootloader
binary** at build time (and also in the application firmware binary
for UPD001 / manifest verification). Both copies are derived from the
same `pki/manufacturer/public/manufacturer_public.pem` source file by
the build pipeline; a discrepancy would be a build-time error.

The integrity property "an attacker cannot substitute their own
pubkey for ours" is preserved because:

- The bootloader binary is reachable for write only via `bl_update`,
  which only flashes the bootloader image bundled in a running,
  manufacturer-signed app fw's ROMFS (ADR-015) — so an attacker would
  already need the manufacturer's private key to push a bootloader
  with a substituted pubkey.
- The bootloader cannot be reached via SWD/JTAG without breaking the
  airframe + Cube tamper-evident seal (out-of-scope physical attacker
  class — ADR-013 threat model).
- DFU is software-refused by the secure bootloader (ADR-014), so an
  attacker with USB access cannot rewrite sector 0 via DFU.

### 4.4 ~~RDP Level 0/1/2 model~~ 🚫 RETIRED — see ADR-013

> **🚫 RETIRED 2026-05-04 (ADR-013).** RDP burn is no longer part of
> our provisioning sequence. Original analysis preserved below for
> traceability and for context if a future hardware platform with
> accessible BOOT0 (e.g., a custom carrier or STM32H5 migration —
> §14) brings RDP back into scope.

| Level | DFU writes | SWD/JTAG | Flash readout | Option-byte changes | Reversible? |
|---|---|---|---|---|---|
| ~~**RDP 0** (factory default)~~ | ~~Allowed~~ | ~~Allowed~~ | ~~Allowed~~ | ~~Allowed~~ | ~~Yes~~ |
| ~~**RDP 1**~~ | ~~Allowed~~ | ~~Limited (no flash read)~~ | ~~Blocked~~ | ~~Allowed~~ | ~~Yes (regression L1→L0 mass-erases flash, then chip is reusable)~~ |
| ~~**RDP 2**~~ | ~~**Blocked**~~ | ~~**Blocked**~~ | ~~**Blocked**~~ | ~~**Blocked**~~ | ~~**NO — permanent.**~~ |

~~**Production deployment burns RDP Level 2.** Once burned:~~
- ~~DFU bootloader still runs but rejects all flash writes~~
- ~~Debug probe cannot enumerate the target~~
- ~~External flash readout returns zeros~~
- ~~Option bytes themselves can no longer be changed (the L2 setting is
  itself frozen)~~

~~**The RDP burn is the most dangerous step in the deployment process.**
A typo in option-byte values during the L2 burn is permanent — the only
recovery is replacing the physical chip. This is why the
[RDP_BURN_RUNBOOK.md](RDP_BURN_RUNBOOK.md) (Phase 5b deliverable)
mandates an L1 rehearsal before L2 commit.~~

#### ✅ CURRENT — DFU/SWD closure without RDP

| Path | How it's closed under ADR-013/014 |
|---|---|
| **DFU** | Software DFU-refuse in the secure bootloader (ADR-014) — bootloader checks the secure-build flag at the DFU-entry decision point and returns immediately. No ROM DFU loader is invoked. |
| **SWD/JTAG** | Out-of-scope (physical attacker class). Reaching SWD pads requires opening the airframe AND the Cube enclosure, which visibly breaks the tamper-evident seal. RMA receipt with broken seal triggers quarantine + re-provisioning. |
| **Option-byte changes** | Not relied on. Option bytes are left at factory defaults; no provisioning step modifies them. |

**No irreversible burn step.** This eliminates the
"typo-bricks-the-unit" risk that motivated `RDP_BURN_RUNBOOK.md`. That
runbook is being marked historical (deliverable in next-session
step 6).

---

## 5. The chain of trust

### 5.1 The full chain (CubeOrange+ post-Phase 5b)

**🚫 RETIRED 2026-05-04 (ADR-013) — original (OTP + RDP L2):**

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

**✅ CURRENT 2026-05-04 (ADR-013/014/015) — bootstrap-trust + sealing:**

```
[Tamper-evident seal: airframe + Cube]  ← visibly broken on intrusion;
        │                                 enforced by RMA workflow
        ▼
[Bootloader binary in sector 0]         ← contains the manufacturer pubkey
        │ DFU entry: software-refused (ADR-014)
        │ SWD/JTAG: physically blocked by seal
        │ Sector-0 write: only via bl_update from running signed app fw
        │ verifies firmware signature on every boot (BOOT001)
        ▼
[Firmware: SIGNED by manufacturer]      ← bootloader checks the signature
        │ contains manifest-verify logic; uses pubkey embedded in firmware
        │ contains the secure bootloader image in ROMFS (ADR-015)
        │ verifies manifest signature on every boot (POST)
        ▼
[manifest.bin: SIGNED by manufacturer]  ← firmware checks the signature
        │ contains registered checksums (code_hash, data_hash, board_id)
        │ POST recomputes and compares
        ▼
[ARM gate]                              ← refuses to arm if any check failed
```

### 5.2 What protects each layer

**🚫 RETIRED 2026-05-04 (ADR-013) — original:**

| Layer | Protected by | Mechanism |
|---|---|---|
| ~~OTP pubkey~~ | ~~Silicon (write-once fuses)~~ | ~~Hardware-immutable; no erase command; only fail-closed corruption possible~~ |
| ~~Bootloader code~~ | ~~RDP Level 2 (BOOT003)~~ | ~~Chip refuses external flash writes — DFU dead, SWD dead~~ |
| ~~Bootloader trust anchor~~ | ~~OTP separation~~ | ~~Trust anchor lives in OTP, not bootloader code — a copied bootloader cannot substitute its own key~~ |
| Firmware code | Bootloader signature check (BOOT001) | Hashed and RSA-PSS-verified on every boot using ~~OTP pubkey~~ ✅ **bootloader-embedded pubkey** |
| Manifest | Firmware signature check (POST001) | RSA-PSS-verified on every boot using firmware-embedded pubkey (which was itself protected by the firmware sig check) |
| Arming decision | Manifest verification result | `commander` subscribes to `firmware_integrity_status` uORB; ARMING_DENIED if `check_passed=false` |

**✅ CURRENT 2026-05-04 (ADR-013/014/015):**

| Layer | Protected by | Mechanism |
|---|---|---|
| Tamper-evident seal | Operational (manufacturing + RMA workflow) | Serialized holographic / void-pattern seal on airframe AND Cube; UID + seal-serial recorded at manufacture; broken seal at RMA → quarantine |
| Bootloader binary | (a) Software DFU-refuse (ADR-014) (b) Tamper-evident seal blocking SWD/JTAG access (c) Bootstrap-trust (sector 0 write only via `bl_update` from running signed app fw — ADR-015) | The bootloader cannot be replaced by anyone holding less than the manufacturer's RSA-2048 private key + access to break the seal + access to sign a malicious app fw whose ROMFS contains the malicious bootloader |
| Bootloader trust anchor (manufacturer pubkey) | Embedded in bootloader binary | Modifying the embedded pubkey requires writing sector 0, which inherits the protections above |
| Firmware code | Bootloader signature check (BOOT001) | Hashed and RSA-PSS-verified on every boot using the bootloader-embedded pubkey |
| Manifest | Firmware signature check (POST001) | RSA-PSS-verified on every boot using firmware-embedded pubkey (which was itself protected by the firmware sig check) |
| Arming decision | Manifest verification result | `commander` subscribes to `firmware_integrity_status` uORB; ARMING_DENIED if `check_passed=false` |

### 5.3 Trust transitivity

**🚫 RETIRED 2026-05-04 (ADR-013) — original:**

~~Each layer's trust comes from:~~
1. ~~**OTP pubkey** ← silicon (root)~~
2. ~~**Bootloader integrity** ← RDP L2 silicon protection (root)~~
3. ~~**Firmware integrity** ← bootloader signature check, using #1~~
4. ~~**Embedded-in-firmware pubkey integrity** ← #3 (embedded pubkey
   can't be modified without breaking firmware signature)~~
5. ~~**Manifest integrity** ← firmware signature check, using #4~~
6. ~~**Registered checksum integrity** ← #5~~

~~The chain is rooted at two points: silicon (OTP and RDP) protects the
bootstrap (#1, #2); cryptography (RSA-3072 signatures) protects
everything downstream.~~

**✅ CURRENT 2026-05-04 (ADR-013/014/015):**

Each layer's trust comes from:

1. **Tamper-evident seal** ← operational (manufacturing + RMA), root
   for the physical-attacker class
2. **Bootloader integrity** ← bootstrap-trust (sector 0 only writable
   via `bl_update` from running signed app fw) + DFU-refuse (ADR-014)
   + sealed SWD access; root for the USB-attacker class
3. **Bootloader-embedded pubkey integrity** ← #2 (modifying it
   requires writing sector 0)
4. **Firmware integrity** ← bootloader signature check, using #3
5. **Embedded-in-firmware pubkey integrity** ← #4 (embedded pubkey
   can't be modified without breaking firmware signature)
6. **Manifest integrity** ← firmware signature check, using #5
7. **Registered checksum integrity** ← #6

The chain is rooted at two points: **operational integrity** (the
tamper-evident seal anchors the physical-attacker class) and
**cryptography** (RSA-2048 signatures + bootstrap-trust anchor the
USB-attacker class). All downstream layers (#3–#7) are
cryptographically protected.

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
  (now: factory bootloader hash check on receipt + first-install via
  `bl_update` at our trusted facility — ADR-015)
- ~~RDP Level 2 (BOOT003) physically preventing replacement post-burn~~
  ⚠️ AMENDED 2026-05-04 (ADR-013). ✅ **Bootstrap-trust chain**
  (sector 0 only writable via `bl_update` from running signed app fw)
  + **software DFU-refuse** (ADR-014) + **tamper-evident sealing**
  preventing replacement post-deployment.

The end property is the same; the mechanism differs from Apple/Android.

### 5.5 Why POST and ~~RDP L2~~ the chain-of-trust are both needed

> **🟡 AMENDED 2026-05-04 (ADR-013).** This section originally argued
> POST is required *in addition to* RDP L2. Under the amended
> architecture, POST is required *in addition to* the
> bootstrap-trust chain + tamper-evident seal + bootloader sig-verify.
> The argument structure is unchanged (POST catches failure modes that
> the upstream protection layer cannot see); only the upstream layer's
> name changes. Original framing struck where it specifically named
> RDP L2; the failure-mode analysis itself remains valid.

A natural question: if ~~RDP Level 2 prevents anyone from writing to
flash~~ ✅ **the bootstrap-trust chain prevents unauthorized writes
to sector 0 and the bootloader sig-verifies the firmware**, why do we
still need POST to verify firmware integrity at every boot? Doesn't
~~RDP L2~~ ✅ **the bootloader's sig-check** already guarantee that
what's in flash is what we put there?

**Short answer:** ~~RDP L2 prevents unauthorized external writes~~
✅ **the upstream layer (chain-of-trust + bootloader sig-verify) keeps
unauthorized firmware out**; POST verifies that what actually got
executed *and* its associated manifest and the chip's identity all
match what we expect. They protect against different failure modes
and together provide defense in depth.

#### Five failure modes the upstream layer cannot detect

| # | Failure mode | Why ~~RDP L2~~ ✅ the upstream layer misses it | Why POST catches it |
|---|---|---|---|
| 1 | Legitimate firmware update landed corrupt (interrupted write, MAVLink-FTP transmission error) | ~~RDP L2 sees an authorized internal write — no anomaly to flag~~ ✅ Bootloader sig-verify catches *signature* mismatch but a partial write may damage the manifest region without changing the firmware signature. POST hash recomputation catches it. | Bootloader sig-verify + POST hash recomputation fail; drone refuses to arm |
| 2 | Bit rot over fleet lifetime (cosmic ray, temperature cycling, flash wear) | ~~RDP L2 only watches write attempts, not stored-state integrity~~ ✅ Bootloader sig-verify catches firmware bit rot, but POST also re-checks code/data hashes against manifest values per-boot, defending against rot in regions the bootloader doesn't fully cover | SHA-256 mismatch detected at every boot |
| 3 | Wrong manifest installed on right firmware (factory or fleet-management error) | Both manifest and firmware are individually signed correctly — bootloader's firmware-signature check passes | POST004 board_id check catches the chip-vs-manifest mismatch |
| 4 | ~~Lab-grade defeat of RDP L2~~ ✅ Lab-grade physical attacker who breaks the seal + flashes via SWD (out of Level 1 scope) | ~~If RDP L2 is bypassed, attacker can write flash~~ ✅ Seal is broken (visible at RMA) and SWD write is possible | Bootloader still requires a manufacturer-signed firmware (signature impossible without private key); broken seal triggers operational quarantine on RMA receipt |
| 5 | Factory provisioning window (chip has stock factory bootloader between receipt and `bl_update`-driven secure-bootloader install) | ~~RDP L2 isn't burned yet — no protection~~ ✅ Stock factory bootloader trusts anything during the window | POST runs on first boot of our app fw; if firmware or manifest are wrong, factory tooling sees the failure before sealing the unit. Window is closed by the secure bootloader install + tamper-evident seal application step in the manufacturing runbook (ADR-015). |

#### Three structural reasons POST is required regardless

POST isn't a redundant check layered on top of RDP — it's a structural
component the rest of the system depends on:

| # | Structural role | What breaks without POST |
|---|---|---|
| A | **The arming gate's input** — `commander` reads `firmware_integrity_status` uORB to decide whether to allow arming (ARM001) | No publisher of `firmware_integrity_status` → ARM001 has nothing to gate on → drone arms with any firmware state |
| B | **The audit log's record of integrity events** — every boot writes a `POST_RESULT` entry (LOG001) | Audit log is silent on the most important security event of every flight; auditor has no boot-history record |
| C | **The auditor-visible runtime evidence** — ~~RDP L2 is invisible from outside (no easy way to confirm it's burned without specialized tooling)~~ ✅ tamper-evident seal + UID-record provide *static* evidence; POST publishes live `firmware_integrity_status` viewable in QGC, providing *runtime* evidence | Auditor cannot see runtime proof that integrity is being verified; only static evidence remains |

#### How the layers stack

**🚫 RETIRED 2026-05-04 (ADR-013) — original (RDP L2 at the top):**

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

**✅ CURRENT 2026-05-04 (ADR-013/014/015):**

```
Tamper-evident seal → physical write paths require visible damage   (preventive, operational)
   ↓
DFU-refuse + bootstrap-trust → unauthorized sector-0 writes blocked (preventive, software)
   ↓
Bootloader sig-verify → firmware signature verified pre-launch       (cryptographic, runtime)
   ↓
POST → manifest + checksums + board_id                                (cryptographic, runtime, auditable)
   ↓
ARM gate → preflight refuses if POST failed                           (operational, runtime)
   ↓
Audit log → POST_RESULT recorded per boot                             (evidence)
```

Each layer covers a different failure mode. Removing POST in favor of
"~~RDP L2~~ ✅ the upstream layer is enough" would break the arming
gate (no consumer for the integrity status), break the audit log (no
`POST_RESULT` entries), lose visibility for the auditor, lose detection
of all non-malicious corruption (bit rot, partial updates, manifest
mismatches), and reduce the chain to a single check (firmware
signature) with no runtime verification of the manifest or board-id
binding.

~~**RDP L2 prevents unauthorized writes. POST verifies what got
executed. Both are required.**~~ ✅ **The upstream layer
(seal + DFU-refuse + bootstrap-trust + bootloader sig-verify) keeps
unauthorized firmware out. POST verifies what got executed and that
the manifest and chip-identity match. Both are required.**

---

## 6. What gets signed, by whom, verified where

### 6.1 Artifact catalog

| Artifact | What it is | Signed by | Verified where | Verified when |
|---|---|---|---|---|
| **Application firmware** (`px4_fmu-v6x_default.bin` or equivalent) | The PX4 firmware binary | Manufacturer (RSA-2048 PSS, offline) | Bootloader on FC (libtomcrypt) | Every boot |
| **Bootloader** (`bootloader.bin`) | PX4 bootloader (Phase 5b patched version) | Manufacturer (RSA-2048 PSS, offline) | Factory programming tool (build-time only) | At factory flash; **not at runtime** on STM32H743 |
| **`manifest.bin`** | Binary blob with code_hash, data_hash, board_id, version, signature | Manufacturer (RSA-2048 PSS, offline) | Firmware POST module on FC (libtomcrypt) | Every boot |
| **`.fwbundle`** (update package) | Tar of firmware + manifest + signature | Manufacturer (RSA-2048 PSS, offline) | (a) QGC plugin client-side (BCrypt on Windows / OpenSSL elsewhere) and (b) FC `FirmwareUpdateGatekeeper` (libtomcrypt) | Pre-flash, before staging |
| **Audit log** (`audit_log.bin`) | Append-only event log on FC SD card | Encrypted SHA-256 hash signed per-file | Manufacturer offline tool (`verify_audit_log.py`, OpenSSL) | After log download |

### 6.2 What is NOT signed (and why it's OK)

| Not signed | Why OK |
|---|---|
| `firmware_integrity_status` uORB messages | Internal to FC; the ARM gate runs on the FC, so spoofing this message would require already-compromised firmware (and at that point the attacker has more direct attacks) |
| MAVLink telemetry to GCS | GCS display is informational only; arming gate is on-FC, not in GCS |
| Per-event audit log entries | The whole-file signing model (LOG001) covers integrity at log-download time; per-entry signing was rejected (DEV001 risk — would require a device-resident private key) |
| Individual flight parameters (most) | Compliance-critical params are protected by static compilation (PAR001 zero-window protection), not by signature |

### 6.3 Where the public key is embedded

The same public key appears in ~~three~~ ✅ **two** locations on a
deployed device:

| Location | Purpose | Updateable? |
|---|---|---|
| ~~**STM32H7 OTP**~~ | ~~Bootloader's trust anchor for verifying firmware~~ ⚠️ **RETIRED 2026-05-04 (ADR-013)** — OTP not used | ~~No (write-once)~~ |
| **Bootloader binary** | ✅ **CURRENT:** bootloader's trust anchor for verifying firmware (BOOT001). The bootloader binary is shipped inside the app fw ROMFS and self-installed via `bl_update` (ADR-015). | Yes — replaced with a new bootloader flash (which can only happen via a manufacturer-signed app fw, ADR-015) |
| **Application firmware** (header file `manufacturer_pubkey.h`) | Firmware's trust anchor for verifying manifest and update bundles | Yes (with firmware update) |

~~All three copies~~ ✅ **Both copies** are the same key. Discrepancy
would mean a build error (the build pipeline derives all copies from
`pki/manufacturer/public/manufacturer_public.pem`).

---

## 7. Boot sequence — step by step

This is what happens on a CubeOrange+ post-Phase 5b on every power-on or
reset.

**🚫 RETIRED step 4 (OTP read) — see ADR-013. ✅ CURRENT in step 4 below: bootloader uses its own embedded pubkey symbol. All other steps unchanged.**

```
1. Power applied / reset pin released
2. CPU begins execution at the bootloader entry point in flash (0x08000000).
   This is fixed by hardware — the CPU has no way to skip the bootloader.
3. Bootloader initializes minimum required hardware (clocks, RAM).
4. RETIRED: Bootloader reads the manufacturer RSA-3072 public key from
   the OTP region (e.g. 0x08FFF000-0x08FFF3FF). OTP read is via
   memory-mapped I/O, internal to the chip.
   CURRENT (ADR-013): Bootloader uses its own embedded RSA-2048 public
   key symbol (manufacturer_pubkey[], compiled into the bootloader
   binary at build time from pki/manufacturer/public/manufacturer_public.pem).
   No OTP access; the symbol is in code flash adjacent to the verify routine.
5. Bootloader reads the application firmware's signature (appended at a
   known offset in the firmware image, or stored in a small metadata
   block immediately after the firmware).
6. Bootloader computes SHA-256 over the application firmware region
   (e.g. 0x08020000 to firmware_end). libtomcrypt performs the hash.
7. Bootloader runs:
       RSA-PSS-Verify(embedded_pubkey, sha256(firmware), signature)
   libtomcrypt performs the signature verification.

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
- ~~Step 4: OTP read is internal to the chip; cannot be intercepted~~
  ✅ **Step 4 (CURRENT, ADR-013):** the embedded pubkey symbol lives
  inside the bootloader binary's code section; modifying it requires
  rewriting sector 0, which requires either (a) DFU (refused by ADR-014
  software check), (b) SWD (blocked by tamper-evident seal — broken
  seal triggers RMA quarantine), or (c) `bl_update` from a malicious
  app fw (impossible without the manufacturer's private key, since
  app fw is sig-verified at every boot)
- ~~Step 7: bypassing this requires either (a) modifying the bootloader
  (blocked by RDP L2), (b) glitching the CPU at the verify branch
  (out of Level 1 scope), or (c) substituting the OTP pubkey
  (physically impossible — write-once fuses)~~
  ✅ **Step 7 (CURRENT, ADR-013/014/015):** bypassing this requires
  either (a) modifying the bootloader (blocked by the same three
  protections as step 4), (b) glitching the CPU at the verify branch
  (out of Level 1 scope), or (c) substituting the embedded pubkey
  (same as modifying the bootloader)
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
- ~~**Post-BOOT003 state:** RDP Level 2 disables DFU writes at the chip
  level. DFU bootloader still runs but its commands are rejected by
  silicon. Path A is fully closed.~~ ⚠️ **AMENDED 2026-05-04 (ADR-014).**
- ✅ **Post-ADR-014 state:** the secure bootloader software-refuses
  DFU mode entry. The ROM DFU loader is never invoked, so the host
  PC cannot enumerate a DFU device. Path A is fully closed at the
  software layer. SWD remains blocked operationally by the
  tamper-evident seal (out-of-scope physical attacker class).

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
| Path A (DFU) | Nothing — OPEN GAP | BOOT001 (firmware refuses to launch) + ~~BOOT003 (DFU dead)~~ ✅ **ADR-014 software DFU-refuse** |
| Path B (MAVLink-FTP) | UPD001 (QGC + FC verify) | UPD001 + BOOT001 (bootloader re-verify) |

After Phase 5b, **every byte of code the CPU executes was signed by
the manufacturer's RSA-2048 private key**, regardless of which path
delivered it.

### 8.4 ~~How updates work on a chip locked by RDP L2~~ How updates work under the bootstrap-trust architecture

> **🟡 AMENDED 2026-05-04 (ADR-013/015).** This section originally
> explained how UPD001 + BOOT001 work despite RDP L2's external-write
> block. Under the amended architecture there is no RDP L2 burn, but
> the **same internal-vs-external distinction still matters** for the
> bootloader's tamper-evident-sealing argument: external writes are
> blocked by software DFU-refuse + sealing, internal writes (from
> running signed app fw) are how updates legitimately happen.

A common question: ~~"If RDP L2 blocks all flash writes, how do
firmware updates get installed?"~~ ✅ **"If DFU is refused and SWD is
sealed, how do firmware updates get installed?"** The answer hinges on
a critical distinction that's easy to miss.

~~**RDP L2 blocks EXTERNAL writes (DFU bootloader, SWD/JTAG debugger).
It does NOT block writes initiated by RUNNING TRUSTED FIRMWARE on the
chip itself.**~~ ✅ **The bootstrap-trust architecture blocks
EXTERNAL writes (DFU bootloader, SWD/JTAG debugger via the seal). It
does NOT block writes initiated by RUNNING TRUSTED FIRMWARE on the
chip itself, because internal writes go through code that is itself
signature-verified.**

| Who's writing | Mechanism | Blocked under ADR-013/014? |
|---|---|---|
| Host PC via DFU bootloader (`dfu-util` etc.) | External — USB → ROM bootloader → flash peripheral | ✅ Yes — secure bootloader software-refuses DFU mode entry (ADR-014); ROM DFU loader is never invoked |
| Debug probe via SWD/JTAG | External — debug interface → flash peripheral | ✅ Yes — out-of-scope physical attacker; tamper-evident seal must be visibly broken to reach SWD pads |
| Running PX4 firmware writing to flash | Internal — CPU executes flash-write instructions on the FLASH peripheral | ❌ No, allowed — but the running firmware is itself sig-verified by the bootloader on every boot, so an attacker can't get malicious code into this position |

This is the same model every modern locked-down device uses (iPhone,
Android with locked bootloader, Tesla, modern automotive ECUs). The
chip is "selectively writable by entities holding the right key" —
not "completely write-protected."

#### The actual update flow under the bootstrap-trust architecture

```
1. Manufacturer signs new firmware bundle (.fwbundle) offline with private key
2. Operator downloads .fwbundle, opens QGroundControl
3. QGC client-side verifies bundle signature (UPD001 client check)
4. QGC uploads .fwbundle to FC via MAVLink-FTP
   ↓
5. Running PX4 firmware on FC receives the bundle via FirmwareUpdateGatekeeper
6. PX4 firmware verifies the bundle signature using libtomcrypt + embedded
   manufacturer pubkey (UPD001 drone-side check)
7. PX4 firmware writes the new firmware to a STAGING flash region using
   the STM32 HAL flash-write functions
   ← THIS WRITE WORKS because it is initiated by trusted firmware
     already running on the CPU itself; sealing only blocks external
     write paths (DFU/SWD)
8. PX4 firmware writes the new manifest.bin to its flash region
9. PX4 firmware sets a "boot from staged firmware on next reset" flag
10. FC reboots
   ↓
11. Bootloader runs (the same secure bootloader installed at factory
    via bl_update; cannot be replaced without the manufacturer's
    private key — ADR-013/015)
12. Bootloader sees the staged-firmware flag, points at the new region
13. Bootloader hashes the new firmware, verifies signature against
    embedded manufacturer pubkey (ADR-013)
14a. PASS → bootloader launches new firmware. Update successful.
14b. FAIL → bootloader rolls back to previous firmware (A/B partition pattern)
```

The crucial security property: **the only entity that can deliver a
working firmware update is one holding the manufacturer's RSA-2048
private key.** ~~Even though RDP L2 allows internal writes,~~ ✅ Even
though running firmware can write flash internally, an attacker cannot
push an update because:

- They cannot sign the bundle (no private key)
- The running firmware refuses to write the bytes if signature check
  fails (UPD001 step 6)
- The bootloader refuses to launch the new firmware if signature check
  fails (BOOT001, step 13)
- Both verifications use ~~the OTP-resident pubkey~~ ✅ **the
  bootloader/firmware-embedded pubkey** (ADR-013), which cannot be
  replaced without already holding the private key

The update path is open *for legitimate updates* and closed *for
unauthorized ones* — the property we want.

#### ~~What CANNOT be updated post-RDP-L2~~ What can/cannot be updated under the bootstrap-trust architecture

> **🟡 AMENDED 2026-05-04 (ADR-013/015).** The original section
> claimed the bootloader is "deliberately unupdatable" via WRP +
> RDP L2. Under the amended architecture, the bootloader **is
> updatable** — but only via `bl_update` initiated from a running,
> manufacturer-signed app fw (ADR-015). The end property is the same
> from an attacker's perspective: nothing without the manufacturer's
> private key can change the bootloader. From the manufacturer's
> perspective, the new architecture is *more flexible* — bootloader
> bugs can be patched in the field via a signed app fw update.

~~Some flash regions need additional protection beyond RDP — using
**WRP (Write Protection)**, a separate per-sector option-byte
setting that blocks ALL writers including running firmware:~~

**🚫 RETIRED — original (RDP L2 + WRP) regions table:**

| Region | Protection | Updatable post-RDP-L2? |
|---|---|---|
| ~~Application firmware (~1.5 MB)~~ | ~~RDP L2 only — no WRP~~ | ~~✅ Yes (via UPD001)~~ |
| ~~`manifest.bin` region~~ | ~~RDP L2 only — no WRP~~ | ~~✅ Yes (via UPD001)~~ |
| ~~Staging region (A/B partition)~~ | ~~RDP L2 only — no WRP~~ | ~~✅ Yes (where new firmware lands during update)~~ |
| ~~Audit log region~~ | ~~RDP L2 only — no WRP~~ | ~~✅ Yes (firmware appends entries)~~ |
| ~~**Bootloader region (~128 KB)**~~ | ~~RDP L2 + **WRP**~~ | ~~❌ **No — deliberately unupdatable**~~ |
| ~~OTP pubkey~~ | ~~Hardware write-once silicon fuses~~ | ~~❌ No~~ |
| ~~RDP setting in option bytes~~ | ~~Frozen by RDP L2 itself~~ | ~~❌ No~~ |

**✅ CURRENT (ADR-013/015) — flash regions and what can update them:**

| Region | Protection | Updatable in the field? | Update mechanism |
|---|---|---|---|
| Application firmware (~1.5 MB) | Software DFU-refuse + bootloader sig-verify on next boot | ✅ Yes | UPD001 (signed `.fwbundle` via QGC + MAVLink-FTP) |
| `manifest.bin` region | Bootloader sig-verify of fw covers manifest verify by transitivity | ✅ Yes | UPD001 (manifest is part of the bundle) |
| Staging region (A/B partition) | Same as app fw region | ✅ Yes | Internal write by signed app fw during UPD001 |
| Audit log region | Append-only by signed app fw; LOG001 sig-of-file at download | ✅ Yes | Internal append by signed app fw |
| **Bootloader region (~128 KB, sector 0)** | (a) Software DFU-refuse (ADR-014) (b) Tamper-evident seal blocking SWD (c) Bootstrap-trust: only `bl_update` from signed app fw can write sector 0 | ✅ **Yes**, but only by manufacturer-signed app fw via `bl_update` (ADR-015) | Bundle a new bootloader image in the next signed app fw's ROMFS; operator runs `bl_update` from QGC; old bootloader is replaced after sig-verify. |
| ~~OTP pubkey~~ | ~~Not used~~ | n/a | n/a |
| ~~Option bytes (RDP/WRP)~~ | ~~Not modified — left at factory defaults~~ | n/a | n/a |

The **bootloader region is updatable, but only by the manufacturer**.
Every byte of the chain (sector 0, app fw, manifest) is reachable for
write only by code that itself was signed with the manufacturer's
RSA-2048 private key. The trade-offs:

- **Pro:** the trust anchor of the chain (the bootloader that does
  verification) cannot be replaced by anyone holding less than the
  manufacturer's private key + ability to ship a signed app fw
- **Pro:** a compromise of the firmware-signing process *can* be
  weaponized to push a malicious bootloader (this is a real change
  vs. WRP-locked-bootloader; mitigated by keeping the private key
  offline + key-ceremony controls — ADR-001's residual risk)
- **Pro (vs. retired):** a critical bug found in the bootloader after
  deployment **can** be patched in the field via a signed app fw
  update; affected units do not need physical replacement
- **Con:** the bootloader's integrity rests on the same private key
  as everything else (no "physically immutable" anchor); accepted
  because adding hardware immutability is not feasible on this
  carrier (ADR-013 forcing function)

This is the same trade-off ArduPilot accepts. The flexibility is
deliberate.

#### ~~Phase 5b implication~~ Phase 5b implementation under the amended architecture

~~Phase 5b's BOOT001 (verifying bootloader) and BOOT003 (RDP L2 burn)
together require the bootloader region to be WRP-locked as part of the
factory provisioning sequence. The full sequence:~~

~~1. Flash bootloader to chip~~
~~2. Flash application firmware~~
~~3. Flash manifest.bin~~
~~4. Program OTP with manufacturer pubkey (BOOT002)~~
~~5. Burn WRP on bootloader sectors (locks bootloader against all writers)~~
~~6. Burn RDP Level 2 (closes external write paths)~~

~~After step 6, the chip is in production mode: the bootloader is
permanent, OTP is permanent, RDP is permanent, and the only way to
update the application firmware is via UPD001 with a manufacturer-signed
bundle.~~

✅ **CURRENT (ADR-013/014/015) — Phase 5b reduces to:**

1. **Receive** CubeOrange+ from Hex with stock factory bootloader.
2. **Verify factory bootloader hash** against a known-good reference
   (closes the supply-chain trust window before our first install).
3. **Flash first app fw** via standard QGC firmware load (the stock
   factory bootloader accepts unsigned fw — this is the trust window
   we close immediately after).
4. **MAVLink `flashbootloader`** triggers `bl_update`: running app fw
   extracts the secure bootloader from its ROMFS and writes it to
   sector 0.
5. **Reboot.** Secure bootloader is now in flash.
6. **Verify secure bootloader hash** by reading sector 0 over USB
   (one-shot — the secure bootloader will refuse this once DFU-refuse
   is active, so this is read via the running app fw or the stock
   bootloader before step 4).
7. **Load production app fw** (signed). Secure bootloader verifies
   on next boot (BOOT001).
8. **Verify signature enforcement** by attempting to load an unsigned
   app fw — confirm rejection.
9. **Apply tamper-evident seal** to airframe + Cube enclosure.
10. **Record** STM32 96-bit UID + seal serial in QMS.
11. **Ship.**

After step 11, the chip is in production mode: the bootloader is
manufacturer-replaceable but not attacker-replaceable, and the only
way to update the application firmware is via UPD001 with a
manufacturer-signed bundle.

The detailed manufacturing runbook is being written as a separate
deliverable (`Docs/MANUFACTURING_RUNBOOK.md`, next-session step 5).

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
| **Securely** | RSA-2048 signed by manufacturer; tamper detected by signature verification at every boot |
| **Cannot be updated without authorization** | Only the manufacturer (holder of the private key) can produce a `manifest.bin` whose signature the FC will accept. An attacker can rewrite the bytes, but the result will fail signature verification → POST fails → drone refuses to arm. |

**The auditor walk-through:**
1. Show `manifest.bin` location in flash (`hexdump`).
2. Show that any byte modification → POST fails → `firmware_integrity_status.check_passed=false` → arming blocked. (SITL acceptance step 5, ✅.)
3. Show that the only update paths for the manifest are:
   - UPD001 (signed bundle through MAVLink-FTP) — gated by signature
   - BOOT001 firmware update (signed firmware containing new manifest) — gated by signature
   - ~~DFU (Path A) — closed by BOOT003 in production~~ ✅ **DFU (Path A) — closed by software DFU-refuse in the secure bootloader (ADR-014); SWD path blocked by tamper-evident sealing of airframe + Cube (ADR-013)**
4. Show that the trust anchor ~~(OTP pubkey)~~ ✅ **(bootloader-embedded pubkey)** cannot be replaced ~~(write-once silicon)~~ ✅ **without already holding the manufacturer's private key (sector 0 only writable via `bl_update` from a running, signed app fw — ADR-015)**.

This is a **stronger property** than the audited reference's flash encryption
approach. the audited reference hides the storage so attackers can't read or coherently
write to it. We expose the storage but cryptographically authenticate
it. Either approach satisfies the requirement.

### 9.2 Other DGCA requirements (summary)

Detailed mapping is in [SECURITY_PLAN.md](../SECURITY_PLAN.md). Quick summary:

| DGCA topic | Our requirement IDs | Status |
|---|---|---|
| Root of Trust | ROT001, ROT002, ~~BOOT002~~ | ✅ Done (key infra); ~~⏳ BOOT002 hardware~~ ⚠️ **BOOT002 retired 2026-05-04 (ADR-013)** — pubkey now in bootloader binary, no OTP burn |
| Firmware checksums | CHK001 | ✅ Done |
| Signed firmware | SIG001, PKG001 | ✅ Done |
| POST | POST001/002/003/004 | ✅ Done (SITL); ⏳ hardware |
| Arming gate | ARM001 | ✅ Done |
| Secure update | UPD001 | ✅ Done; SITL steps 11/12 pending |
| Parameter protection | PAR001 | ✅ Done |
| Audit logging | LOG001 | ✅ Done |
| GCS-FC pairing | PAIR001 | ✅ Done (SITL) |
| Bootloader hardening | BOOT001 + ~~BOOT003~~ ✅ ADR-014 (DFU-refuse) + ADR-015 (bl_update install) | ⏳ Phase 5b under amended architecture (BOOT003 retired 2026-05-04, ADR-013) |

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

**🚫 RETIRED 2026-05-04 (ADR-013) — original (OTP-resident pubkey):**

```
[OTP: RSA-3072 public key]   ← write-once
        │ used by bootloader to verify
        ▼
[Plain flash, signed firmware]   ← readable, but tampering detectable
        │ contains
        ▼
[manifest.bin — RSA-3072 signed]   ← any modification breaks signature
```

**✅ CURRENT 2026-05-04 (ADR-013):**

```
[Bootloader binary: RSA-2048 public key embedded]   ← compiled in
        │ used by bootloader to verify firmware
        ▼
[Plain flash, signed firmware]   ← readable, tampering detectable
        │ contains
        ▼
[manifest.bin — RSA-2048 signed]   ← any modification breaks signature
        │ + tamper-evident seal blocks SWD; bl_update is the only sector-0 write path
```

Our protection is **authenticity-based**:
- Attacker can read the checksums (they're public values — `SHA-256(firmware)`)
- Attacker can write replacement bytes, but the result fails signature verification
- ~~RDP L2 blocks external write paths anyway~~ ✅ **Software DFU-refuse + tamper-evident sealing block external write paths anyway (ADR-013/014)**

### 10.3 Why our approach is sufficient (and arguably better) for DGCA Level 1

| Property | the audited reference approach | Our approach |
|---|---|---|
| **DGCA §4.1.2 requirement (storage authorization)** | ✅ Met via confidentiality | ✅ Met via authenticity |
| **Confidentiality of firmware bytes** | ✅ Provided | ❌ Not provided (~~RDP L2 blocks readout~~ ✅ tamper-evident seal blocks SWD-readout, but flash bytes are not encrypted) |
| **Auditability** | Harder (auditor can't easily inspect what's in flash without the key) | Easier (auditor can `hexdump` and compare to known-good) |
| **Standard pattern** | Vendor-specific | Matches Apple/Android/UEFI signed-boot ✅ + ArduPilot |
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
confidentiality requirement. ~~RDP Level 2 provides the practical
equivalent (flash unreadable from outside) for Level 1 deployment.~~
✅ **AMENDED 2026-05-04 (ADR-013):** the tamper-evident seal provides
the practical equivalent of "flash unreadable from outside without
visible tampering" for Level 1 deployment; readout via SWD requires
breaking the seal, which triggers operational quarantine.

~~If we add BOOT004 later, the OTP has ~576 bytes of free space (after
the ~422-byte pubkey takes ~14 of 32 blocks) — plenty for a per-device
AES-256 key and metadata. The architecture is forward-compatible.~~
⚠️ **AMENDED 2026-05-04 (ADR-013):** OTP is no longer used for the
pubkey, so the full 1024 bytes are available for any future per-device
data (e.g., per-device AES key). Adding BOOT004 later would also
require revisiting the hardware-access constraint (current carrier has
no accessible BOOT0 / SWD without breaking the seal); a productization
phase that adds flash encryption likely also moves to a custom carrier
or to STM32H5/U5 (§14).

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
| ~~**Inofly (this project)** on STM32H743~~ | ~~RSA-3072 pubkey in STM32H7 OTP~~ | ~~**No** — bootloader integrity from RDP L2, not runtime sig check~~ | ~~DGCA Level 1~~ |
| **Inofly (this project)** on STM32H743 ✅ **CURRENT 2026-05-04 (ADR-013), key-size amended 2026-05-06 (ADR-016)** | RSA-2048 pubkey **embedded in bootloader binary** | **No** — bootloader integrity from **bootstrap-trust chain + tamper-evident sealing**, not runtime sig check (same constraint as before: STM32H743 has no authenticating Boot ROM) | DGCA Level 1 |
| **ArduPilot** (production firmware, multi-vendor) | Up to 10 RSA pubkeys embedded in bootloader binary | **No** — bootloader integrity from chain-of-trust + (optional) software DFU-refuse | Hundreds of thousands of fielded units (the architectural pattern we adopted in ADR-013) |
| **the audited reference (audit reference)** | AES-128 in OTP + RSA pubkey embedded in firmware | (Bootloader stores firmware hash; design unclear from reference) | Reference implementation |

**Key observation:** every production secure-boot system roots trust
in silicon **or in an operationally-controlled boot chain**. The
mechanism varies (Boot ROM signature check vs. ~~RDP write-protection
of the bootloader region~~ ✅ bootstrap-trust + tamper-evident
sealing), but the property is the same — **the bootloader on a
deployed unit is the bootloader the manufacturer intended, and an
attacker cannot replace it.**

~~Our STM32H743 deployment uses RDP L2 to provide that property.~~
✅ **Our STM32H743 deployment uses bootstrap-trust + tamper-evident
sealing to provide that property** (forced by the
no-accessible-BOOT0 carrier constraint — ADR-013). If we move to
STM32H5/U5 in the future (§14), we'll get the silicon-verified-bootloader
pattern as well, "for free."

This is **not a novel architecture.** It is the mainstream pattern,
validated by billions of production devices (Apple/Android/UEFI) and
hundreds of thousands of fielded ArduPilot units.

---

## 12. Architecture Decision Log

This section records the major architectural decisions, with date,
rationale, and alternatives considered. Append-only — supersession is
recorded as a new entry referencing the old one.

### ADR-001 — Single RSA-2048 keypair for everything (2026-04-15) ⚠️ Deployment sub-claim amended 2026-05-04 by ADR-013 (no OTP) · ⚠️ Key size amended 2026-05-06 by ADR-016 (RSA-3072 → RSA-2048)

**Decision:** Use one manufacturer keypair for firmware signing,
manifest signing, update-bundle signing, AND audit-log encryption.
Private key offline at manufacturer; public key embedded in firmware
~~and (Phase 5b) burned to OTP~~ ✅ **and (Phase 5b under amended
architecture) embedded in the bootloader binary as well — see ADR-013**.
The single-keypair core decision is unchanged.

**Alternatives considered:**
- Separate firmware-signing and log-signing keypairs — rejected. More
  keys to manage with no security gain.
- Separate per-device keys — rejected. Would require device-resident
  private keys (DEV001 risk), more complex provisioning, no audit
  precedent.

**Rationale:** Simpler operational model; RSA supports both signing
and public-key encryption; compromise scenarios are not worse with one
key than with multiple.

### ADR-002 — ~~RSA-3072 (not RSA-2048)~~ (2026-04-15) ⚠️ **REVERSED 2026-05-06 by ADR-016 — production now uses RSA-2048**

> **🟡 SUPERSEDED 2026-05-06 (ADR-016).** The original decision below
> chose RSA-3072 over RSA-2048 for beyond-2030 NIST headroom. ADR-016
> reverses that choice: production now uses **RSA-2048** for smaller
> on-device artifacts (especially in the bootloader sector-0 budget)
> and tighter alignment with the the audited reference audit reference. The
> RSA-vs-ECDSA half of this ADR (single primitive supporting both
> sign and public-key-encrypt) is **unchanged** and still load-bearing.
> Original text preserved below for traceability.

~~**Decision:** Use RSA-3072 PSS for all signatures.~~

~~**Alternatives considered:**~~
- ~~RSA-2048 (the audited reference reference uses this) — rejected. NIST
  recommends 3072+ for use beyond 2030.~~
- ECDSA P-256 — rejected. Doesn't support public-key encryption,
  would require additional crypto layer for audit-log use case.
  *(This rationale is unchanged under ADR-016 — RSA is still chosen
  over ECDSA for the same reason.)*

~~**Rationale:** Future-proof against NIST lifecycle; modest
performance cost on STM32H7 (~50 ms verify); single primitive for both
signing and encryption.~~

### ADR-003 — Bootloader integrity from RDP L2, not runtime signature check (2026-04-29) ⚠️ SUPERSEDED 2026-05-04 by ADR-013

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

### ADR-005 — libtomcrypt on NuttX, OpenSSL on host/SITL (2026-03-20, library-name corrected 2026-05-07)

> **📝 Doc fix 2026-05-07.** Earlier revisions of this ADR named
> **mbedTLS** as the on-device library. That was always wrong — PX4
> already links **libtomcrypt** (for RSA) and **monocypher** (for
> Ed25519); mbedTLS was never in the tree. The substantive decision
> ("MCU-sized crypto on device, OpenSSL on host") is unchanged. The
> Path C bootloader (BOOT001) extends the same already-linked
> libtomcrypt to sector 0 — no new crypto dependency was ever added.

**Decision:** Use **libtomcrypt** for all cryptographic operations on
embedded hardware (NuttX RTOS — both app firmware and the verifying
bootloader); use OpenSSL for host-side tooling and
SITL.

**Alternatives considered:**
- libtomcrypt everywhere — rejected. OpenSSL is the host-side standard
  with better Python bindings (via the `cryptography` package).
- mbedTLS on hardware — rejected. Would have meant adding a fresh
  crypto dependency to NuttX when libtomcrypt is already linked. Some
  earlier planning material named mbedTLS without checking what PX4
  actually ships; that wording is corrected.
- OpenSSL everywhere — rejected. OpenSSL is too large for MCU flash
  budget.

**Rationale:** Both libraries implement RSA-PSS / SHA-256 with full
interoperability. libtomcrypt is sized for MCU and is already linked
into PX4 — no new dependency, and reusing the linked subset minimizes
bootloader sector-0 footprint (the binding constraint per ADR-016).
Using libtomcrypt on device + OpenSSL on host gives best-of-both
without expanding the device dependency surface.

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

### ADR-010 — Two update paths, both gated (2026-04-29) ⚠️ AMENDED 2026-05-04 — Path A mechanism replaced by ADR-014; Path B unchanged

**Decision:** Path A (DFU) closed by BOOT003 (RDP L2 disables DFU
writes); Path B (MAVLink-FTP) gated by UPD001 (signed bundle) +
BOOT001 (bootloader re-verify on next boot).

**Rationale:** Defense in depth. Even a hypothetical bug in
UPD001's signature check would be caught by the bootloader. Path A
has no in-firmware mitigation possible (DFU runs from ROM, bypassing
the firmware), so chip-level lockdown (RDP L2) is the only defense.

### ADR-011 — RDP Level 2 mandatory for production (2026-04-29) ⚠️ SUPERSEDED 2026-05-04 by ADR-013

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

### ADR-013 — Bootstrap-trust + tamper-evident sealing (2026-05-04, supersedes ADR-003 and ADR-011, amends ADR-001 deployment sub-claim)

**Decision:** Replace the OTP-resident public-key trust anchor and the
RDP Level 2 silicon write-lockdown with a **bootstrap-trust chain +
tamper-evident sealing** model:

- **Public key location.** RSA-2048 manufacturer pubkey is embedded in
  the **bootloader binary** (and continues to be embedded in app fw
  for UPD001 / manifest verification). No OTP burn. Single-keypair
  decision (ADR-001) is unchanged; only the deployment mechanism for
  the public copy moves from "OTP" to "compiled into the bootloader."
- **Bootloader integrity at runtime.** Not cryptographically verified
  at runtime (STM32H743 has no authenticating Boot ROM — same
  constraint as ADR-003). Integrity is instead provided by:
  1. **Bootstrap-trust:** a malicious bootloader cannot be installed
     because the only path to write sector 0 is `bl_update` initiated
     from a running, manufacturer-signed app fw (see ADR-015).
  2. **Tamper-evident sealing:** airframe + Cube enclosure are sealed
     with serialized holographic / void-pattern seals at our facility
     before shipping. Reaching SWD/JTAG to bypass `bl_update` requires
     visibly breaking those seals.
  3. **Serial-number tracking:** STM32 96-bit UID + seal serial recorded
     at manufacture; mismatch on RMA receipt is auditable.
- **DFU path closure.** Software check in the secure bootloader
  refuses DFU mode entry — see ADR-014.

**Forcing function (hardware constraint):** CubeOrange+ as shipped by
Hex has no externally accessible BOOT0 button on the carriers we use.
Reaching SWD or DFU pins requires opening the airframe **and** the Cube
enclosure, which breaks the Hex factory seal. Consequently, OTP write,
RDP Level 2 burn, and WRP option-byte set — all of which require BOOT0
+ SWD access during factory provisioning — are operationally infeasible.

**Threat model boundary (explicit):**

- **IN scope, fully blocked cryptographically:** USB-only attackers
  (remote, opportunistic, supply-chain-after-our-seal). The signed
  bootloader + signed firmware + UPD001 chain rejects any unauthorized
  artifact. Software DFU-refuse (ADR-014) closes Path A.
- **OUT of scope at the cryptographic layer:** physical attacker who
  disassembles the airframe AND the Cube enclosure. Compensated
  procedurally by:
  - Tamper-evident seal on airframe AND Cube — visibly broken on
    intrusion.
  - RMA inspection workflow — units returning with broken seals are
    quarantined and not re-flown without re-provisioning.
  - Serial-number tracking via STM32 96-bit UID, recorded at
    manufacture and cross-checked at RMA.
- **Supply-chain trust caveat (first install):** the chip ships from
  factory with the standard PX4 bootloader, which trusts anything.
  Mitigations: (a) verify factory bootloader hash on receipt at our
  facility before first install, (b) perform first install at our
  trusted facility, (c) ship sealed.

**Alternatives reconsidered:**

- **Original OTP + RDP plan (ADR-003, ADR-011).** Rejected on the
  hardware-access constraint above. The plan was sound on paper; it
  cannot be executed on the carriers we ship.
- **Switch hardware to STM32H5 (with RSS / authenticating Boot ROM)
  or STM32U5 (with TrustZone-M + SFI).** Deferred — board procurement,
  BSP work, and timeline impact are all significant. See §14.
- **Procure an alternative CubeOrange+ carrier with accessible BOOT0.**
  Investigated; no Hex SKU exposes BOOT0 by default. Custom carrier
  redesign would compromise the "Hex-blessed enclosure" story we want
  for productization.
- **Adopt ArduPilot's full crypto choice (Ed25519, 10 keys).** Rejected.
  - Ed25519: LOG001's "FC pubkey-encrypts log hash, manufacturer
    decrypts offline" trick relies on RSA's asymmetric encryption
    capability; Ed25519 has no equivalent primitive. Cost of staying
    on RSA: ~25–35 KB extra in app fw vs Ed25519 under RSA-2048
    (originally estimated ~40–50 KB under RSA-3072 — see ADR-016).
    Acceptable.
  - 10-key model: appropriate for ArduPilot's multi-vendor ecosystem,
    not for a single-manufacturer deployment.
- **Adopt ArduPilot's architectural pattern (embedded keys + ROMFS
  bootloader + DFU refusal) without switching to Ed25519.** **Selected.**

**Rationale:** End property is the same as RDP L2 ("the bootloader on
a deployed unit is the manufacturer's bootloader, and an attacker
cannot replace it") via a different mechanism (chain of trust +
sealing instead of silicon lockdown). This is the mainstream
ArduPilot production pattern, validated across hundreds of thousands
of fielded units. It also gives us a credible "we use the same
security architecture as ArduPilot" story for the auditor.

**What this does NOT change:**

- Single-keypair decision (ADR-001 core)
- RSA-PSS scheme (ADR-002, key size later amended to RSA-2048 by ADR-016 — orthogonal to this ADR)
- libtomcrypt on NuttX, OpenSSL on host (ADR-005's substantive intent)
- LOG001 per-file RSA log signing (ADR-006)
- PAR001 static parameter compilation (ADR-007)
- PAIR001 MAVLink signing (ADR-008)
- POST in app fw (SITL) and bootloader (hardware) (ADR-009) — the
  bootloader is still the verifier on hardware, just trusted via a
  different mechanism
- BOOT001 (verifying bootloader) — kept; this is the load-bearing
  cryptographic check
- ADR-004 (no flash encryption) — unchanged
- UPD001 — unchanged

**What this DOES retire:**

- BOOT002 (OTP pubkey programming) — removed
- BOOT003 (RDP Level 2 burn) — removed
- WRP-locking the bootloader region — removed (not applicable when
  there's no RDP burn step)
- RDP_BURN_RUNBOOK.md — to be marked historical

**Prior-art citations:**

- ArduPilot signed-firmware design: github.com/ArduPilot/ardupilot
  Tools/scripts/signing/README.md — *"installing a bootloader with up
  to 10 public keys included"*; *"the flight controller will refuse a
  switch to DFU mode if it is running a secure bootloader already"*
- ArduPilot bootloader update flow: ardupilot.org/copter/docs/common-bootloader-update.html
  — *"the ArduPilot specific bootloader is included within the
  ArduPilot firmware but it lies dormant by default"*; flashed via
  Mission Planner "Bootloader Update", QGC "Flash ChibiOS Bootloader",
  or MAVProxy `flashbootloader`.

### ADR-014 — Secure bootloader refuses DFU mode (2026-05-04, supersedes ADR-010 Path A)

**Decision:** The secure (signed) variant of the PX4 bootloader
contains a software check that **refuses to enter DFU mode** when it
is the bootloader currently in flash. The check runs before the
DFU-entry condition (BOOT pin, magic-word, watchdog escape, etc.) is
evaluated.

**Mechanism (planned):** model after ArduPilot's secure-bootloader
DFU-refuse. A build-time flag (`#define INOFLY_SECURE_BL`) guards a
compile-time refusal that returns from the DFU-entry path immediately
when set. The flag is set in the production bootloader build target
and unset in dev builds.

**Why this works as Path A closure:**

- An attacker with USB access **cannot** enter DFU because the running
  bootloader actively refuses — the ROM DFU loader is not invoked.
- An attacker **cannot** flash via SWD/JTAG because the airframe + Cube
  enclosure are sealed (out-of-scope physical attacker class — see
  ADR-013 threat model).
- An attacker **cannot** push a malicious app fw via UPD001 because
  UPD001 verifies signatures with the manufacturer pubkey.
- An attacker **cannot** push a malicious bootloader via `bl_update`
  because `bl_update` only flashes the ROMFS-embedded bootloader image
  out of a *running* app fw, and the running app fw is itself
  signature-verified by the existing bootloader (ADR-015 chain).

**Alternatives considered:**

- **Trust app fw to clear the DFU-entry condition on every boot.**
  Rejected. The bootloader is the right layer because it is the only
  entity that runs before a hostile app fw could prevent the check.
  Putting the check in app fw makes a bootloader-only attack surface
  larger.
- **Physically de-pad the BOOT pin in factory.** Rejected. Irreversible
  hardware modification; risks Hex warranty / certification claims;
  not a software-controllable fallback if the policy needs to change.

**Rationale:** Same end property as BOOT003 (RDP L2 disables DFU)
through a software mechanism that is feasible without breaking the
Hex factory seal. ArduPilot uses this pattern in production; our
deployment can follow the same path.

### ADR-015 — bl_update / ROMFS-bundled bootloader as install path (2026-05-04, reverses 2026-05-03 disable)

**Decision:** The secure bootloader binary is **bundled inside the
application firmware as a ROMFS asset** (PX4's existing `bl_update`
mechanism, ArduPilot equivalent). The first install — and any future
bootloader updates — flow via the MAVLink `flashbootloader` command:
running app fw reads the bootloader image out of its own ROMFS,
writes it to sector 0, reboots.

**This reverses** the 2026-05-03 decision to disable `bl_update` for
size reasons. Under the amended architecture, `bl_update` is the
install path, not optional bloat.

**Install / update flow:**

1. **First install** (factory provisioning at our facility):
   - Receive CubeOrange+ from Hex, sealed, with stock PX4 bootloader.
   - **Verify the factory bootloader hash** against a known-good
     reference. (Mitigates the "factory bootloader trusts anything"
     supply-chain caveat.)
   - Flash our **first app fw** via the standard QGC firmware load
     (the stock factory bootloader accepts any unsigned fw — this is
     the supply-chain trust window we close immediately after).
   - Trigger MAVLink `flashbootloader` from QGC. Running app fw
     extracts the **secure bootloader** from its ROMFS and writes it
     to sector 0.
   - Reboot. The secure bootloader is now in flash.
   - Verify the secure bootloader's hash by reading sector 0 over USB
     (one-shot; the secure bootloader will refuse this once
     DFU-refuse is active in production).
   - Load the **production app fw** (signed). The secure bootloader
     verifies its signature on next boot (BOOT001).
   - Verify signature enforcement by attempting to load an unsigned
     app fw — confirm rejection.
   - **Apply tamper-evident seal** to airframe + Cube enclosure.
   - Record STM32 96-bit UID + seal serial in QMS.
   - Ship.
2. **Field bootloader update** (if ever needed): same path —
   manufacturer-signed app fw containing the new bootloader in ROMFS
   → MAVLink `flashbootloader` → reboot. Field bootloader updates are
   gated by the app fw's own signature, so a malicious bootloader
   cannot be pushed without the manufacturer's private key.

**Implications:**

- `bl_update` must remain **enabled** in `cubeorangeplus_default.px4board`
  (or a project-specific board variant). The 2026-05-03 disable patch
  is reversed.
- App fw size budget gains the ROMFS-embedded bootloader (~44 KB
  baseline, growing with Path C / RSA-PSS extension to ~100 KB+).
  If app fw overflows under bl_update enabled, manage size by
  **stripping unused PX4 modules** (using the categorized strip list
  in project memory: `fw_*`, `vtol_*`, `rover_*`, `airship_*`, etc.),
  **not** by disabling bl_update.
- A separate `cubeorangeplus_inofly.px4board` may be created to hold
  the strip list (rather than modifying default), if upstream-fork
  hygiene matters.

**Rationale:** matches ArduPilot's production pattern and is the only
install path that closes the supply-chain trust window without
external programming hardware. Bundling the bootloader in app fw is
the standard PX4 capability — we are using the platform's intended
mechanism, not building a custom one.

### ADR-016 — RSA-2048 (reverses ADR-002 RSA-3072 choice) (2026-05-06, supersedes ADR-002)

**Decision:** Migrate the manufacturer keypair from **RSA-3072** to
**RSA-2048**. RSA-PSS scheme (SHA-256 hash, MGF1-SHA256, salt length
32) is unchanged. Single-keypair decision (ADR-001) is unchanged.
Embedded-pubkey deployment (ADR-013) is unchanged. The change is
scoped to key size only.

**What changes mechanically:**

- Modulus / private key size: 3072 bits → 2048 bits
- Signature size: 384 bytes → 256 bytes
- SubjectPublicKeyInfo DER size: ~422 bytes → ~294 bytes
- All consumers updated in lockstep across the three repos
  (inoflyTools host signers + tests, PX4 fork bootloader and
  secure_boot module, inoflyGCU QGC plugin)

**Rationale:**

- **Smaller artifacts where it matters most.** Bootloader sector 0
  on STM32H743 is 128 KB. The libtomcrypt RSA bignum routines and
  the embedded pubkey are both larger under RSA-3072; RSA-2048 frees
  bootloader headroom that we want to keep available for future
  bootloader features without forcing module strips on the app fw
  side. App fw artifact size also drops (smaller embedded pubkey,
  smaller signature in the manifest, smaller `.fwbundle`).
- **Audit alignment.** the audited reference and the audited reference reference designs both use
  RSA-2048. Matching them removes an explanation step in the auditor
  conversation ("why are you stronger than the reference?") and
  removes RSA-3072 as a *differentiator we have to defend* in audit.
- **Sufficiency.** RSA-2048 satisfies DGCA Level 1's authenticity
  requirement. NIST SP 800-57 still considers RSA-2048 acceptable
  through 2030; we are inside that window. If we need to extend
  beyond 2030, the migration path is clear (re-key + re-sign + ship
  a new bootloader via `bl_update`).

**Alternatives considered:**

- **Stay on RSA-3072** — the original ADR-002 choice. Rejected for the
  artifact-size and audit-alignment reasons above; the beyond-2030
  argument is real but is more cleanly handled by a future re-key
  than by carrying the larger key today.
- **Move to ECDSA P-256 / Ed25519 to shrink artifacts further.**
  Rejected for the same reason as ADR-002 originally rejected ECDSA:
  LOG001 needs RSA's public-key-encryption capability, and we want
  one primitive across signing and log encryption.

**What this does NOT change:**

- ADR-001 (single keypair) — still single keypair
- ADR-002 RSA-vs-ECDSA decision — still RSA (only the bit-length
  changes)
- ADR-005, ADR-006, ADR-007, ADR-008 — unchanged
- ADR-013/014/015 (bootstrap-trust + sealing + bl_update) — unchanged
- PSS scheme parameters: SHA-256 hash, MGF1-SHA256, **salt length 32
  bytes** (project-wide convention, applied to every signer and
  verifier in the chain)

**Migration status:** Code-complete and committed across all three
repos as of 2026-05-06 (host) / 2026-05-07 (QGC plugin + saltlen
unification). Documentation sweep (this ADR + body-text rewrite of
RSA-3072 references) completed in the same batch.

---

### ADR-017 — secure_boot module crypto bring-up on app firmware (2026-05-10, deferred decision)

**Status:** Open. Decision deferred pending the trade-off below. Code
state: nothing landed; working tree is reverted to pre-session.

**Context.** Until 2026-05-10, the `secure_boot` PX4 module had been
authored, unit-tested on host, and validated in SITL — but had never
been compiled into a CubeOrange+ app firmware image. The flag
`CONFIG_MODULES_SECURE_BOOT=y` was missing from
`boards/cubepilot/cubeorangeplus/default.px4board`. Adding that flag,
together with the libtomcrypt include path the pickup memory said was
the only other prerequisite, surfaced a chain of integration gaps that
none of host tests, SITL builds, or the existing bootloader build
exercise.

**The dependency chain we discovered (in build-failure order).**

1. **Stack frame overflow in `SecurityAuditLogger::_updateLogSignature`.**
   libtomcrypt's `rsa_key` is a 5-`mp_int` aggregate, and TomsFastMath's
   `mp_int` is a fixed-size struct (~3.4 KB). With `prng_state` and
   `hash_state` also stack-allocated, the function frame totals ~18.9 KB
   — overshooting NuttX's `-Wframe-larger-than=2048` by ~9.2×. The
   POSIX/SITL build did not catch this because OpenSSL's `EVP_PKEY` API
   heap-allocates internally. Fix shape: move `rsa_key key` and
   `prng_state prng` to function-local `static` storage (the method is
   driven serially by a single `px4::WorkItem`, so non-reentrant
   storage is safe; ~17 KB relocates from work-queue stack to BSS).
   This is a real defect that would have surfaced regardless of the
   bring-up question.

2. **libtomcrypt header path missing.** The PX4 module build context
   does not run `Make.defs`, so `<tomcrypt.h>` is unresolved. Fix:
   `target_include_directories(modules__secure_boot PRIVATE
   ${PX4_SOURCE_DIR}/src/lib/crypto/libtomcrypt/src/headers)`. (Note:
   `target_link_libraries` PUBLIC propagation does *not* satisfy this
   for the target shape `px4_add_module` produces — explicit include is
   required.)

3. **libtomcrypt CMake target undefined.** `src/lib/crypto/CMakeLists.txt`
   is gated `if(DEFINED PX4_CRYPTO)`. `PX4_CRYPTO` is set only when
   `CONFIG_BOARD_CRYPTO=y` is in the board config. The bootloader sets
   it; app fw does not. Without the gate triggered, the `libtomcrypt`
   and `libtommath` targets are never created, so
   `target_link_libraries(modules__secure_boot PRIVATE libtomcrypt
   libtommath)` resolves to bare `-llibtomcrypt -llibtommath` flags
   that the linker cannot satisfy.

4. **PX4 platform-layer cascade.** Setting `CONFIG_BOARD_CRYPTO=y`
   defines `PX4_CRYPTO`, which makes
   `platforms/common/include/px4_platform_common/crypto.h` get included
   transitively by every translation unit that touches the px4 layer
   (`px4_init.cpp`, `px4_crypto.cpp`, …). That header pulls in
   `crypto_backend_definitions.h` (requires `CONFIG_DRIVERS_SW_CRYPTO=y`)
   and `keystore_backend_definitions.h` (requires
   `CONFIG_DRIVERS_STUB_KEYSTORE=y`), which in turn requires
   `CONFIG_PUBLIC_KEY0=...` in the board config pointing at a public-key
   file. **secure_boot does not use any of these abstractions** — it
   calls libtomcrypt directly with the manufacturer pubkey embedded via
   our own `manufacturer_pubkey.h`. Riding the framework adds two
   parallel key paths and ~?? KB of code.

5. **`px4_random` also gated.** libtomcrypt's `sprng` PRNG calls
   `px4_get_secure_random` provided by the `px4_random` target, which is
   defined in `platforms/nuttx/src/px4/common/CMakeLists.txt` under the
   same `if(DEFINED PX4_CRYPTO)` gate, and links `nuttx_crypto`.

6. **NuttX kernel config.** `nuttx_crypto` is a NuttX subsystem
   library; it is built only when `CONFIG_CRYPTO=y` is in the NuttX
   defconfig. CubeOrange+'s `nuttx-config/nsh/defconfig` (app fw) does
   **not** set this. The bootloader's defconfig does. Enabling the
   subsystem on app fw is a kernel-config change requiring `make ...
   boardconfig` regeneration.

7. **PRNG choice.** libtomcrypt's `rsa_encrypt_key_ex` with
   `LTC_PKCS_1_V1_5` requires a registered PRNG to generate padding
   bytes. With our use case (RSA-encrypt-with-PUBLIC-key as a cheap
   unforgeable signature variant — the security property is "only
   manufacturer's private key can decrypt", not confidentiality), the
   padding randomness does not affect security. A deterministic or
   weakly-seeded PRNG is acceptable; using `sprng` ties us to layers
   5+6 above.

**FLASH context.** Last clean CubeOrange+ build (secure_boot OFF) is
1,916,460 / 1,966,080 B (97.48 %). Each layer above adds bytes. We do
not have a measured budget for the full bring-up; FLASH overflow is a
plausible outcome and would force another round of PX4 module strips
(see `project_root_cause_romfs_bootloader_bloat` memo).

**Why this is an ADR rather than a fix.** Two paths have meaningfully
different long-term consequences and the choice has not been made:

- **Path α — Bypass.** Keep `secure_boot` self-contained. Either lift
  the `if(DEFINED PX4_CRYPTO)` gates in `src/lib/crypto/CMakeLists.txt`
  and `platforms/nuttx/src/px4/common/CMakeLists.txt` (smallest patch,
  modifies upstream-aligned files in our fork) **or** inline the
  required libtomcrypt + libtommath sources into a private
  `secure_boot_crypto` library inside the module (largest patch,
  isolated to our directory). In either sub-variant, also enable
  `CONFIG_CRYPTO=y` in `nuttx-config/nsh/defconfig` and pick a PRNG
  that does not require `nuttx_crypto`'s `getrandom()`. Pro: no
  parallel key path; pro: clean conceptual separation between PX4's
  crypto framework and our compliance module. Con: we maintain crypto
  wiring our fork doesn't share with upstream.

- **Path β — Ride PX4's framework.** Set `CONFIG_BOARD_CRYPTO=y` +
  `CONFIG_DRIVERS_SW_CRYPTO=y` + `CONFIG_DRIVERS_STUB_KEYSTORE=y` +
  `CONFIG_PUBLIC_KEY0=...` pointing at our manufacturer pubkey, and
  enable `CONFIG_CRYPTO=y` in NuttX. Accept ~?? KB of framework code
  and the existence of two parallel key paths (PX4 `keystore_backend`
  and our embedded `manufacturer_pubkey.h`). Pro: uses PX4-blessed
  wiring; matches the pattern the audited reference-style audits expect. Con:
  bigger FLASH cost on a 97.48 %-full image; con: two key paths
  invite drift.

**Decision.** Deferred. To be made before the next attempt at landing
secure_boot on hardware. Resume from a clean working tree and a chosen
path; do not re-discover this chain mid-build.

**What this does change:**

- The pickup-memory line *"libtomcrypt symbols should already be in
  NuttX's libcrypto.a so no link-time change should be needed"* is
  retired. That is true for the **bootloader** build (which sets
  `CONFIG_BOARD_CRYPTO=y` so `BOARD_CRYPTO=tomcrypt` injects the
  symbols), not for app fw.
- Layer 1 (`SecurityAuditLogger` frame-size) is a real defect
  independent of this decision and should land regardless.
- Whichever path is chosen, `CONFIG_MODULES_SECURE_BOOT=y` cannot land
  by itself — it co-lands with the chosen crypto bring-up.

**What this does NOT change:**

- ADR-001 through ADR-016 are unaffected. The bring-up is a **build
  integration** problem, not an architecture change. The chain of
  trust, key model, signing scheme, and bootstrap-trust mechanism are
  all unchanged.

---

## 13. Residual risks (acknowledged)

The architecture defends against software-level attacks and
production-grade physical attacks. It does NOT defend against:

| Risk | Why we accept it | Mitigation outside Level 1 scope |
|---|---|---|
| **Manufacturer private key compromise** | Operational, not technical. Same risk class as every PKI-based ecosystem (Apple, Microsoft, Google all have this exposure). | HSM, key ceremony, access controls, periodic key rotation if compromised |
| **Lab-grade fault injection** (voltage glitch, EM injection, clock glitch at the verify branch) | Out of DGCA Level 1 threat scope. Requires equipment and expertise of nation-state-level adversary. | HSM-class silicon (e.g., STM32U5 with TrustZone-M anti-glitch) — future hardware option |
| ~~**Chip decap and OTP rewriting**~~ ✅ **Chip decap (and rewrite of bootloader-embedded pubkey)** | Physically possible in a state-of-the-art lab; out of Level 1 scope. ⚠️ AMENDED 2026-05-04 (ADR-013) — OTP no longer used; the equivalent attack is decap + rewrite of the bootloader-binary region of internal flash, same out-of-scope class. | Same — silicon with OTP tamper detection / anti-decap (e.g., STM32U5) |
| **Supply chain compromise** (malicious code injected into PX4 source before signing) | Not a software-attack-against-the-device vector; mitigated operationally. | Reproducible builds, code review, controlled build host |
| ~~**Dev boards (RDP 0)** | RDP L0 dev units have full SWD/JTAG/DFU exposure. We accept this for development; production units have RDP L2 burned. | Operational segregation (dev units never flown in regulated airspace)~~ ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Dev boards (no seal, dev-build bootloader without DFU-refuse):** dev units have full SWD/JTAG/DFU exposure; production units have software DFU-refuse + tamper-evident seal. Same operational segregation (dev units never flown in regulated airspace). | Same — operational segregation |
| **Confidentiality of firmware bytes** | Not a Level 1 requirement. ~~RDP L2 provides practical readout protection.~~ ✅ **Tamper-evident seal provides practical readout protection (SWD readout requires visibly breaking the seal, triggering RMA quarantine).** | Add BOOT004 (flash encryption) for productization or Level 2/3 |
| ✅ **Manufacturer-signed malicious-bootloader push** (new under ADR-013/015) | A compromise of the firmware-signing process *can* be weaponized to push a malicious bootloader via `bl_update`, because sector 0 is no longer WRP-locked. Same risk class as the "Manufacturer private key compromise" row above; not a separate residual unless the signing process is segmented. | HSM-only signing of `bl_update`-bundling app fw releases; release-process review; out-of-band hash comparison of bootloader bytes vs. last release |

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
- Single RSA-2048 keypair (re-key to RSA-3072/4096 or Ed25519 if needed — see ADR-016 for migration playbook)
- Manifest format and signing process
- POST logic and ARM-gate wiring
- LOG001 audit-log signing approach
- PAR001 static parameter compilation
- PAIR001 MAVLink signing
- Manufacturer toolchain (signing, packaging, factory provisioning)

What changes per chip family:
- Bootloader implementation (verifier vs verified-by-Boot-ROM)
- OTP layout (different sizes, different addresses) — currently
  unused on H743 (ADR-013); could be re-enabled on a chip with
  accessible BOOT0 / SWD
- Lockdown mechanism: ~~RDP L2~~ on H743 → **bootstrap-trust + tamper-evident seal** (ADR-013); on H5 → RSS-managed lockdown; on U5 → "device closed" bit
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
| 1.2 | 2026-05-04 | Partial amendment. Added amendment notice (top), flagged lockdown rows L4/L5/L12/L13 as superseded, added new lockdown rows L14/L15, marked ADR-003/010/011 with supersession pointers, appended ADR-013 (bootstrap-trust + tamper-evident sealing), ADR-014 (software DFU-refuse), ADR-015 (bl_update / ROMFS-bundled bootloader). Forcing function: CubeOrange+ has no externally accessible BOOT0 button on shipped carriers, making OTP write / RDP burn / WRP option-byte set operationally infeasible. **Convention:** retired material in §3–§11 is rendered in `~~strikethrough~~` (or a 🚫 RETIRED label for code-block diagrams that markdown won't strike) and immediately followed by an ✅ CURRENT replacement block. Sections touched: §1 (lockdown table + open-items list), §2.1, §2.2, §3.2, §4.1, §4.2, §4.3 (full strike + current), §4.4 (full strike + current), §5.1 (diagram strike + current), §5.2, §5.3, §5.4, §5.5 (entire RDP framing relabeled, all 5 failure modes amended, layers-stack diagram strike + current), §6.3, §7 (boot sequence step 4, attacker-cannot-skip steps 4 + 7), §8.1 (Path A post-state), §8.3 (gating table Path A row), §8.4 (full strike + current update flow + post-RDP regions table + Phase 5b sequence), §9.1 (auditor walk-through), §9.2 (root-of-trust + bootloader-hardening rows), §10.2 (deviation diagram strike + current), §10.3 (table cells), §10.4 (BOOT004 + OTP space note), §11 (Inofly comparison row + new ArduPilot row + key-observation paragraph), §13 (residual risks: chip-decap, dev-boards, confidentiality rows + new manufacturer-signed-malicious-bootloader-push row), §14.4 (per-chip-family change list), Appendix A→companion-docs table (RDP_BURN_RUNBOOK.md retired pointer), ADR-001 (deployment sub-claim amendment). |
