# Threat Model — Inofly UAS Firmware Security

**Document version:** 1.1
**Date:** 2026-04-29
**Scope:** DGCA Level 1 Type Certification — Firmware Manufacturer
**Framework:** Adapted from STRIDE for embedded UAS systems

**Changes since 1.0:**
- Added threats T10–T13 covering bootloader, OTP, and physical-debug
  attack surfaces (the Phase 5b gap)
- New Section 7: "Attack Tree — Secure Boot Bypass Analysis" walks
  through every plausible bypass and what stops it
- New Section 8: "Prior Art" cites comparable architectures (Apple,
  Android Verified Boot, STM32MPU ROM, UEFI)
- New Section 9: glossary of hardware-security terms used in this doc
  (DFU, SWD/JTAG, OTP, RDP, option bytes)

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

### T10 — DFU (Path A) bootloader bypass

| Field | Value |
|-------|-------|
| **Attack** | Attacker holds the BOOT button while plugging in USB. STM32H7 enters its built-in DFU bootloader, which flashes any image presented over `dfu-util` without checking signatures. UPD001 protects only the MAVLink-FTP path (Path B) — DFU runs from ROM and never invokes our firmware. |
| **Impact** | Arbitrary firmware on flight controller; full compromise. |
| **Likelihood** | High with physical USB access; trivial tooling (`dfu-util` is open source). |
| **Mitigations** | BOOT001 (custom bootloader re-verifies firmware signature on every boot — DFU-flashed unsigned firmware will not launch on next reboot), BOOT003 (RDP Level 2 disables the DFU bootloader at the chip level — USB DFU enumerator simply does not respond). |
| **Residual risk** | Currently HIGH (Phase 5b not shipped). After BOOT001: LOW (firmware refuses to launch). After BOOT003: NONE (DFU dead at chip level). |

### T11 — Custom bootloader replacement

| Field | Value |
|-------|-------|
| **Attack** | Attacker uses DFU or SWD to overwrite our bootloader with one that returns "signature OK" without actually verifying. The replaced bootloader then launches arbitrary firmware. |
| **Impact** | Bypasses the entire chain of trust — every downstream check (firmware sig, manifest sig, POST, ARM gate) is performed by attacker-controlled code. |
| **Likelihood** | High pre-RDP (DFU and SWD both writable); requires physical port access. |
| **Mitigations** | BOOT003 (RDP Level 2 disables DFU writes AND SWD/JTAG writes at the chip level — no remaining external write path to the bootloader region). The bootloader's trust anchor (manufacturer pubkey) lives in OTP, not in the bootloader binary, so even a copied bootloader cannot substitute its own key. |
| **Residual risk** | HIGH on dev boards (RDP 0 — accepted, dev-only). NONE on production units after RDP L2 is burned. This is the single strongest argument for why production hardware MUST go through Phase 5b's RDP burn. |

### T12 — OTP public-key tampering

| Field | Value |
|-------|-------|
| **Attack** | Attacker attempts to overwrite the manufacturer public key in OTP with their own pubkey, then signs malicious firmware with the matching private key. |
| **Impact** | Would defeat the entire root of trust — bootloader would happily verify attacker-signed firmware. |
| **Likelihood** | Physically impossible once our pubkey is programmed. |
| **Mitigations** | OTP is one-time-programmable at the silicon level: bits flip 0→1 once, never 1→0. After we write our pubkey, an attacker can only flip additional bits to 1, which corrupts our key bytes (signature verify fails — fails closed, drone won't boot, but attacker gains nothing). |
| **Residual risk** | NONE — hardware-enforced. Compromise would require chip decap and physical rewriting of OTP fuses, which is outside DGCA Level 1 threat scope and well into nation-state-actor territory. |

### T13 — Debugger-based runtime verification skip

| Field | Value |
|-------|-------|
| **Attack** | Attacker attaches an SWD/JTAG debugger, halts the CPU at the signature-verify call inside the bootloader, forces the comparison result to "pass," resumes execution. Bootloader then launches malicious firmware. |
| **Impact** | One-off bypass per boot; persists only for that session unless attacker also writes flash. |
| **Likelihood** | Requires physical access + debug probe (~$20 hardware) on dev boards. Impossible after RDP L2. |
| **Mitigations** | BOOT003 (RDP Level 2 permanently disables SWD/JTAG — debug probe cannot enumerate the target). On dev boards (RDP 0), this remains an accepted risk. |
| **Residual risk** | HIGH on dev boards — accepted because dev units are not flown in regulated airspace. NONE on production units after RDP L2. |

---

## 4. Risk Summary

| Threat | Current Risk | After Full Implementation |
|--------|-------------|--------------------------|
| T1 — Firmware modification | **Low** | Low |
| T2 — Manifest tampering | **Low** | Low |
| T3 — Key compromise | **Medium** (dev) | Low (HSM in production) |
| T4 — Unsigned update (Path B) | **Low** ✅ UPD001 done | Low |
| T5 — Audit log tampering | **Low** ✅ LOG001 done | Low |
| T6 — Parameter tampering | **Low** ✅ PAR001 done | Low |
| T7 — Telemetry spoofing | **Low** | Low |
| T8 — Flash corruption | **Low** | Low |
| T9 — Board ID mismatch | **Medium** | Low |
| T10 — DFU (Path A) bypass | **High** (Phase 5b open) | Low (BOOT001) → None (BOOT003) |
| T11 — Bootloader replacement | **High** (RDP 0) | None (RDP L2) |
| T12 — OTP key tampering | **None** | None (hardware-enforced) |
| T13 — Debugger verify skip | **High** (RDP 0) | None (RDP L2) |

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
| T10 | BOOT001, BOOT003 | Secure Boot, Tamper Resistance |
| T11 | BOOT003 | Tamper Resistance (chip-level lockdown) |
| T12 | BOOT002 | Root of Trust (immutable trust anchor) |
| T13 | BOOT003 | Tamper Resistance |

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
- HSM / offline key storage correctly implements key isolation; private
  key never leaves controlled storage
- PX4 NuttX kernel is not compromised (trusted computing base)
- SD card is accessible to an attacker with physical access to the drone
- Production hardware will have RDP Level 2 burned before deployment in
  regulated airspace; dev boards remain at RDP 0 with that acknowledged
  as out-of-scope for production threat assumptions

---

## 7. Attack Tree — Secure Boot Bypass Analysis

This section answers the auditor's question: *"Walk me through every
way an attacker could get unsigned code running on the flight
controller, and show me what stops each one."*

### 7.1 The chain of trust

Once Phase 5b ships, the trust chain on a CubeOrange+ is:

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
        │ verifies manifest signature on every boot
        ▼
[manifest.bin: SIGNED by manufacturer]  ← firmware checks the signature
        │ contains registered checksums (code_hash, data_hash, board_id)
        │ POST recomputes and compares
        ▼
[ARM gate]                              ← refuses to arm if any check failed
```

**Important note on terminology.** Industry literature often says "signed
bootloader" to mean a bootloader whose own signature is verified by silicon
below it (Boot ROM). Apple iPhone, Android with a Secure SoC, STM32MPU, and
STM32H5 with RSS all work that way. The STM32H743/H753 used on CubeOrange+
does **not** have an authenticating Boot ROM — its system bootloader is a
DFU loader that doesn't verify anything. Our BOOT001 is therefore a
**verifying bootloader** (it checks the firmware's signature) rather than a
*signed-and-verified-at-boot* bootloader. The bootloader's own integrity is
guaranteed by:

- Factory-controlled flashing of a known-good bootloader binary
- RDP Level 2 (BOOT003) physically preventing replacement post-burn

We additionally sign the bootloader binary at build time so factory tooling
can verify it before programming, but no runtime check on this signature
happens on this chip. This is a different mechanism than Apple/Android but
provides the same property: the bootloader running on a deployed unit is
the bootloader we intended.

Each layer's trust anchor is protected by the layer above it (or by
hardware):
- The OTP pubkey is protected by the silicon (write-once fuses)
- The bootloader code is protected by RDP Level 2 (chip refuses external
  flash writes)
- The firmware code is protected by the bootloader (signature check on
  every boot)
- The manifest is protected by the firmware (signature check in POST)
- The arming decision is protected by the manifest (POST result drives
  the ARM gate)

### 7.2 Boot sequence in detail

On every power-on or reset of a Phase-5b-ready CubeOrange+:

1. CPU begins execution at the bootloader entry point in flash
   (typically `0x08000000`). This is fixed by the chip's reset
   vector — the CPU has no way to skip the bootloader.
2. Bootloader initializes minimal hardware (clocks, RAM).
3. Bootloader reads the manufacturer RSA-3072 public key from the
   STM32H7 OTP region (e.g. `0x08FFF000`–`0x08FFF3FF`). Read access
   to OTP is via memory-mapped I/O, internal to the chip — no
   external path can intercept or modify this read.
4. Bootloader reads the application firmware's signature (appended at
   a known offset in the firmware image).
5. Bootloader computes SHA-256 over the application firmware region.
6. Bootloader runs RSA-PSS-Verify(pubkey_from_OTP, SHA-256(firmware),
   signature). mbedTLS performs the math.
7. **PASS:** bootloader executes a `BX` jump to the firmware reset
   vector. Firmware now controls the CPU.
   **FAIL:** bootloader logs the failure to a known flash region,
   drives an error-LED pattern, and halts (or enters a recovery-only
   mode that accepts only signed firmware). The drone never arms.
8. Firmware boots. The `secure_boot` module runs POST: re-hashes the
   running code/data sections, verifies the manifest signature using
   a manufacturer pubkey embedded in the firmware (validated
   transitively because the firmware itself was signature-verified
   in step 7), publishes `firmware_integrity_status` uORB.
9. The `commander` module reads `firmware_integrity_status`. If
   `check_passed=false`, it adds `ARMING_DENIED: firmware integrity`
   to the preflight checks. Pilot cannot arm.

### 7.3 Bypass attempts and what stops them

The following table enumerates every plausible bypass path. Each row
shows the attack, the layer that stops it, and the residual risk.

| # | Attack | Stopped by | Residual risk |
|---|--------|-----------|---------------|
| 1 | Replace firmware via MAVLink-FTP (over the air or USB through QGC) | UPD001 (QGC + FC verify .fwbundle signature) AND BOOT001 (bootloader re-verifies on next boot) | Requires manufacturer private key |
| 2 | Replace firmware via stock STM32 DFU (USB + BOOT button) | BOOT001 (firmware refuses to launch on next boot) AND BOOT003 (DFU disabled at chip level) | None after RDP L2 |
| 3 | Replace bootloader itself with one that skips verification | BOOT003 (RDP L2 disables both DFU and SWD writes — no external write path to bootloader region) | None after RDP L2; bootloader's trust anchor is in OTP, not in bootloader code, so even a copied bootloader cannot substitute its own key |
| 4 | Tamper with `manifest.bin` only (claim attacker firmware's hashes) | POST001 manifest signature check (any change invalidates the RSA-PSS signature) | Requires manufacturer private key |
| 5 | Patch firmware binary to swap the embedded manifest-verify pubkey | BOOT001 (any change to firmware bytes breaks its own signature) | Requires manufacturer private key |
| 6 | Overwrite the OTP-resident pubkey with attacker's pubkey | OTP write-once silicon (T12) — bits cannot be erased; setting more bits to 1 corrupts our key, fails closed | None — hardware-enforced |
| 7 | Use SWD/JTAG debugger to halt CPU and force the verify result to "pass" | BOOT003 (RDP L2 permanently disables SWD/JTAG) | None on production units; accepted on dev boards |
| 8 | Voltage / clock / EM glitch at the verify branch (fault injection) | Out of DGCA Level 1 scope. RDP L2 raises the equipment bar (no debug header to attack electrically). | Acknowledged residual risk; mitigation requires HSM-class silicon |
| 9 | Forge an RSA-3072 signature without the private key | Cryptography (NIST recommends RSA-3072 past 2030; ~2^128 work to brute-force) | Out of practical reach |
| 10 | Compromise the manufacturer's private key | Operational controls: HSM / offline storage, key ceremony, access controls | Single point of failure for any PKI-based system; same exposure as Apple/Microsoft/Google software signing |
| 11 | Supply chain — inject malicious code into PX4 source before signing | Out of secure-boot scope. Mitigated by reproducible builds, code review, controlled build host | Acknowledged; not a software-attack-against-the-device vector |

### 7.4 The property the chain guarantees

> Every byte of code the CPU executes was authored by a party
> holding the manufacturer's RSA-3072 private key, verified at boot
> against a public key physically fused into the chip and unreachable
> from any software path.

The two genuine residual risks are:
1. **Manufacturer key compromise** — operational, not technical.
   Same risk class as every signed-software ecosystem on earth.
2. **Lab-grade physical attack** (chip decap, advanced fault
   injection) — out of DGCA Level 1 scope.

Everything else either fails-closed or is impossible without breaking
either RSA-3072 or the silicon itself.

### 7.5 Why flash encryption is not required

the audited reference reference architectures use AES-128 in OTP to **encrypt
flash contents**. This is a *confidentiality* control: it protects
the firmware binary from being read out. Our chain provides
*integrity and authenticity* — the property DGCA Level 1 actually
requires:

> "Registered checksums should be stored securely in the flight
> module such that they cannot be updated without the authorization
> of the manufacturer."

The DGCA rule is about authorization of updates, not secrecy of
checksum values. Checksum values are `SHA-256(firmware)` — any
reviewer can recompute them. What matters is that the device only
accepts a checksum the manufacturer authored. Our signed-manifest +
signed-firmware chain delivers exactly that.

In addition, RDP Level 2 already prevents external flash readout
(returns zeros), so flash encryption would only add value against
attack scenarios already out of Level 1 scope (chip decap, advanced
fault injection). For productization or the audited reference parity, flash encryption
can be added later as BOOT004 — it is not required for certification.

---

## 8. Prior Art — Comparable Architectures

The architecture we are deploying (immutable hardware-resident
trust anchor → verifying bootloader → signed firmware → signed
config/manifest) is the standard pattern for production secure boot.

In systems with an authenticating Boot ROM (Apple, Android with Secure
SoC, STM32MPU, STM32H5), the bootloader is itself signature-verified at
runtime by silicon below it. On the STM32H743/H753 used here, the
bootloader's integrity is provided by RDP Level 2 (chip-level write
lockdown) rather than runtime signature verification. The end property —
the bootloader on a deployed unit is the bootloader the manufacturer
intended — is identical; the mechanism differs.
It is used at scale by:

| System | Trust anchor | Verifies | At scale |
|---|---|---|---|
| **Apple iPhone / iPad** | Apple Root CA public key in immutable Boot ROM (laid down at chip fab) | Boot ROM verifies LLB → LLB verifies iBoot → iBoot verifies kernel | Billions of devices |
| **Android Verified Boot (AVB)** | OEM public key hash in hardware-protected storage | Bootloader verifies signed VBMeta → VBMeta hashes verify boot/system/vendor partitions | Every Android device since 8.0 |
| **UEFI Secure Boot** | Platform Key (PK) X.509 cert in firmware NVRAM | Firmware verifies signed bootloader (db) → bootloader verifies kernel | Every Windows PC since Windows 8 |
| **STM32MPU ROM secure boot** (ST's own reference) | SHA-256 of public key in OTP WORD 24–31, plus "device closed" bit in OTP WORD 0 | ROM code verifies signed TF-A boot firmware | ST's documented production flow for STM32MP1 |
| **ARM Trusted Firmware (TF-A)** | Root-of-trust public key hash burned in SoC fuses | Verifies BL2 → BL31 → BL33 in turn | Industry-standard ARM secure-boot reference |

Critical observations:

- **Hardware-resident trust anchor is universal.** Every production
  secure-boot system stores the root public key (or its hash) in
  silicon — Boot ROM, OTP fuses, or eFuses. This is what makes the
  trust anchor immutable.
- **Asymmetric (signature) crypto, not symmetric (encryption), is
  the standard for the trust chain.** AES is sometimes used
  alongside for *confidentiality* (Apple's Effaceable Storage,
  STM32H5 PROC_FILTERING for IP protection) but the *authenticity*
  check is always signature-based.
- **STM32 specifically supports this exact pattern.** ST's own
  STM32MPU secure boot stores a public key hash in OTP and uses
  ECDSA signature verification in ROM. We are using a CubeOrange+
  (STM32H7), which has equivalent OTP and RDP capabilities — our
  Phase 5b is essentially porting ST's own MPU secure-boot pattern
  to the STM32H7 MCU using the PX4 bootloader as the verifier.
- **RDP Level 2 (or its equivalent) is mandatory for production.**
  Apple uses fused chip configuration; Android uses locked
  bootloader + TEE; UEFI uses Setup Mode lockdown; STM32MPU uses
  the OTP "device closed" bit + RDP L2. Our Phase 5b plan matches
  this pattern — RDP L2 is what makes the deployed unit's trust
  chain immutable.

This is not a novel or experimental architecture. It is the
mainstream pattern, with billions of devices in field deployment
(Apple alone), supported by the silicon vendor's own reference
documentation (ST), and codified in industry specifications (UEFI,
ARM TF-A).

---

## 9. Glossary — Hardware Security Terms

This section defines the hardware-specific terms used elsewhere in
this document for readers unfamiliar with embedded MCU security.

### DFU — Device Firmware Update (the protocol AND the bootloader)

DFU is a USB protocol (USB-IF specification) for flashing firmware
to a device without specialized hardware. STM32 chips ship with a
**stock DFU bootloader baked into ROM** that runs when the BOOT
pin is held high at reset. Tools like `dfu-util` (open source) can
talk to it from any PC and write arbitrary data to flash.

- **The problem this creates:** the stock DFU bootloader does not
  verify what it is flashing. Anyone with physical access to the
  USB port can flash unsigned firmware. This is the "Path A" gap
  that Phase 5b closes.
- **How RDP L2 fixes it:** RDP L2 sets a chip option that tells the
  silicon to refuse all flash writes from the DFU path. The DFU
  bootloader still runs but cannot do anything useful — its
  flash-write commands are rejected at the hardware level.

### SWD / JTAG — Debug interfaces (Serial Wire Debug / Joint Test Action Group)

These are the hardware interfaces a debugger (e.g. ST-Link,
J-Link, BlackMagic Probe) uses to connect to an MCU. Through SWD
or JTAG, a debugger can:

- Halt the CPU at any instruction
- Inspect and modify registers and memory
- Single-step through code
- Read or write any flash region (mass erase, full reflash)
- Bypass any software-level protection by directly forcing CPU
  state

SWD is a 2-pin variant common on small MCUs (STM32 included).
JTAG is the older 4-pin standard. Both are equally powerful
attack surfaces if left enabled in production.

- **How RDP L2 fixes it:** RDP L2 permanently disables the debug
  interface at the silicon level. Connecting a debug probe to a
  Level-2 chip results in the probe failing to enumerate the
  target — there is nothing to talk to.

### Flash readout

Refers to dumping the contents of internal flash memory off the
chip — typically via SWD/JTAG (read each address) or via the DFU
bootloader's read commands. An attacker who can read flash can:

- Extract any embedded keys (which is why we use OTP + signing
  rather than embedded secrets)
- Reverse-engineer the firmware
- Identify vulnerabilities for a targeted attack

- **How RDP levels affect it:**
  - RDP 0: flash is freely readable via SWD or DFU
  - RDP 1: SWD reads of flash return zero, but the chip can be
    regressed to RDP 0 (which mass-erases flash first — contents
    are protected, but the chip is reusable)
  - RDP 2: SWD readout permanently disabled; flash content
    cannot be retrieved by any external interface

### OTP — One-Time Programmable memory

A region of non-volatile memory inside the MCU made of physical
fuses. Each bit can be flipped from 0 to 1 exactly once (the fuse
is permanently blown). Bits **cannot** be flipped back from 1 to 0
— there is no erase command at the silicon level.

STM32H7 has 1024 bytes of OTP organized as 32 blocks of 32 bytes
each. We use it to store the manufacturer RSA-3072 public key
(~422 bytes in DER format, occupying ~14 of the 32 blocks).

- **Why this is the right place for the trust anchor:** an attacker
  with physical access cannot erase or substitute the key. Setting
  more bits to 1 corrupts our key bytes (signature verification
  fails — the system fails closed; the attacker gains nothing).
- **OTP vs flash:** flash is a different memory region that *can*
  be erased and rewritten. Storing the trust anchor in flash
  rather than OTP would mean an attacker who can write flash can
  replace the trust anchor. OTP closes that door.

### Option bytes

A small dedicated configuration region (separate from main flash
and from OTP) that stores chip-level settings: BOOT pin behavior,
RDP level, brown-out reset voltage, watchdog configuration, and
write-protection bits for individual flash sectors.

The RDP level is stored in option bytes. Changing option bytes is
itself a flash-like operation, gated by an unlock sequence.

- **"Future option-byte changes" being blocked at RDP L2** means:
  once RDP L2 is set, the option bytes themselves become
  read-only at the silicon level. An attacker (or even the
  legitimate manufacturer) cannot change the RDP level back, or
  flip any other option-byte setting, ever. This is what makes
  the L2 burn permanent.

### RDP — Read-Out Protection (and its three levels)

A chip-level protection setting (stored in option bytes) that
controls how much of the chip's internal state is exposed to
external interfaces.

| Level | Effect | Reversible? |
|---|---|---|
| **RDP 0** | Default. Everything open: SWD/JTAG works, DFU works, flash readable, option bytes editable. Used on dev boards. | Yes |
| **RDP 1** | Flash readout via debug disabled. DFU flash writes still work but reads are blocked. Regression to RDP 0 is allowed but **mass-erases flash first** (so the contents stay secret, but the chip is recoverable for re-provisioning). Used as a rehearsal step before RDP 2. | Yes (with mass erase) |
| **RDP 2** | Hard lockdown: DFU bootloader refuses writes, SWD/JTAG permanently disabled, flash readout returns zeros, boot from RAM/system memory blocked, option bytes themselves can no longer be changed. | **No — permanent.** |

The "burn" is literally writing new values to the option-byte
region via SWD before RDP L2 is set. Once L2 is committed, the
chip's hardware refuses to accept any further option-byte writes —
the configuration is frozen for the life of the chip.

This is why RDP L2 is the most dangerous step in our deployment
process: a wrong configuration burned at L2 is permanent, and
recovery requires replacing the physical chip.
