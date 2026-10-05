# Threat Model — Inofly UAS Firmware Security

**Document version:** 1.5
**Date:** 2026-07-16 (amended)
**Scope:** DGCA Level 1 Type Certification — Firmware Manufacturer
**Framework:** Adapted from STRIDE for embedded UAS systems

> **🟡 PARTIALLY AMENDED — 2026-05-04 (architecture pivot).** Threats
> T10–T13 originally cited BOOT002 (OTP pubkey) and BOOT003 (RDP Level
> 2 burn) as their primary mitigations. Those requirements are
> **retired** — the CubeOrange+ carriers we ship have no externally
> accessible BOOT0 button, making OTP write and RDP burn operationally
> infeasible. They are replaced by an ArduPilot-style bootstrap-trust
> chain plus tamper-evident sealing. See
> [ARCHITECTURE.md §12 ADR-013/014/015](ARCHITECTURE.md) and
> [SECURITY_PLAN.md](../SECURITY_PLAN.md) for the architectural and
> requirement-level detail.
>
> Section 6 ("Assumptions and Boundaries") has been amended to make
> the **physical-attacker scope boundary** explicit. T10–T13 mitigation
> rows have been amended in place using the project-wide
> strikethrough+current convention. Section 7 attack-tree narrative
> uses the same convention.
>
> ⚠️ **FURTHER AMENDED — 2026-06-05 ([ADR-024](ARCHITECTURE.md)).**
> **BOOT005 (software DFU-refuse) is reclassified from a load-bearing
> mitigation to defense-in-depth, is not implemented, and is deferred into
> ADR-023.** Throughout T10/T11/T12'/Section 7, BOOT005 is listed alongside
> BOOT006/BOOT007 in the compensating-control bundle — but on our airframe USB
> sits *inside* the tamper seal, so a USB/DFU attacker is already a seal-breaker
> with SWD (who bypasses BOOT001 *and* BOOT005). **The load-bearing controls
> are BOOT001 (unsigned won't run) + BOOT007 (seal makes physical USB/SWD
> access tamper-evident) + BOOT006 (signed `bl_update`).** Read every BOOT005
> citation below as defense-in-depth that becomes load-bearing only for a
> future airframe that exposes USB *outside* the seal. The residual-risk
> ratings ("Low on sealed production units") are unchanged because they already
> rest on the seal, not on BOOT005.

**Changes in 1.5 (2026-07-16):**
- **T15 added — malicious SD-staged update (ADR-023 executed):** the SD-staged
  update path (`UPDATE.BIN`/`UPDATE.MTA` at SD root, applied by the secure
  bootloader) is a **new attack surface** and gets its own threat entry:
  verify-before-erase (RSA-PSS vs embedded pubkey) at the BL, TOC parser
  bounds-checked with the signature key **pinned** (the TOC's key field is
  attacker-controlled), BL mounts the SD **read-only** (no SD-write surface in
  the trust root), meta sidecar untrusted-but-self-validating. Bench-proven
  refusals: tampered image (B9.3), attacker-key image (B9.4), power-loss
  recovery (B9.6).
- **T14 partially closed (ADR-023 + manifest format v4):** the app-side update
  path now enforces `created_at` anti-rollback at **apply** (reject reason 8)
  and at **first-boot promotion** (refusal + audit event 6). Manifest format
  **v4** (2026-07-16) folds `created_at` into the RSA-signed payload — in v3
  it was CRC-only and the compared timestamp was forgeable. The BL-path
  residual is retained (authenticity, not freshness) but now lands
  **fail-closed**: promotion refuses the older manifest, POST fails against
  the rolled-back flash, arming stays blocked. T14 section + Risk Summary row
  updated.
- **BOOT005 implemented (A-7, default OFF):** T10 Risk Summary row updated —
  `CONFIG_BOOTLOADER_REFUSE_DFU` now exists in code inside ADR-023, ships
  **OFF**, remains defense-in-depth per ADR-024 (B10 bench pending).
- **Consistency rows:** §5 DGCA mapping gained T14/T15 rows (T14 had never
  been mapped); §6 in-scope list corrected ("BOOT005 closes Path A" →
  seal per ADR-024) and now names the SD-staged write path; §7.3 bypass
  table gained row 13 (malicious SD-staged update).

**Changes in 1.4 (2026-06-30):**
- **T11-H flipped to IMPLEMENTED (BOOT008 / [ADR-025](ARCHITECTURE.md)):** the
  bootloader is now a signed embedded-TOC artifact and `bl_update` RSA-PSS-
  verifies it before erasing sector 0 (refuse-before-erase). Updated the T11-H
  section (added Resolution row), the T11 and T11-H Risk Summary rows. The
  `bl_update` sector-0 path is now closed by cryptography, not only the seal +
  access control; pending hardware validation (BOOTLOADER_BRINGUP B8). Residual
  narrows to signing-process compromise + rollback (T14, still open — since
  partially closed in 1.5).

**Changes since 1.2 (2026-06-13 → 2026-06-30):**
- **T11 / T12' `bl_update` claim corrected (2026-06-13, hardware finding):**
  `bl_update` performs **no signature check** on the bootloader image
  (`bl_update.cpp:167`, vector-table sanity only), and ADR-022 moved the
  bootloader out of the signed app-fw ROMFS to a loose SD file — so the old
  "requires the manufacturer's private key (→ T3)" claim was retired. The
  bootloader-replacement path is closed by **access control** (only a signed app
  fw runs → attacker code can't self-invoke `bl_update`; remote blocked by
  MAVLink signing, local USB behind the BOOT007 seal), **not** by a signature on
  the bootloader. Risk Summary T11 row + T11/T12' Mitigations updated.
- **T11 / T12' Likelihood cells tightened (2026-06-30):** removed the residual
  "`bl_update` requires a signed app fw (BOOT006)" phrasing that could be misread
  as "`bl_update` verifies the bootloader," making the whole table tell one story
  with the corrected Mitigations cells.
- **T11-H added (2026-06-13):** optional future hardening — cryptographically
  signed bootloader updates (sign the bootloader binary + verify before erasing
  sector 0 → tamper-evident becomes tamper-resistant). Not required for L1;
  aligns with the approved BOOT008 / Workstream B roadmap.
- **T14 added (2026-06-13):** firmware rollback / downgrade — accepted by-design
  residual (BOOT001 verifies authenticity, not freshness; no version counter).
  Future BOOT00x if wanted, pairs with T11-H.

**Changes since 1.1 (2026-05-04):**
- Section 6 boundaries: explicit physical-attacker-out-of-scope
  statement, with the compensating procedural controls listed
- T10 (DFU bypass): mitigation amended — software DFU-refuse (BOOT005)
  replaces RDP-L2 chip-level disable (⚠️ **further amended 2026-06-05, ADR-024:**
  BOOT005 → defense-in-depth + deferred; the tamper seal carries T10)
- T11 (Custom bootloader replacement): mitigation amended — bootstrap-
  trust (BOOT006) + tamper-evident seal (BOOT007) replace RDP-L2 SWD
  disable
- T12 (OTP key tampering): retired (no OTP), replaced by T12'
  (bootloader-embedded pubkey tampering) with same fail-closed property
  via bootstrap-trust
- T13 (Debugger verify skip): mitigation amended — tamper-evident
  seal (BOOT007) replaces RDP-L2 SWD disable
- Section 7 attack-tree narrative: chain-of-trust diagram replaced
  with the bootstrap-trust + sealing variant; Section 7.5
  "Why flash encryption is not required" updated (seal replaces RDP
  in the readout-protection argument)

**Changes since 1.0 (2026-04-29):**
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
| **Residual risk** | Low — attacker must also forge the manufacturer's RSA-2048 signature |

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
| **Attack** | Attacker obtains the manufacturer RSA-2048 private key |
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
| **Mitigations** | PAR001 (static **ceiling** baked into firmware in `.compliance_params` flash table covered by `data_hash`; runtime cap-semantics — operator can set any value ≤ ceiling but cannot exceed it; over-cap attempts audit-logged via LOG001; values not persisted across reboots; pre-arm gate. ADR-019.) |
| **Residual risk** | Low — ceiling cannot be raised without re-flashing manufacturer-signed firmware (any change to `.compliance_params` shifts `data_hash` and fails POST003). Operator-side risk (setting an in-cap value that is unsafe for the specific mission) is outside the scope of PAR001 — covered by operator training and post-flight telemetry-log review. |

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
| **Attack** | Attacker holds the BOOT button while plugging in USB. STM32H7 enters its built-in DFU bootloader, which flashes any image presented over `dfu-util` without checking signatures. UPD001 protects only the MAVLink-FTP path (Path B) — DFU runs from ROM and never invokes our firmware. ⚠️ **AMENDED 2026-05-04 (ADR-013):** on the CubeOrange+ carriers we ship, the BOOT pin is not externally accessible without breaking the Hex factory seal — so the *opportunistic* USB-only attacker cannot even assert BOOT0. The "USB + BOOT button" attack therefore requires the seal-breaking step, which moves it into the physical-attacker class (out of scope at the cryptographic layer; see Section 6). |
| **Impact** | Arbitrary firmware on flight controller; full compromise. |
| **Likelihood** | ~~High with physical USB access; trivial tooling (`dfu-util` is open source).~~ ⚠️ **AMENDED 2026-05-04:** ✅ **Low** for the USB-only attacker class — BOOT0 is not exposed on our shipped carrier. **High** for a physical attacker who breaks the seal (out of scope at the crypto layer; compensated procedurally by the seal + RMA workflow). |
| **Mitigations** | BOOT001 (verifying bootloader re-checks firmware signature on every boot — DFU-flashed unsigned firmware will not launch on next reboot). ~~BOOT003 (RDP Level 2 disables the DFU bootloader at the chip level — USB DFU enumerator simply does not respond).~~ ⚠️ **AMENDED 2026-05-04 (ADR-014):** ✅ **BOOT005 (software DFU-refuse).** The secure variant of the PX4 bootloader contains a compile-time check (`#define INOFLY_SECURE_BL`) that refuses DFU mode entry — same end property as RDP L2 (DFU is unreachable from a running production unit) via a software mechanism that does not require BOOT0/SWD access at provisioning time. ArduPilot uses this exact pattern in production. |
| **Residual risk** | ~~Currently HIGH (Phase 5b not shipped). After BOOT001: LOW (firmware refuses to launch). After BOOT003: NONE (DFU dead at chip level).~~ ⚠️ **AMENDED 2026-05-04:** ✅ **Currently HIGH** (Phase 5b not shipped). **After BOOT001:** LOW (firmware refuses to launch). **After BOOT005:** LOW for USB-only attackers (DFU mode entry refused before the ROM loader is reached); the seal-breaking physical attacker is handled procedurally (T10 likelihood row + Section 6). |

### T11 — Custom bootloader replacement

| Field | Value |
|-------|-------|
| **Attack** | Attacker uses DFU or SWD to overwrite our bootloader with one that returns "signature OK" without actually verifying. The replaced bootloader then launches arbitrary firmware. ⚠️ **AMENDED 2026-05-04 (ADR-013/015):** under the bootstrap-trust model, sector 0 is also writable via PX4's `bl_update` mechanism — but `bl_update` runs *inside* a running app fw, and the running app fw is signature-verified by the existing bootloader (BOOT001). ~~So `bl_update` is only weaponizable by an attacker who already holds the manufacturer's RSA-2048 private key (covered by T3).~~ ⚠️ **CORRECTED 2026-06-13 (hardware finding).** `bl_update` does **no signature check** on the bootloader image — verified in `bl_update.cpp:167`, the only validation is a vector-table sanity check (SP in RAM, reset vector inside the BL flash region; the "verify" pass is a flash read-back, not crypto). And **ADR-022 (2026-05-24) moved the bootloader out of the signed app-fw ROMFS to a loose SD file**, so the app-fw signature no longer transitively covers it. **No private key is required to flash a substitute bootloader once `bl_update` is reachable.** The real gate on this path is **access control to the `bl_update` command**: only a manufacturer-signed app fw runs (BOOT001), so attacker *code* can't self-invoke it; a *human* invoking it needs console access — **remote is blocked by MAVLink signing (PAIR001); local USB is behind the BOOT007 tamper seal.** The end property still holds on *sealed* units, but it rests on BOOT007 + access control, not a private-key gate. See **T11-H** below. |
| **Impact** | Bypasses the entire chain of trust — every downstream check (firmware sig, manifest sig, POST, ARM gate) is performed by attacker-controlled code. |
| **Likelihood** | ~~High pre-RDP (DFU and SWD both writable); requires physical port access.~~ ⚠️ **AMENDED 2026-05-04:** ✅ **Low** for the USB-only attacker class — DFU is software-refused (BOOT005); ~~`bl_update` requires a manufacturer-signed app fw (BOOT006).~~ ⚠️ **CORRECTED 2026-06-13:** `bl_update` is reachable only from a **running signed app fw** (BOOT001 access control) — note it does **not** verify the bootloader image itself (`bl_update.cpp:167`, header sanity only); the closing control is access control + BOOT007, not a signature on the bootloader (see **Mitigations** and **T11-H**). **High** for a physical attacker who reaches SWD/JTAG by breaking the airframe + Cube seal (out of scope at the crypto layer; compensated procedurally — see Section 6 and T11 mitigation row). |
| **Mitigations** | ~~BOOT003 (RDP Level 2 disables DFU writes AND SWD/JTAG writes at the chip level — no remaining external write path to the bootloader region). The bootloader's trust anchor (manufacturer pubkey) lives in OTP, not in the bootloader binary, so even a copied bootloader cannot substitute its own key.~~ ⚠️ **AMENDED 2026-05-04 (ADR-013/014/015):** ✅ **Three-part compensating control replaces RDP L2:** (a) **BOOT005 software DFU-refuse** — production bootloader actively refuses DFU mode entry, closing the DFU path. (b) ~~**BOOT006 bootstrap-trust** — sector 0 writes via `bl_update` require a manufacturer-signed app fw containing the new bootloader in ROMFS; an attacker without the manufacturer's private key cannot push a malicious bootloader.~~ ⚠️ **CORRECTED 2026-06-13:** post-ADR-022 the bootloader is a *loose SD file* (not ROMFS) and `bl_update` does **not** verify it. BOOT006's real contribution is that **only a signed app fw *runs*** (BOOT001), so attacker code can't self-invoke `bl_update`; the closing control is **BOOT007 (local USB) + MAVLink signing (remote)**, not a private-key gate. See T11-H. (c) **BOOT007 tamper-evident seal** — physical SWD/JTAG access requires visibly breaking the airframe + Cube seal, triggering RMA quarantine on receipt. The bootloader's trust anchor (manufacturer pubkey) is now embedded in the bootloader binary itself; an attacker who could rewrite sector 0 could substitute a key — but every remaining write path is closed by (a)–(c) above. |
| **Residual risk** | ~~HIGH on dev boards (RDP 0 — accepted, dev-only). NONE on production units after RDP L2 is burned. This is the single strongest argument for why production hardware MUST go through Phase 5b's RDP burn.~~ ⚠️ **AMENDED 2026-05-04:** ✅ **HIGH on dev boards** (no DFU-refuse, no seal — accepted, dev-only segregation as before). **LOW on sealed production units** at the cryptographic layer (DFU dead, `bl_update` requires signed fw, SWD requires breaking seal). The residual *physical-attacker* risk on sealed production units is acknowledged and compensated procedurally (RMA inspection + UID/seal-serial tracking — see Section 6). The single strongest argument for why production manufacturing **must** go through MANUFACTURING_RUNBOOK.md (seal application + UID recording). |

### ~~T12 — OTP public-key tampering~~ 🚫 RETIRED 2026-05-04 (ADR-013) — replaced by T12'

> ~~Attacker attempts to overwrite the manufacturer public key in OTP
> with their own pubkey, then signs malicious firmware with the
> matching private key. Mitigation: OTP is one-time-programmable
> (write-once silicon fuses); bits cannot be cleared. Attacker can
> only corrupt our key (fails closed). Residual: NONE.~~
>
> 🚫 **RETIRED 2026-05-04 (ADR-013).** OTP is no longer used for the
> trust anchor. The equivalent threat under the amended architecture
> is T12' below.

### T12' — Bootloader-embedded public-key tampering ⭐ NEW 2026-05-04 (replaces T12)

| Field | Value |
|-------|-------|
| **Attack** | Attacker attempts to substitute the manufacturer pubkey embedded in the bootloader binary with their own pubkey, then signs malicious firmware with the matching private key. The substitution requires writing sector 0 (where the bootloader lives). |
| **Impact** | Would defeat the entire root of trust — modified bootloader would happily verify attacker-signed firmware. |
| **Likelihood** | **Low** for the USB-only attacker class — every external write path to sector 0 is gated: DFU is software-refused (BOOT005); ~~`bl_update` requires a manufacturer-signed app fw (BOOT006).~~ ⚠️ **CORRECTED 2026-06-13:** `bl_update` is reachable only from a **running signed app fw** (BOOT001 access control) — it does **not** verify the bootloader image itself (`bl_update.cpp:167`, header sanity only); the closing control is access control + BOOT007, not a signature on the bootloader (see **Mitigations** and **T11-H**). **High** for a physical attacker who breaks the seal to reach SWD/JTAG (out of scope at the crypto layer — see Section 6). |
| **Mitigations** | **BOOT005 (software DFU-refuse)** + **BOOT006 (bootstrap-trust via `bl_update`)** + **BOOT007 (tamper-evident seal on SWD path)**. Same compensating-control bundle as T11. ~~The `bl_update` path is the only unprivileged route to sector 0, and it is gated by signature verification of the running app fw containing the new bootloader image — an attacker would need the manufacturer's RSA-2048 private key to weaponize it (collapsed into T3).~~ ⚠️ **CORRECTED 2026-06-13 — `bl_update` does not verify the bootloader image (header check only, `bl_update.cpp:167`), and post-ADR-022 the bootloader is a loose SD file outside the signed ROMFS, so no private key is required to flash a substitute. The `bl_update` path is gated by access control (only-signed-app-runs + BOOT007 seal on USB + MAVLink signing on remote), not by a signature on the bootloader. See T11-H.** |
| **Residual risk** | LOW on sealed production units at the crypto layer. Acknowledged residuals: (a) physical attacker breaking the seal — handled procedurally via RMA inspection + UID/seal-serial tracking (Section 6); (b) chip decap + physical rewriting of internal flash — outside DGCA Level 1 scope, nation-state-actor territory. ⚠️ **Note on hardware-enforced strength:** the original T12 had a hardware-enforced "fails closed" property (write-once OTP fuses). T12' does not — internal flash *can* be erased and rewritten if an attacker reaches sector 0. The end property "the bootloader on a deployed unit is the bootloader the manufacturer intended" is preserved by the seal + bootstrap-trust combination; the crypto-layer guarantee is replaced by an operational guarantee, which is the standard pattern at this hardware tier (and is what ArduPilot ships with). |

### T13 — Debugger-based runtime verification skip

| Field | Value |
|-------|-------|
| **Attack** | Attacker attaches an SWD/JTAG debugger, halts the CPU at the signature-verify call inside the bootloader, forces the comparison result to "pass," resumes execution. Bootloader then launches malicious firmware. |
| **Impact** | One-off bypass per boot; persists only for that session unless attacker also writes flash. |
| **Likelihood** | ~~Requires physical access + debug probe (~$20 hardware) on dev boards. Impossible after RDP L2.~~ ⚠️ **AMENDED 2026-05-04:** Requires physical access + debug probe (~$20 hardware) **AND** breaking the airframe + Cube tamper-evident seal to reach the SWD/JTAG pads. Out of scope at the cryptographic layer; the seal-breaking step is handled procedurally via RMA inspection (Section 6). |
| **Mitigations** | ~~BOOT003 (RDP Level 2 permanently disables SWD/JTAG — debug probe cannot enumerate the target). On dev boards (RDP 0), this remains an accepted risk.~~ ⚠️ **AMENDED 2026-05-04 (ADR-013):** ✅ **BOOT007 (tamper-evident seal + UID/seal-serial tracking).** Reaching SWD/JTAG requires visibly breaking the seal on the airframe AND on the Cube enclosure. Detection is procedural — units returning with broken seals are quarantined on RMA receipt and not re-flown without re-provisioning. The compensating control replaces RDP L2's hardware-level SWD-disable with an operational seal-and-track workflow. On dev boards (no seal applied), this remains an accepted risk for dev-only segregation. |
| **Residual risk** | ~~HIGH on dev boards — accepted because dev units are not flown in regulated airspace. NONE on production units after RDP L2.~~ ⚠️ **AMENDED 2026-05-04:** ✅ **HIGH on dev boards** (no seal — accepted, dev-only segregation as before). **LOW at the cryptographic layer on sealed production units** (the SWD path requires the seal-breaking step). The remaining physical-attacker residual on sealed units is acknowledged and compensated procedurally (Section 6); a successful T13 attack would leave physically visible evidence (broken seal) that triggers RMA quarantine. |

### T11-H — Cryptographically signed bootloader updates ⭐ NEW 2026-06-13 · ✅ IMPLEMENTED 2026-06-30 (BOOT008 / ADR-025)

> ✅ **IMPLEMENTED 2026-06-30 (BOOT008 / [ADR-025](ARCHITECTURE.md)).** This was
> raised 2026-06-13 as a future hardening option; it is now built in code
> (B-1…B-3). The `bl_update` path is closed by **cryptography**, not only by the
> seal + access control. Pending hardware validation (BOOTLOADER_BRINGUP **B8**).
> Still **not** a DGCA Level 1 gate — defense-in-depth that raises the path from
> tamper-evident to tamper-resistant.

| Field | Value |
|-------|-------|
| **Gap (as of 2026-06-13, now closed)** | `bl_update` (the only sanctioned sector-0 writer) performed **no signature check** on the bootloader image — only a vector-table sanity check (`bl_update.cpp:167`). On a deployed unit the bootloader-replacement path (T11/T12') was closed by **tamper-evidence** (BOOT007 seal + RMA inspection) and access control (MAVLink signing on remote), **not by cryptography**. A seal-breaking physical attacker with console access could install an unsigned/malicious bootloader. |
| **Resolution (BOOT008)** | The bootloader is now a manufacturer-signed embedded-TOC artifact (`bl_toc.c`, B-1), signed host-side (`sign_bootloader_image`, B-2). `bl_update` RSA-PSS-verifies the candidate bootloader against the embedded manufacturer key on the same in-RAM buffer it will flash, and **refuses before erasing sector 0** on any failure (B-3, shared `secure_verify` lib; gated by `CONFIG_BL_UPDATE_REQUIRE_SIG=y` on the secure target). Refuse-before-erase adds no brick path. Even a seal-breaking, console-having attacker can no longer install an **unsigned** bootloader. |
| **Status** | ✅ **IMPLEMENTED in code (B-1…B-3), builds on NuttX + SITL; pending hardware validation (BOOTLOADER_BRINGUP B8).** The Level 1 integrity property was already delivered by bootstrap-trust + the tamper seal (ADR-013/015, the standard pattern at this tier — ArduPilot ships the same); BOOT008 hardens it. Residual: signing-process compromise (still produces a validly-signed image — §13 residual) and rollback (T14 — authenticity not freshness; no version counter). |

### T14 — Firmware rollback / downgrade ⭐ NEW 2026-06-13 · 🟡 PARTIALLY CLOSED 2026-07-16

> ✅ **PARTIALLY CLOSED 2026-07-16 (ADR-023 + manifest format v4).** The
> **app-side update path** now enforces anti-rollback at two points: `secure_boot
> apply_update` rejects a staged manifest whose `created_at` is older than the
> active one's (reject reason 8, audit-logged), and first-boot
> `promoteAfterUpdate()` applies the same check before promoting (refusal =
> audit event 6, code 8). **Manifest format v4** makes the compared timestamp
> unforgeable: `created_at` moved inside the manifest's RSA-signed payload
> (in v3 it was CRC32-only — an attacker could forward-date an old signed
> manifest and beat both checks). **Residual retained:** the bootloader's SD
> gate verifies *authenticity*, not *freshness* — a genuinely-signed old image
> staged with its matching old manifest still flashes at the BL — but this now
> lands **fail-closed**: promotion refuses the older manifest, the newer active
> manifest is kept, POST002/003 fails against the rolled-back flash, and arming
> stays blocked (downgrade becomes a detectable availability problem, not a
> silent integrity one). Full close remains a **monotonic version counter in
> the bootloader** — future BOOT00x.

| Field | Value |
|-------|-------|
| **Attack** | Attacker (with the same access needed to flash firmware) installs an **older but genuinely manufacturer-signed** app firmware carrying a known, since-patched vulnerability. BOOT001 verifies *authenticity*, not *freshness* — there is no monotonic version counter — so a validly-signed old image is accepted and boots. |
| **Impact** | Re-introduces a patched vulnerability. The chain of trust itself is **not** broken — the image is genuinely manufacturer-signed. |
| **Likelihood** | Low — requires firmware-flash access, which on a deployed unit means a MAVLink-signed link (remote) or breaking the BOOT007 seal (local USB/DFU). Same access gate as T10/T11. |
| **Mitigations** | ~~**Accepted residual — by design, not a DGCA Level 1 requirement.**~~ ✅ **App-path closed (ADR-023 + v4):** `created_at` anti-rollback at apply + promotion, timestamp inside the RSA-signed payload. **BL-path accepted residual, fail-closed:** no version counter in the trust root; a BL-path downgrade fails POST and cannot arm. Anti-rollback is still not a DGCA Level 1 requirement. Full close if desired later: a **monotonic version counter** checked by the bootloader — a future BOOT00x, paired with T11-H. |
| **Residual risk** | Low on sealed production units (access-gated); BL-path downgrade = availability impact only (unit refuses to arm until re-flashed); accepted at Level 1. |

### T15 — Malicious SD-staged update ⭐ NEW 2026-07-16 (ADR-023 surface)

| Field | Value |
|-------|-------|
| **Attack** | Attacker places a crafted `UPDATE.BIN` / `UPDATE.MTA` at the SD card root — physically (seal-breaker with SD access) or remotely (MAVLink-FTP file write over a signed link) — hoping the bootloader's every-boot SD probe flashes attacker code, corrupts flash via a malformed TOC, or downgrades the unit (→ T14). |
| **Impact** | If the verify-before-erase gate failed: arbitrary code execution below the app fw. Otherwise: at worst denial of service (unit busy refusing the staged file each boot). |
| **Likelihood** | Low — remote requires a MAVLink-signed link (PAIR001); local requires breaking the BOOT007 seal. Same access gates as T10/T11/T14. |
| **Mitigations** | **Verify-before-erase (the load-bearing control):** the BL streams SHA-256 over the staged image and RSA-PSS-verifies against the **embedded** manufacturer pubkey before erasing a single byte — unsigned, tampered, or attacker-keyed images are refused with flash untouched (bench: B9.3 tampered, B9.4 attacker-key). **Parser hardening:** TOC parse is strictly bounds-checked and the signature key slot is **pinned** — the TOC's own key field is attacker-controlled and ignored. **No SD-write surface in the trust root:** the BL mounts the SD read-only (ChaN FatFs RO); all cleanup/quarantine is app-owned. **Meta sidecar untrusted:** `UPDATE.MTA` is self-validating against the signed manifest's hashes; lying about lengths ⇒ hash-binding failure (reject reason 6). **Torn-write safety:** first vector-table word committed last + ECC-safe idempotence check, so power games during apply cannot produce a bootable half-image (bench: B9.6). **App-side quarantine:** a failing image is renamed `UPDATE.BAD`, terminating the BL retry loop (bounded DoS, audit event 6). |
| **Residual risk** | Low. Genuinely-signed old image = T14 (fail-closed via promotion + POST). Persistent garbage-staging = bounded DoS on an attacker who already has seal-broken or signed-link access. Cut-power-during-erase can leave the unit needing DFU/USB recovery (documented in ADR-023). |

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
| T10 — DFU (Path A) bypass | **High** (Phase 5b open) | ~~Low (BOOT001) → None (BOOT003)~~ ~~✅ Low (BOOT001 + BOOT005)~~ → **Low: BOOT001 + tamper seal (BOOT007)**; BOOT005 = DiD, ✅ implemented in ADR-023 2026-07-15 (default OFF, B10 pending) per ADR-024 |
| T11 — Bootloader replacement | **High** (no seal, no DFU-refuse) | **Low on sealed production units** — ⚠️ **2026-06-13:** closure was **BOOT007 seal + access control** (only-signed-app-runs + MAVLink signing), **not** crypto on the `bl_update` path. ✅ **2026-06-30 (BOOT008/ADR-025):** `bl_update` now RSA-PSS-verifies the bootloader before erase, so unsigned images are refused by **cryptography** too (pending B8 hw validation). BOOT005 = DiD/deferred per ADR-024 |
| ~~T12 — OTP key tampering~~ | ~~**None**~~ | ~~None (hardware-enforced)~~ 🚫 Retired — see T12' |
| T12' — Bootloader-embedded pubkey tampering ⭐ | **High** (Phase 5b open) | Low at crypto layer on sealed production units (same controls as T11); physical-attacker residual handled procedurally |
| T13 — Debugger verify skip | **High** (no seal) | ~~None (RDP L2)~~ ✅ Low at crypto layer on sealed production units (BOOT007); RMA inspection workflow for the seal-breaking case |
| T11-H — Signed bootloader updates ⭐ | High if `bl_update` reachable + unsigned accepted | ✅ **IMPLEMENTED (BOOT008/ADR-025)** — `bl_update` verify-before-erase; tamper-evident → tamper-resistant. Pending B8 hw validation; not required for L1. Residual: signing-process compromise, rollback (T14) |
| T14 — Firmware rollback ⭐ | **Low** (access-gated) | 🟡 **Partially closed 2026-07-16 (ADR-023 + manifest v4):** app-path `created_at` anti-rollback at apply + promotion, timestamp RSA-signed; BL-path residual fail-closed (POST blocks arming). Full close = future BOOT00x version counter |
| T15 — Malicious SD-staged update ⭐ | **Low** (access-gated) | ✅ Verify-before-erase at the BL (RSA-PSS vs embedded key) + pinned-key bounds-checked TOC parse + read-only BL FS + app-side quarantine; bench-proven B9.3/B9.4/B9.6 |

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
| T10 | BOOT001 + BOOT007 (seal); ~~BOOT003~~ ~~BOOT005~~ → BOOT005 DiD/deferred (ADR-024) | Secure Boot, Tamper Resistance |
| T11 | ~~BOOT003~~ ✅ BOOT006 + BOOT007 (BOOT005 DiD/deferred — ADR-024) | Tamper Resistance (operational lockdown — bootstrap-trust + seal) |
| ~~T12~~ → T12' | ~~BOOT002~~ ✅ BOOT006 + BOOT007 (BOOT005 DiD/deferred — ADR-024) | Root of Trust (bootloader-embedded pubkey, protected operationally) |
| T13 | ~~BOOT003~~ ✅ BOOT007 | Tamper Resistance (seal-gated SWD path + RMA inspection) |
| T14 ⭐ | UPD001 apply/promotion `created_at` anti-rollback (app path, ADR-023 + manifest v4); BL-path residual accepted, fails closed via POST | Secure Update (anti-rollback itself not an L1 clause) |
| T15 ⭐ | UPD001 (apply-path binding) + BOOT001 (BL verify-before-erase) + POST001 | Secure Update, Secure Boot |

---

## 6. Assumptions and Boundaries

**In scope (cryptographic layer — fully blocked by signature chain):**
- Firmware integrity from build to boot
- Manufacturer signing and drone-side verification
- USB-only attackers (remote, opportunistic) — every software write
  path to flash is gated by signature verification: UPD001 covers
  Path B (MAVLink-FTP), BOOT001 covers app fw on every boot, ~~BOOT005
  closes Path A (DFU)~~ *(per ADR-024: the tamper seal closes Path A;
  BOOT005 is DiD, implemented 2026-07-15, ships OFF)*, the ADR-023
  SD-staged path is gated by BL verify-before-erase + apply-path hash
  binding (T15), BOOT006 makes `bl_update` the only sector-0
  write path and gates it on a signed app fw
- GCS display of security status

**Physical-attacker boundary (out of scope at the cryptographic layer; compensated procedurally):**

⚠️ **NEW BOUNDARY STATEMENT — 2026-05-04 (ADR-013).** Under the
amended architecture, an attacker who **disassembles the airframe
AND breaks the Cube enclosure** to reach SWD/JTAG pads is **out of
scope at the cryptographic layer**. This boundary is required because
the CubeOrange+ carriers we ship have no externally accessible BOOT0,
making OTP write and RDP Level 2 burn operationally infeasible (they
would require breaking the same Hex factory seal we are now relying
on). The previous architecture (BOOT002 OTP + BOOT003 RDP L2) would
have moved this attacker class fully in-scope at the silicon layer;
the amended architecture cannot.

The compensating procedural controls are:

- **Tamper-evident seals (BOOT007)** on airframe AND on the Cube
  enclosure, applied at our manufacturing facility before shipping.
  Reaching SWD/JTAG visibly breaks one or both seals.
- **STM32 96-bit UID + seal serial recorded in QMS** at manufacture.
  The pair forms a per-unit fingerprint that persists across the
  unit's lifetime.
- **RMA inspection workflow.** Units returning with broken seals
  are quarantined and not re-flown without re-provisioning (full
  factory reset → secure bootloader re-install → reseal → re-record
  UID + new seal serial in QMS).

This is the same standard as physical anti-tamper on production
avionics at this tier (and the standard ArduPilot ships with on
hundreds of thousands of fielded units).

**Out of scope (for Level 1, unchanged):**
- GCS-to-drone authentication (Phase 7 — deferred)
- Network-based attacks on telemetry (covered by MAVLink 2 signing in future)
- Supply chain security of hardware components beyond the receive-and-verify-bootloader-hash step in MANUFACTURING_RUNBOOK.md
- Denial of service (radio jamming)
- Lab-grade fault injection (voltage glitch, EM, clock glitch — nation-state-actor class)
- Chip decap and physical rewriting of internal flash — outside Level 1 scope

**Assumptions:**
- Manufacturer build environment is physically secured
- HSM / offline key storage correctly implements key isolation; private
  key never leaves controlled storage
- PX4 NuttX kernel is not compromised (trusted computing base)
- SD card is accessible to an attacker with physical access to the drone
- ~~Production hardware will have RDP Level 2 burned before deployment in
  regulated airspace; dev boards remain at RDP 0 with that acknowledged
  as out-of-scope for production threat assumptions~~ ⚠️ **AMENDED 2026-05-04 (ADR-013):** ✅ **Production hardware will have the secure bootloader installed (BOOT001/005/006) AND tamper-evident seal applied (BOOT007) AND UID + seal serial recorded in QMS, before deployment in regulated airspace.** Dev boards run the dev bootloader (no DFU-refuse) and have no seal applied; dev-vs-production segregation is operationally enforced (dev units never flown in regulated airspace), unchanged from the original assumption.

---

## 7. Attack Tree — Secure Boot Bypass Analysis

This section answers the auditor's question: *"Walk me through every
way an attacker could get unsigned code running on the flight
controller, and show me what stops each one."*

### 7.1 The chain of trust

🚫 **RETIRED 2026-05-04 (ADR-013) — original (OTP + RDP L2):**

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

✅ **CURRENT 2026-05-04 (ADR-013/014/015) — bootstrap-trust + sealing:**

Once Phase 5b ships, the trust chain on a CubeOrange+ is:

```
[Tamper-evident seal: airframe + Cube]  ← procedural; broken seal = RMA quarantine
        │ blocks SWD/JTAG access without visible damage
        │ DFU entry: software-refused (ADR-014)
        ▼
[Bootloader: pubkey embedded inside]    ← integrity from bootstrap-trust + seal
        │ contains firmware-verify logic; uses its embedded pubkey symbol
        │ refuses DFU mode entry (BOOT005)
        │ verifies app fw signature on every boot
        ▼
[Firmware: SIGNED by manufacturer]      ← bootloader checks the signature
        │ contains the secure bootloader image in ROMFS (ADR-015)
        │ contains manifest-verify logic; uses pubkey embedded in firmware
        │ verifies manifest signature on every boot
        │ `bl_update` from QGC writes sector 0 with the ROMFS-embedded bootloader
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

- Factory-controlled first-install at our facility (verify factory
  bootloader hash on receipt → flash signed app fw → trigger
  `bl_update` to install secure bootloader → verify → seal)
- ~~RDP Level 2 (BOOT003) physically preventing replacement post-burn~~
  ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Bootstrap-trust + tamper-evident
  seal:** sector 0 is only writable via `bl_update` from a running,
  manufacturer-signed app fw (BOOT006); DFU is software-refused (BOOT005);
  SWD/JTAG access requires visibly breaking the seal (BOOT007). Same end
  property — "the bootloader on a deployed unit is the bootloader the
  manufacturer intended" — via a different mechanism.

We additionally sign the bootloader binary at build time so factory tooling
can verify it before programming, but no runtime check on this signature
happens on this chip. This is the same architectural pattern ArduPilot
ships with: it is validated across hundreds of thousands of fielded units.

Each layer's trust anchor is protected by the layer above it (or
operationally):
- ~~The OTP pubkey is protected by the silicon (write-once fuses)~~
  ⚠️ AMENDED. ✅ **The bootloader-embedded pubkey is protected by the
  same controls that protect the bootloader binary itself: software
  DFU-refuse + bootstrap-trust via signed `bl_update` + tamper-evident
  seal on the SWD path.**
- ~~The bootloader code is protected by RDP Level 2 (chip refuses
  external flash writes)~~ ⚠️ AMENDED. ✅ **The bootloader code is
  protected by the bootstrap-trust chain: only `bl_update` from a
  manufacturer-signed app fw can write sector 0; DFU is refused; SWD
  is sealed.**
- The firmware code is protected by the bootloader (signature check on
  every boot) — unchanged
- The manifest is protected by the firmware (signature check in POST) — unchanged
- The arming decision is protected by the manifest (POST result drives
  the ARM gate) — unchanged

### 7.2 Boot sequence in detail

On every power-on or reset of a Phase-5b-ready CubeOrange+:

1. CPU begins execution at the bootloader entry point in flash
   (typically `0x08000000`). This is fixed by the chip's reset
   vector — the CPU has no way to skip the bootloader.
2. Bootloader initializes minimal hardware (clocks, RAM).
3. ~~Bootloader reads the manufacturer RSA-3072 public key from the
   STM32H7 OTP region (e.g. `0x08FFF000`–`0x08FFF3FF`). Read access
   to OTP is via memory-mapped I/O, internal to the chip — no
   external path can intercept or modify this read.~~
   ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Bootloader uses its
   embedded RSA-2048 public key** — a constant data symbol compiled
   into the bootloader binary at build time, sourced from
   `pki/manufacturer/public/manufacturer_public.pem`. The pubkey lives
   inside sector 0 (the bootloader region) and is read via normal
   constant-data access — no external path can intercept or modify
   this read. Substituting the pubkey requires writing sector 0,
   which is closed by BOOT005 (DFU refused) + BOOT006 (`bl_update`
   requires signed app fw) + BOOT007 (SWD gated by seal).
4. Bootloader reads the application firmware's signature (appended at
   a known offset in the firmware image).
5. Bootloader computes SHA-256 over the application firmware region.
6. Bootloader runs RSA-PSS-Verify(embedded_pubkey, SHA-256(firmware),
   signature). libtomcrypt performs the math (already linked into
   PX4 / NuttX; no new crypto dependency).
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
| 2 | Replace firmware via stock STM32 DFU (USB + BOOT button) | BOOT001 (firmware refuses to launch on next boot) AND ~~BOOT003 (DFU disabled at chip level)~~ ✅ **BOOT005 (secure bootloader software-refuses DFU mode entry)**. Also: on the Hex carrier, BOOT0 is not externally accessible — asserting BOOT0 itself requires breaking the seal. | ~~None after RDP L2~~ ✅ Low at the crypto layer; physical-attacker class handled procedurally |
| 3 | Replace bootloader itself with one that skips verification | ~~BOOT003 (RDP L2 disables both DFU and SWD writes — no external write path to bootloader region)~~ ✅ **BOOT005 (DFU refused) + BOOT006 (`bl_update` is the only sector-0 write path; gated by signature verification of the running app fw containing the new bootloader image) + BOOT007 (SWD/JTAG access requires breaking the seal)** | ~~None after RDP L2; bootloader's trust anchor is in OTP, not in bootloader code, so even a copied bootloader cannot substitute its own key~~ ✅ Low at the crypto layer on sealed production units; bootloader's trust anchor is now embedded in the bootloader binary, so an attacker who could write sector 0 could substitute a key — but every write path is closed (DFU refused, `bl_update` requires signed fw, SWD gated by seal). Physical-attacker residual handled procedurally. |
| 4 | Tamper with `manifest.bin` only (claim attacker firmware's hashes) | POST001 manifest signature check (any change invalidates the RSA-PSS signature) | Requires manufacturer private key |
| 5 | Patch firmware binary to swap the embedded manifest-verify pubkey | BOOT001 (any change to firmware bytes breaks its own signature) | Requires manufacturer private key |
| 6 | ~~Overwrite the OTP-resident pubkey with attacker's pubkey~~ ✅ **Overwrite the bootloader-embedded pubkey with attacker's pubkey** | ~~OTP write-once silicon (T12) — bits cannot be erased; setting more bits to 1 corrupts our key, fails closed~~ ✅ **Same controls as row 3** (BOOT005 + BOOT006 + BOOT007) — the embedded pubkey lives in the bootloader binary in sector 0, so substituting it requires writing sector 0, which every external path now blocks. See T12'. | ~~None — hardware-enforced~~ ✅ Low at the crypto layer on sealed production units; the original "fails-closed at the silicon layer" property is replaced by an operational guarantee (consistent with ArduPilot's deployed pattern) |
| 7 | Use SWD/JTAG debugger to halt CPU and force the verify result to "pass" | ~~BOOT003 (RDP L2 permanently disables SWD/JTAG)~~ ✅ **BOOT007 (tamper-evident seal on the SWD pads) + RMA inspection workflow.** The seal-breaking step leaves visible evidence; returning units with broken seals are quarantined. | ~~None on production units; accepted on dev boards~~ ✅ Low at the crypto layer on sealed production units; physical-attacker residual handled procedurally |
| 8 | Voltage / clock / EM glitch at the verify branch (fault injection) | Out of DGCA Level 1 scope. ~~RDP L2 raises the equipment bar (no debug header to attack electrically).~~ ✅ The tamper-evident seal raises the same equipment bar (no exposed pads to attack electrically without visibly breaking the seal). | Acknowledged residual risk; mitigation requires HSM-class silicon |
| 9 | Forge an RSA-2048 signature without the private key | Cryptography (RSA-2048 acceptable per NIST SP 800-57 through 2030; ~2^112 work to brute-force — re-key to RSA-3072/4096 or Ed25519 before then per ADR-016 migration playbook) | Out of practical reach |
| 10 | Compromise the manufacturer's private key | Operational controls: HSM / offline storage, key ceremony, access controls | Single point of failure for any PKI-based system; same exposure as Apple/Microsoft/Google software signing |
| 11 | Supply chain — inject malicious code into PX4 source before signing | Out of secure-boot scope. Mitigated by reproducible builds, code review, controlled build host | Acknowledged; not a software-attack-against-the-device vector |
| 12 ⭐ | Supply-chain compromise of the **first-install** trust window (factory PX4 bootloader trusts anything; we use it once to load our first signed app fw) | Verify factory bootloader hash on receipt at our facility before first install (MANUFACTURING_RUNBOOK.md step 2); first install performed only at our trusted facility; sealed before shipping. | Acknowledged residual; same control category as supply-chain trust generally — mitigated procedurally |
| 13 ⭐ (2026-07-16) | Stage a malicious or rolled-back `UPDATE.BIN` (+ `UPDATE.MTA`) at the SD root for the bootloader's every-boot probe (the ADR-023 update path; reachable via local SD access or MAVLink-FTP file write) | Bootloader RSA-PSS **verify-before-erase** against the embedded manufacturer pubkey (signature key slot pinned, TOC parse bounds-checked, SD mounted read-only) AND app-side `apply_update` image↔manifest hash binding + `created_at` anti-rollback (manifest format v4 signs the timestamp) AND first-boot promotion (`matchesRunningFirmware`) + POST. See **T15**. | Arbitrary code requires the manufacturer private key. Old-genuinely-signed image = T14: flashes at the BL but fails closed at promotion/POST (unit won't arm). Garbage-staging = bounded DoS (quarantine `UPDATE.BAD`) |

### 7.4 The property the chain guarantees

> ~~Every byte of code the CPU executes was authored by a party
> holding the manufacturer's RSA-3072 private key, verified at boot
> against a public key physically fused into the chip and unreachable
> from any software path.~~

⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Updated property statement:**

> Every byte of code the CPU executes was authored by a party
> holding the manufacturer's RSA-2048 private key, verified at boot
> against a public key embedded in the bootloader binary, with every
> external path to overwrite that bootloader closed by software
> (DFU refused, `bl_update` requires a signed app fw) or by
> tamper-evident sealing (SWD gated by a seal that, if broken,
> triggers RMA quarantine).

The genuine residual risks are:
1. **Manufacturer key compromise** — operational, not technical.
   Same risk class as every signed-software ecosystem on earth.
2. **Lab-grade physical attack** (chip decap, advanced fault
   injection) — out of DGCA Level 1 scope.
3. **Physical attacker who breaks the seal to reach SWD/JTAG** —
   acknowledged out-of-scope at the cryptographic layer (forced by
   the carrier's no-accessible-BOOT0 constraint, ADR-013); compensated
   procedurally by tamper-evident sealing + UID/seal-serial tracking
   + RMA inspection (Section 6).
4. **First-install supply-chain trust window** — the factory PX4
   bootloader trusts anything; we use it once at our facility to load
   our first signed app fw, then immediately install the secure
   bootloader via `bl_update` and seal. Mitigated by verifying the
   factory bootloader hash on receipt and performing first install
   only at our trusted facility (MANUFACTURING_RUNBOOK.md).

Everything else either fails-closed cryptographically or is closed
operationally with detectable evidence.

### 7.5 Why flash encryption is not required

Some reference architectures use AES-128 in OTP to **encrypt
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

~~In addition, RDP Level 2 already prevents external flash readout
(returns zeros), so flash encryption would only add value against
attack scenarios already out of Level 1 scope (chip decap, advanced
fault injection).~~ ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **In
addition, the tamper-evident seal (BOOT007) makes external flash
readout via SWD detectable** — reading flash requires connecting a
debug probe to SWD pads, which requires visibly breaking the seal.
Units returning with broken seals are quarantined on RMA receipt.
Flash encryption would only add value against attack scenarios already
out of Level 1 scope (chip decap, advanced fault injection, and the
narrow case of an attacker who reads flash without re-flying the unit
afterward). For productization or reference parity, flash encryption can
be added later as BOOT004 — it is not required for certification.

---

## 8. Prior Art — Comparable Architectures

The architecture we are deploying (~~immutable hardware-resident
trust anchor~~ ✅ **operationally-controlled trust anchor (bootloader-embedded
pubkey, protected by software DFU-refuse + bootstrap-trust + tamper-evident
seal)** → verifying bootloader → signed firmware → signed
config/manifest) is the standard pattern for production secure boot.

In systems with an authenticating Boot ROM (Apple, Android with Secure
SoC, STM32MPU, STM32H5), the bootloader is itself signature-verified at
runtime by silicon below it. On the STM32H743/H753 used here, the
bootloader's integrity is provided by ~~RDP Level 2 (chip-level write
lockdown)~~ ⚠️ **AMENDED 2026-05-04 (ADR-013):** ✅ **bootstrap-trust
(`bl_update` from a signed app fw is the only sector-0 write path)
+ software DFU-refuse + tamper-evident sealing of airframe + Cube
enclosure** rather than runtime signature verification. The end property —
the bootloader on a deployed unit is the bootloader the manufacturer
intended — is identical; the mechanism differs. **This is the same
architectural pattern ArduPilot ships with** (see ADR-013 prior-art
citations) and is in field deployment on hundreds of thousands of
units. It is used at scale by:

| System | Trust anchor | Verifies | At scale |
|---|---|---|---|
| **Apple iPhone / iPad** | Apple Root CA public key in immutable Boot ROM (laid down at chip fab) | Boot ROM verifies LLB → LLB verifies iBoot → iBoot verifies kernel | Billions of devices |
| **Android Verified Boot (AVB)** | OEM public key hash in hardware-protected storage | Bootloader verifies signed VBMeta → VBMeta hashes verify boot/system/vendor partitions | Every Android device since 8.0 |
| **UEFI Secure Boot** | Platform Key (PK) X.509 cert in firmware NVRAM | Firmware verifies signed bootloader (db) → bootloader verifies kernel | Every Windows PC since Windows 8 |
| **STM32MPU ROM secure boot** (ST's own reference) | SHA-256 of public key in OTP WORD 24–31, plus "device closed" bit in OTP WORD 0 | ROM code verifies signed TF-A boot firmware | ST's documented production flow for STM32MP1 |
| **ARM Trusted Firmware (TF-A)** | Root-of-trust public key hash burned in SoC fuses | Verifies BL2 → BL31 → BL33 in turn | Industry-standard ARM secure-boot reference |

Critical observations:

- ~~**Hardware-resident trust anchor is universal.** Every production
  secure-boot system stores the root public key (or its hash) in
  silicon — Boot ROM, OTP fuses, or eFuses. This is what makes the
  trust anchor immutable.~~
  ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Hardware-resident OR
  operationally-controlled trust anchor.** Most production secure-boot
  systems store the root key in silicon (Boot ROM / OTP / eFuses).
  Some — most prominently ArduPilot — embed it in the bootloader
  binary and protect that binary via a chain-of-trust install path
  (ROMFS-bundled bootloader updated only via signed app fw) plus
  tamper-evident sealing. The end property "an attacker cannot
  substitute the trust anchor" is preserved by either mechanism. We
  use the ArduPilot pattern because the CubeOrange+ carrier we ship
  has no accessible BOOT0 for OTP/RDP-style hardware lockdown.
- **Asymmetric (signature) crypto, not symmetric (encryption), is
  the standard for the trust chain.** AES is sometimes used
  alongside for *confidentiality* (Apple's Effaceable Storage,
  STM32H5 PROC_FILTERING for IP protection) but the *authenticity*
  check is always signature-based.
- ~~**STM32 specifically supports this exact pattern.** ST's own
  STM32MPU secure boot stores a public key hash in OTP and uses
  ECDSA signature verification in ROM. We are using a CubeOrange+
  (STM32H7), which has equivalent OTP and RDP capabilities — our
  Phase 5b is essentially porting ST's own MPU secure-boot pattern
  to the STM32H7 MCU using the PX4 bootloader as the verifier.~~
  ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **Equivalent capability
  exists in STM32H7 (OTP + RDP), but is operationally infeasible on
  the carrier we ship (no accessible BOOT0).** A future move to
  STM32H5 (with RSS / authenticating Boot ROM) or to a custom
  CubeOrange+ carrier with accessible BOOT0 would let us re-enable
  the silicon-lockdown path; see [ARCHITECTURE.md §14](ARCHITECTURE.md).
- ~~**RDP Level 2 (or its equivalent) is mandatory for production.**
  Apple uses fused chip configuration; Android uses locked
  bootloader + TEE; UEFI uses Setup Mode lockdown; STM32MPU uses
  the OTP "device closed" bit + RDP L2. Our Phase 5b plan matches
  this pattern — RDP L2 is what makes the deployed unit's trust
  chain immutable.~~
  ⚠️ **AMENDED 2026-05-04 (ADR-013).** ✅ **An immutable-or-controlled
  trust chain is mandatory for production; the mechanism varies.**
  Apple uses fused chip configuration; Android uses locked bootloader
  + TEE; UEFI uses Setup Mode lockdown; STM32MPU uses the OTP "device
  closed" bit + RDP L2; **ArduPilot uses signed-`bl_update` + DFU-refuse
  + sealing.** Our Phase 5b matches the ArduPilot pattern — bootstrap-
  trust + tamper-evident sealing makes the deployed unit's trust
  chain operationally immutable in lieu of a silicon lockdown step.

This is not a novel or experimental architecture. It is the
mainstream pattern, with billions of devices in field deployment
(Apple alone), supported by the silicon vendor's own reference
documentation (ST), codified in industry specifications (UEFI,
ARM TF-A), and validated specifically for the
embedded-pubkey + ROMFS-bootloader + DFU-refuse variant by the
ArduPilot project across hundreds of thousands of fielded units.

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
each. ~~We use it to store the manufacturer RSA-3072 public key
(~422 bytes in DER format, occupying ~14 of the 32 blocks).~~
⚠️ **AMENDED 2026-05-04 (ADR-013):** OTP is no longer used — the
manufacturer RSA-2048 pubkey (~294 bytes DER) is embedded in the
bootloader binary instead.

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
