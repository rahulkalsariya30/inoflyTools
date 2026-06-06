# Secure Bootloader Bring-Up Gate (Phase 5b) — Engineering Acceptance

**Document version:** 0.4 (draft, 2026-06-06)
**Scope:** First-ever proof, on real CubeOrange+ silicon, that the
**secure bootloader** (BOOT001 verify, installed via BOOT006 `bl_update`)
builds, installs, enforces signatures, and hands off to the app fw — **and**
that a bad install is recoverable. (BOOT005 DFU-refuse is **deferred into
ADR-023** by [ADR-024](ARCHITECTURE.md) — defense-in-depth, not part of this
gate.)
**Authority:** [ARCHITECTURE.md §12 ADR-013/014/015/022](ARCHITECTURE.md),
[SECURITY_PLAN.md](../SECURITY_PLAN.md) BOOT001 / BOOT005 / BOOT006 / BOOT007.

---

## What this doc is, and is not

| Doc | Question it answers | Phase |
|---|---|---|
| [HARDWARE_ACCEPTANCE.md](HARDWARE_ACCEPTANCE.md) (H0–H15) | Does the **app-fw** security stack work on silicon? | Tier 1 — ✅ done (H8 carried) |
| **This doc** (B0–B7) | Does the **secure bootloader** (root of trust) work on silicon, and is a bad install recoverable? | **Phase 5b — engineering gate** |
| [MANUFACTURING_RUNBOOK.md](MANUFACTURING_RUNBOOK.md) (Steps 1–11) | How do we provision **each shipped unit**, assuming the gate passed? | Production |

The runbook's Steps 4–7 (install → verify → positive → negative) are the
**happy-path production version** of B2–B4 below. This gate proves those
steps actually work on real hardware the *first* time, adds the
**recovery rehearsal (B0)** the runbook's happy path omits, and front-loads
the **implementation-status pre-reqs** the runbook assumes are already met.
(BOOT005/B5 is **deferred into ADR-023** — [ADR-024](ARCHITECTURE.md) — and
is no longer a pre-req here.)

**No SITL pre-gate for most of this.** Unlike the H-series (each mirrors a
SITL §-step), the bootloader is hardware-boot code — it does not run under
SITL. B1 (build) is the only step provable off-hardware. Everything from B2
on is hardware-only, which is exactly why the recovery story (B0) is the
first gate, not an afterthought.

---

## ⚠️ DECISION REQUIRED — which unit, and the brick risk

Installing the secure bootloader is the **only irreversible-ish step in the
whole program.** After BOOT006 (BOOT005 is deferred — see
[ADR-024](ARCHITECTURE.md)):

- Sector 0 holds *our* bootloader; the factory bootloader is gone.
- DFU/USB upload **still works** — BOOT005 is *not* part of this install
  (deferred to ADR-023, default OFF), so the "re-flash over USB" recovery path
  stays open. (When BOOT005 is eventually enabled, DFU is refused only while a
  valid signed app is present — a no-app unit can still recover over USB.)
- `bl_update` becomes the only software sector-0 write path — but
  `bl_update` lives **inside the app fw**, so it only helps if a *valid app
  fw is still running*. A bootloader that fails to hand off leaves no app fw
  to run `bl_update` from. That is the brick scenario.

**The one escape hatch on a bench unit: SWD.** Per ADR-013, SWD/JTAG is open
until the BOOT007 tamper seal is applied — and a **bring-up unit is
unsealed**. So a bad bootloader on the bench is recoverable by re-flashing
sector 0 over SWD with a debug probe. **This is only true if the probe,
cable, and a known-good sector-0 image are staged and rehearsed *before* the
first install.** If they are not, a bad install is a real brick.

### Options

| Option | Brick exposure | Cost | Notes |
|---|---|---|---|
| **A — Dedicated bring-up unit** (2nd CubeOrange+) | Tier-1-proven unit untouched; a brick costs only the spare | +1 unit (~₹25–30k) | **Recommended** by [HARDWARE_ACCEPTANCE.md "Bootloader chain"](HARDWARE_ACCEPTANCE.md). Cleanest. |
| **B — Single unit + pre-staged SWD recovery** | Acceptable **iff** B0 passes first | SWD probe (ST-Link V3 / J-Link) + Cube 6-pin DEBUG cable, ~₹2–4k | Viable because the bench unit is unsealed (SWD open). Gated entirely on rehearsing recovery before risking the install. |
| **C — Single unit, no recovery staged** | **Unacceptable** | — | One bad flash = bricked Tier-1 unit, no path back without Hex-side intervention. Do not do this. |

### Recommendation
**Option A if a second unit is in budget; otherwise Option B is acceptable
*provided B0 (recovery rehearsal) passes before any secure-bootloader
install.*** Never Option C. The recovery capability is the gate — not the
spare unit. With SWD recovery proven, a brick becomes a 10-minute reflash,
not an RMA.

> **This decision must be ratified before B2.** Record the choice (A or B),
> and for B the probe/cable/known-good-image inventory, in the sign-off
> table at the end.

---

## Pre-reqs (Phase 0 — confirm before B0)

Analogous to the runbook's P-rows. **Every row must be green before
touching `bl_update`.** Unlike the runbook, some of these are *not yet
confirmed met* — that is the point of listing them.

| # | Item | How to confirm | Status |
|---|---|---|---|
| BP1 | **BOOT001 verify is built into the bootloader.** TOC + `STUB_KEYSTORE` + `PUBLIC_KEY0` (manufacturer pubkey DER) + `sw_crypto`, per `boards/cubepilot/cubeorangeplus/bootloader.px4board`. | Build `cubeorangeplus_bootloader`; confirm the artifact links and the embedded key matches `pki/manufacturer/public/`. Artifact exists today (103,432 B, ≤128 KB sector 0). | ✅ likely (built; re-confirm key) |
| BP2 | ~~**BOOT005 DFU-refuse is built in.**~~ ⚠️ **NOT a Phase 5b pre-req as of [ADR-024](ARCHITECTURE.md) (2026-06-05).** BOOT005 is **deferred into ADR-023** and reclassified to defense-in-depth (USB is behind the tamper seal → the seal, not BOOT005, closes Path A). It is **not implemented** (`stm32_common/main.c` still enters the stock `bootloader(timeout)` upload loop; only BOOT001 TOC-verify is wired) and **must not be built standalone** — it cannot be switched on until ADR-023's app-fw self-reflash exists, else a healthy unit becomes un-updatable over USB. Build it **with ADR-023**, flag `CONFIG_BOOTLOADER_REFUSE_DFU` default OFF. | ➖ **deferred to ADR-023 — not gating Phase 5b** |
| BP3 | **Signed app fw already on the unit**, manufacturer-signed (same key as the bootloader's embedded pubkey). | The Tier-1 build is signed and flashed; confirm `ver all` matches the current signed release. | ✅ (Tier 1) |
| BP4 | **Recovery toolchain staged** (Option B — chosen 2026-06-06). **Kit ordered 2026-06-06:** SWD probe (ST-Link V2 — use **STM32CubeProgrammer** on Windows; or DAPLINK/ST-Link V3) **+ a 6-pin JST SUR 0.8 mm pigtail** (housing `06SUR-32S`, contacts `SSHL-002T-P0.2`). ⚠️ **Connector correction:** the standard carrier board does **not** break out SWD — the only SWD access is the Cube's **internal FMU SWD connector** (`SM06B-SURS-TF`, JST SUR **0.8 mm**), reached by **opening the Cube case** (fine — bring-up unit is unsealed). Wire **SWDIO(4)/SWCLK(5)/GND(6)** to the probe; power the Cube over USB-C; VTref = **3.3 V**, never the connector's pin-1 (5 V). Known-good factory sector-0 image is captured in B0 step 2. **Recovery method is tiered — see [B0 verified SWD-connect procedure](#b0--verified-swd-connect-procedure-research-2026-06-06).** ⚠️ **Gap:** the kit covers Tier 1 (plain attach) only; the Tier-2 connect-under-reset fallback needs an **NRST tap at DF17 pin 7** (internal, not on the SUR connector) — stage if Tier 1 is flaky. | 🟡 **ordered — awaiting delivery (Tier-1 kit; NRST tap not yet staged)** |
| BP5 | **App-fw Tier 1 green on the build under test** (H0–H15, H8 carried). | [HARDWARE_ACCEPTANCE.md sign-off](HARDWARE_ACCEPTANCE.md). | ✅ |
| BP6 | **Known-good app fw `.px4` on hand** to recover the *app-fw* side of B4's negative test. | The signed release `.px4` in `release/`. | ✅ |

> ⚠️ **BP2 is no longer a blocker — superseded by [ADR-024](ARCHITECTURE.md)
> (2026-06-05).** BOOT005 DFU-refuse is **not implemented** and is **deferred
> into ADR-023**, not Phase 5b. The threat-model reason: USB is *inside* the
> tamper seal, so a USB/DFU attacker is already a seal-breaker who has SWD and
> bypasses both BOOT001 and BOOT005 — **the seal closes Path A**, BOOT005 is
> defense-in-depth (load-bearing only if a future airframe exposes USB outside
> the seal). It is also coupled to ADR-023: the only path that writes an
> app-fw image today *is* the DFU upload loop, so BOOT005 cannot be enabled
> until app-fw self-reflash exists. **Phase 5b completion does not require B5.**
> When ADR-023 is executed, build BOOT005 as a targeted mode-select change in
> `stm/stm32_common/main.c` behind `CONFIG_BOOTLOADER_REFUSE_DFU` (default OFF).
> **This is the first piece of Phase 5b work, and it is the one part that
> does not need the bench** — implement + SITL-irrelevant unit-reason it,
> then bring the whole gate to hardware.

---

## Bring-up gate — B0 through B7

Run in order. B0 is a hard gate: **do not run B2 until B0 passes.**

### B0 — Recovery rehearsal (the safety gate) 🔒
**Covers:** the brick-risk mitigation; makes B2–B5 reversible.
**Only required for Option B (single unit); for Option A, recovery = use the
spare, but rehearsing SWD reflash is still recommended.**

1. With the unit running its current (factory or stock) bootloader, **open
   the Cube case** and connect the SWD probe to the **internal FMU SWD
   connector** (`SM06B-SURS-TF`, JST SUR 0.8 mm — the one *not* nearest the
   servo rail; GND is the pin furthest from the servo rail). The standard
   carrier board does not expose SWD. Wire SWDIO/SWCLK/GND; power via USB-C.
2. Dump sector 0 (128 KB @ `0x08000000`) and save it as the **known-good
   image** + record its SHA-256 (this is also MANUFACTURING_RUNBOOK Step 2's
   factory reference hash — capture it here).
3. Deliberately corrupt sector 0 over SWD (or erase it), confirm the unit no
   longer boots.
4. **Re-flash the known-good image over SWD; confirm the unit boots and QGC
   reconnects.**
5. **Pass:** a from-scratch SWD reflash of sector 0 returned a non-booting
   unit to a booting one. Recovery is proven; B2–B5 are now reversible.
   **Fail:** stop. Do not install the secure bootloader on this unit
   (regress to Option A).

#### B0 — verified SWD-connect procedure (research 2026-06-06)
Researched against CubePilot forum reports + ST community + PX4 SWD docs.
SWD recovery of a Cube Orange is **proven** (forum users flash via the
internal `SM06B` FMU debug connector with ST-Link V2 + OpenOCD/gdb). Use a
**tiered** approach — try Tier 1 first, escalate only if it fails:

- **Tier 1 — plain SWD attach (try first).** NRST is *optional* (PX4: "most
  devices can be reset via the SWD lines"). Our brick is a bad **sector-0
  bootloader** that runs only briefly before failing hand-off, on an
  **unlocked** chip (no RDP burned), so SWD pins stay default early in boot.
  Wire **SWDIO(4)/SWCLK(5)/GND(6) + VREF 3.3 V**; power the Cube over USB-C;
  use a **low SWD clock** (long flying leads). Tool: **STM32CubeProgrammer**
  (mode = Normal) or OpenOCD. Read sector 0 to confirm the link before
  trusting it.
- **Tier 2 — connect-under-reset (the "No STM32 target found" fix).** If a
  running/looping bootloader blocks Tier-1 attach: CubeProgrammer **reset
  mode = Hardware reset, mode = Connect under reset** (or hold reset low,
  start connect, release). **This needs NRST**, which is **`FMU_!RESET` on
  DF17 pin 7 — NOT on the 6-pin SUR connector.** Pre-stage an NRST tap
  (DF17 pin 7 internally) as the fallback. *(Your ordered kit does not cover
  this — see BP4.)*
- **Tier 3 — BOOT0 → ROM USB DFU (nuclear, no probe).** "*Break open the
  case and manually pull up the BOOT0 line on power up*" → STM32 system
  bootloader → reflash over USB with CubeProgrammer. BOOT0 is internal with
  **no documented pad** and is manufacturer-discouraged. Last resort only.

> All three tiers require **opening the Cube** (SWD connector, NRST, BOOT0
> are all internal). Damage risk is to the **bottom plastic shell**
> ("difficult to close" — cosmetic, not functional); acceptable on an
> unsealed bench unit. **B0 passes on Tier 1 alone**; Tiers 2–3 are staged
> insurance. If even Tier 3 can't recover, regress to Option A.

### B1 — Secure bootloader builds + binary is valid
**Covers:** BOOT001 build; ADR-022 artifact.
- Build the bootloader target; confirm the `.bin` ≤ 128 KB and the first 8
  bytes are a valid vector table (SP in RAM range, reset vector in the
  bootloader FLASH range — the same header `bl_update` validates).
- Confirm the embedded `PUBLIC_KEY0` DER equals our manufacturer public key.
- **Pass:** valid, key-correct, size-fitting binary. (Off-hardware step.)

### B2 — Install via `bl_update` from SD (BOOT006)
**Covers:** BOOT006; first hardware exercise of the ADR-022 one-shot.
**Gated on B0.**
- Copy `bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin` to SD.
- From `nsh` / MAVLink Console:
  `bl_update /fs/microsd/cubepilot_cubeorangeplus_bootloader.bin`.
- Observe header-validate → erase sector 0 → program → verify (~5–10 s).
- Reboot.
- **Pass:** install completes without error; the unit reboots. **Fail:**
  invoke B0 recovery, diagnose, retry.

### B3 — BOOT001 positive path
**Covers:** BOOT001 verify of a legitimately signed app fw.
- After B2 reboot, confirm the secure bootloader RSA-PSS-verifies the
  already-installed signed app fw and hands off.
- Confirm app-fw POST publishes `firmware_integrity_status check_passed=true`
  and QGC reaches "ready."
- **Pass:** signed app fw boots through the new bootloader; POST green.

### B4 — BOOT001 negative path (fail-closed)
**Covers:** BOOT001 *enforcement* — the load-bearing proof.
- Load an **intentionally tampered app fw** (one byte flipped in the signed
  region; keep it in the bench fixture only, never commit).
- **The secure bootloader must refuse to hand off.** Expected: bootloader
  signals failure (LED/log), app fw never starts, QGC loses heartbeat,
  reboot does not recover until a valid app fw is loaded.
- Recover by re-flashing the known-good signed `.px4` (BP6).
- **Pass:** tampered app fw is rejected, fail-closed. **Fail (it boots):**
  release-blocking — BOOT001 is not enforcing; quarantine and fix.

### B5 — BOOT005 DFU-refuse ➖ DEFERRED (not a Phase 5b gate)
**Covers:** BOOT005. ⚠️ **Moved to the ADR-023 work package by
[ADR-024](ARCHITECTURE.md) (2026-06-05).** BOOT005 is defense-in-depth (the
tamper seal closes Path A on this airframe) and is coupled to ADR-023's
app-fw self-reflash (it cannot be enabled before that exists). **This step is
not required for Phase 5b completion.** It will be exercised as part of
ADR-023 execution, on a build with `CONFIG_BOOTLOADER_REFUSE_DFU` ON:
- With a valid signed app present, attempt a USB upload → **must be refused**.
- With no valid app (erased/blank), the upload loop **must open** (recovery /
  first install).
- **Pass (deferred):** DFU refused iff a verified app is present.

### B6 — `bl_update` remains the only sector-0 path / re-install idempotence
**Covers:** BOOT006 robustness.
- Re-run `bl_update` with the same binary; confirm idempotent re-install and
  a clean reboot (this is also the field-update mechanic under RMA).
- Confirm no *other* software path writes sector 0 (DFU upload loop does not
  write sector 0 — see [bootloader self-protection](ARCHITECTURE.md); SWD is
  hardware, gated by the seal in production). BOOT005 is deferred (ADR-024)
  and not relied on here.
- **Pass:** re-install is clean and idempotent.

### B7 — SWD-open confirmation (pre-seal, expected) ℹ️
**Covers:** documents the residual physical path the BOOT007 seal closes.
- Confirm SWD is still reachable on the unsealed bench unit (it is — this is
  the B0 recovery path).
- **This is expected and is *not* a failure.** In production, BOOT007
  (tamper seal) is the compensating control that closes it. Recorded here so
  the bring-up state is not mistaken for the production state.

---

## Relationship to ADR-023 (auto-flash)

This gate is the prerequisite the [ADR-023](ARCHITECTURE.md) auto-flash work
is sequenced behind: once B3/B4 prove BOOT001 enforces on every boot, a
bad/interrupted app-fw self-reflash **fails closed at the next boot** instead
of running unsigned code. Auto-flash moves from PROPOSED toward EXECUTED only
after this gate is green. **BOOT005 (DFU-refuse) is built as part of that
ADR-023 work** — not this gate — because it can only be switched on once the
self-reflash path gives healthy units a non-DFU way to update ([ADR-024](ARCHITECTURE.md)).

---

## Sign-off

Phase 5b is complete when **B0–B4, B6, B7 pass on a real CubeOrange+**, with
the unit decision ratified and recovery proven. **B5 (BOOT005) is deferred
into the ADR-023 work package** ([ADR-024](ARCHITECTURE.md)) and is **not**
required for Phase 5b sign-off. B0 and B4 are the load-bearing evidence: B0
proves the work was reversible, B4 proves the bootloader actually enforces.

| Step | Result | Date | Notes (commit hashes, board UID, probe used) |
|---|---|---|---|
| Unit decision (A / B) | ✅ **B** | 2026-06-06 | Single Tier-1 unit + pre-staged SWD recovery. B0 is the hard gate; BP4 must be staged before B2. |
| BP1 BOOT001 built | ✅ | 2026-06-06 | Off-hw re-confirm: embedded SPKI DER == `manufacturer_public.pem` (full 294-B DER @ `0x17853`, 256-B modulus @ `0x17874`) in `bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin`. |
| BP2 BOOT005 built | ➖ **deferred** | 2026-06-06 | **Not a Phase 5b pre-req** — [ADR-024](ARCHITECTURE.md): BOOT005 reclassified to defense-in-depth, deferred into ADR-023. |
| BP4 recovery staged | 🟡 ordered | 2026-06-06 | ST-Link V2 (+ STM32CubeProgrammer) **+ 6-pin JST SUR 0.8 mm pigtail** (`06SUR-32S`/`SSHL-002T-P0.2`) for the Cube **internal** FMU SWD connector (`SM06B-SURS-TF`; carrier does NOT break out SWD — open the case). Awaiting delivery. |
| B0 recovery rehearsal | ⬜ | | **hard gate before B2** |
| B1 build valid | ✅ | 2026-06-06 | Off-hw: size 103,432 B ≤ 128 KB; vector table valid (SP `0x24001D0E` AXI SRAM, reset `0x08000305` sector-0 Thumb); embedded key matches (see BP1). Artifact = `bootloader_artifact/...bin`. |
| B2 install (BOOT006) | ⬜ | | |
| B3 BOOT001 positive | ⬜ | | |
| B4 BOOT001 negative | ⬜ | | release-blocking if it boots |
| B5 BOOT005 DFU-refuse | ➖ **deferred** | 2026-06-06 | Moved to ADR-023 work package ([ADR-024](ARCHITECTURE.md)); not required for Phase 5b sign-off. |
| B6 idempotent re-install | ⬜ | | |
| B7 SWD-open (pre-seal) | ⬜ | | expected; seal closes in production |

---

## Document history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-06-05 | Initial draft. Engineering bring-up gate for the secure bootloader (B0–B7), the unit/brick-risk decision (recovery-first), and the Phase 0 pre-reqs. Surfaces the BOOT005 DFU-refuse implementation gap (BP2). |
| 0.2 | 2026-06-06 | **Unit decision ratified: Option B** (single Tier-1 unit + pre-staged SWD recovery). Sign-off + BP4 rows updated; stale BP2/B5 BOOT005 sign-off rows reconciled with [ADR-024](ARCHITECTURE.md) (deferred, not gating). **BP1 + B1 closed off-hardware** (artifact size/vector-table valid, embedded SPKI DER == manufacturer pubkey). Remaining B0/B2/B3/B4/B6/B7 are hardware-only — blocked on BP4 (procure SWD probe + Cube DEBUG cable), then B0 recovery rehearsal (hard gate). |
| 0.3 | 2026-06-06 | **BP4 kit ordered** — ST-Link V2 (+ STM32CubeProgrammer) + 6-pin JST SUR 0.8 mm pigtail (`06SUR-32S`/`SSHL-002T-P0.2`). **Connector correction:** standard carrier board does **not** break out SWD; SWD access is the Cube's **internal** FMU SWD connector (`SM06B-SURS-TF`, JST SUR 0.8 mm) — open the case (bring-up unit is unsealed). B0 step 1 + BP4 rows updated accordingly. Awaiting delivery → then B0. |
| 0.4 | 2026-06-06 | **B0 SWD-connect procedure researched + recorded** (tiered: Tier 1 plain attach / Tier 2 connect-under-reset via NRST @ DF17 pin 7 / Tier 3 BOOT0→ROM USB DFU). Findings: SWD recovery of Cube Orange is proven (forum: ST-Link V2 + OpenOCD via `SM06B`), NRST is *optional* for a healthy/early-boot unlocked chip but the "No STM32 target found" fix is connect-under-reset which **needs NRST (DF17 pin 7, internal — not on the SUR connector)**; BOOT0 is internal/undocumented (nuclear). Opening the Cube risks the bottom plastic shell (cosmetic). **Gap surfaced:** ordered kit covers Tier 1 only; NRST tap not yet staged. Option B remains viable; B0 (Tier 1) is the proof gate. |
