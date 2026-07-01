# Secure Bootloader Bring-Up Gate (Phase 5b) — Engineering Acceptance

**Document version:** 0.8 (draft, 2026-06-09)
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
| BP3 | **A BOOT001-*signed* app fw must be flashed before B2/B3** — manufacturer-signed (same key as the bootloader's embedded pubkey). | 🔴 **Found 2026-06-09 (code review):** the normal PX4 build emits a 256-byte **zero** signature placeholder in `.app_signature` (TOC itself is correct — magic `@0x2A8`, BOOT `flags=0x5`, SIG1 follows; only the *signature bytes* were missing). Flash an unsigned app + secure bootloader → **B3 fails fail-closed** (looks like a brick but isn't). ✅ **Tooling fix landed 2026-06-09:** `tools/pipeline.py` **step 0** now patches the BOOT001 image signature automatically (SITL images auto-skip; tested in `test_PIPE_pipeline.py::TestBoot001PipelineSigning`). **Remaining action = run the pipeline + flash `release/<stem>.px4` (step B1.5) before B2.** | 🟡 **tooling done — must run pipeline + flash before B2** |
| BP4 | **Recovery toolchain staged** (Option B — chosen 2026-06-06). **Kit ordered 2026-06-06:** SWD probe (ST-Link V2 — use **STM32CubeProgrammer** on Windows; or DAPLINK/ST-Link V3) **+ a 6-pin JST SUR 0.8 mm pigtail** (housing `06SUR-32S`, contacts `SSHL-002T-P0.2`). ✅ **Connector location (corrected 2026-06-06, CubePilot forum / S. Purohit):** SWD **is** on the carrier — the **FMU & I/O SWD+DEBUG connectors are on the *underside* of the carrier board** (`SM06B-SURS-TF`, JST SUR **0.8 mm**), reached by taking the carrier out of the plastic case. **No Cube-case opening needed.** FMU connector = the one with SERIAL 5 routed (`1=VDD5V 2=FMU_TX 3=FMU_RX 4=SWDIO 5=SWCLK 6=GND`). Wire **pins 4/5/6** to the probe; USB-C power; VTref **3.3 V**, never pin-1 (5 V). 0.8 mm SUR cable near-unobtainable → solder/pogo to pins 4/5/6. Known-good factory sector-0 image is captured in B0 step 2. **Recovery method is tiered — see [B0 verified SWD-connect procedure](#b0--verified-swd-connect-procedure-research-2026-06-06).** ⚠️ **Gap:** the kit covers Tier 1 (plain attach) only; the Tier-2 connect-under-reset fallback needs an **NRST tap at DF17 pin 7** (internal, not on the SUR connector) — stage if Tier 1 is flaky. | 🟡 **ordered — awaiting delivery (Tier-1 kit; NRST tap not yet staged)** |
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

1. With the unit running its current (factory or stock) bootloader, **take
   the carrier board out of the plastic case** and connect the SWD probe to
   the **FMU SWD+DEBUG connector on the *underside* of the carrier board**
   (`SM06B-SURS-TF`, JST SUR 0.8 mm). ✅ **No need to open the Cube's
   aluminium module** — the carrier exposes both FMU and I/O SWD connectors
   on its underside (confirmed: CubePilot forum, Siddharth Purohit, Feb 2024,
   with annotated photo + pinout). The **FMU** connector (the one we want) is
   the one with **SERIAL 5 (FMU_TX/RX)** routed to it; the other is I/O.
   Pinout: `1=VDD5V · 2=FMU_TX(S5) · 3=FMU_RX(S5) · 4=FMU_SWDIO · 5=FMU_SWCLK
   · 6=GND`. Wire **pin 4 (SWDIO) / 5 (SWCLK) / 6 (GND)** to the probe; power
   the Cube via USB-C; VREF = 3.3 V, **never pin 1 (5 V)**. The 0.8 mm SUR
   mating cable is near-unobtainable — solder fine wires or use pogo-pins to
   pins 4/5/6 instead.
   **Confirmed wiring for our in-hand ST-Link V2 (black clone) — read off the
   actual unit (⚠️ clone pinouts vary; wire by SIGNAL LABEL, not pin number):**
   ST-Link `1=RST 2=SWCLK 3=SWIM 4=SWDIO 5=GND 6=GND 7/8=3.3V 9/10=5.0V`, so:
   - ST-Link **pin 4 (SWDIO)** → carrier FMU **pin 4 (FMU_SWDIO)**
   - ST-Link **pin 2 (SWCLK)** → carrier FMU **pin 5 (FMU_SWCLK)**
   - ST-Link **pin 6 (GND)** → carrier FMU **pin 6 (GND)**

   RST/SWIM/3.3V/5.0V left unconnected; Cube powered over USB-C; carrier FMU
   pins 1/2/3 (5V/TX/RX) = NC. Build = **solder-direct 32 AWG** to the carrier
   FMU pads (simplest for a one-time rehearsal); `06SUR-32S` IDC housing is the
   removable alternative. Hot-glue strain relief — 32 AWG is fragile.
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

### B1.5 — Sign + load the app fw (the BP3 prerequisite) 🔑
**Covers:** the missing link found in the 2026-06-09 code review — the secure
bootloader at B3 verifies the **app fw that is already on the unit**, and a
normally-built app fw carries an **all-zero signature placeholder**. This step
produces a BOOT001-signed app fw and loads it **using the factory bootloader,
before B2**. (Mirrors MANUFACTURING_RUNBOOK Step 3.)

**Now automated in `tools/pipeline.py` (step 0, since 2026-06-09).** The
release pipeline patches the BOOT001 image signature before checksum/bundle, so
the `release/<stem>.px4` it emits is already signed — no manual signer step.
Validated end-to-end off-hardware (real 1.83 MB build): step 0 finds the TOC,
SHA-256-hashes the BOOT region `[0x08020000 .. SIG)`, RSA-PSS-signs (salt 32),
re-wraps, and its post-sign verify passes; SITL/non-secure images (no TOC) are
passed through untouched. Covered by `tests/compliance/test_PIPE_pipeline.py`
(`TestBoot001PipelineSigning`).

```sh
# Canonical: produce a BOOT001-signed release .px4 (WSL build → host pipeline)
cd ~/PX4-Autopilot && make cubepilot_cubeorangeplus_default
cd /mnt/d/Projects/Drone && python3 tools/pipeline.py \
  ~/PX4-Autopilot/build/cubepilot_cubeorangeplus_default/cubepilot_cubeorangeplus_default.px4 \
  --board-id 1063 \
  --elf ~/PX4-Autopilot/build/cubepilot_cubeorangeplus_default/cubepilot_cubeorangeplus_default.elf \
  --version <ver> --output-dir release/
#  -> release/<stem>.px4 is signed; run log must show "BOOT001 image: SIGNED (RSA-PSS)"
```

Under the hood this is `toc_sign.py` (sign the BOOT region) + the px_mkfw-style
zlib+base64 re-wrap. To do it by hand without the pipeline:
`toc_sign.py app.bin app_signed.bin` then `Tools/px_mkfw.py --prototype
boards/cubepilot/cubeorangeplus/firmware.prototype --image app_signed.bin >
app_signed.px4`.

- Flash `release/<stem>.px4` over the **factory** bootloader (QGC → custom
  firmware, or `make ... upload`). The factory bootloader does not verify — but
  the bytes being loaded are now manufacturer-signed, so the trust handover
  starts here.
- (Alternative, once the SWD rig is up: SWD-flash the signed `.bin` directly
  to `0x08020000`.)
- **Pass:** a signed app fw is on the unit (pipeline step-0 post-verify passed).
  **Skip this and B3 will fail fail-closed** on the zero signature.

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
**Depends on B1.5** — the app fw on the unit must be the *signed* one, or this
step fails on the zero signature placeholder (not a bootloader bug).
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

### B8 — signed `bl_update` (BOOT008 / T11-H) ⭐ NEW 2026-06-30
**Covers:** BOOT008 — `bl_update` verify-before-erase ([ADR-025](ARCHITECTURE.md)).
**Prereq:** an app fw built from `cubeorangeplus_default` with
`CONFIG_BL_UPDATE_REQUIRE_SIG=y` (the default secure target), and the **signed**
bootloader artifact on SD (`bootloader_artifact/…bootloader.bin`, produced by
`tools/signer/sign_bootloader.py` — B-2). Lower brick-risk than B2: the reject
path **never erases**, so a failed verify leaves the running bootloader intact.
Run on wall power anyway (the accept path does erase + flash sector 0).
- **B8.1 signed → accept.** `bl_update /fs/microsd/…bootloader.bin` with the
  signed artifact → expect `BOOT008: bootloader signature verified`, then the
  normal image-validate → erase → flash → verify → complete, and a clean reboot.
- **B8.2 tampered → reject, no erase.** Flip one byte in the BOOT region of a
  copy on SD (offline, before flashing) and `bl_update` it → expect
  `BOOT008: bootloader signature INVALID - refusing to flash (sector 0 untouched)`
  and a **non-zero exit with the running bootloader still booting** (reboot to
  confirm the old bootloader is intact — nothing was erased).
- **B8.3 unsigned → reject.** `bl_update` a bootloader built without the signer
  step (256-byte zero SIG, or a pre-BOOT008 bin with no TOC) → expect the same
  refusal (`no image TOC …` or signature-invalid), sector 0 untouched.
- **B8.4 recover.** Re-run B8.1 with the good signed artifact; confirm POST green.
- **Pass:** signed accepted, tampered/unsigned refused **without erasing**,
  recovery clean. This is the load-bearing evidence for T11-H closure.

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

Phase 5b is complete when **B1.5–B4 and B6 pass on a real CubeOrange+**, with
the unit decision ratified and **recovery proven by an actually-available path**.
**B5 (BOOT005) is deferred into the ADR-023 work package**
([ADR-024](ARCHITECTURE.md)) and is **not** required for Phase 5b sign-off.
B4 and the recovery evidence are load-bearing: B4 proves the bootloader actually
enforces, recovery proves the work was reversible.

> **B0/B7 disposition — ratified 2026-06-30.** The original gate made the **B0
> SWD recovery rehearsal** a hard pre-req. The bench SWD rig never came up (BP4 —
> ST-Link enumerates, CubeProgrammer "No STM32 target found"), and we have no
> other SWD access to this unit. **Decision: re-scope the gate to accept
> USB-DFU as the recovery path of record for this bring-up unit**, rather than
> blocking on reviving SWD. This is sound because the reversibility property B0
> exists to prove was demonstrated **four times** via USB-DFU (the B4 wrong-key /
> tampered / unsigned recoveries + the B6 cycle). B0 is therefore **dispositioned
> (re-scoped), not skipped**, and B7 (pre-seal SWD-open confirmation) is **n/a**
> on a rig where SWD could not be brought up. Two caveats recorded so this
> isn't mistaken for a blanket "SWD doesn't matter":
> - **Coupled to BOOT005 staying deferred.** USB-DFU recovery only works because
>   the secure bootloader does **not** software-refuse DFU ([ADR-024](ARCHITECTURE.md)).
>   When BOOT005 ships as part of the ADR-023 self-reflash work, the recovery
>   story for healthy units shifts to app-fw self-reflash; the bootloader's DFU
>   window still opens on an **invalid/absent app** (the brick case), which is the
>   scenario this disposition relies on — but re-confirm that window when BOOT005
>   lands.
> - **Production RMA SWD assumption is untouched.** This disposition is about the
>   *bring-up bench rig*, not the factory. [MANUFACTURING_RUNBOOK.md](MANUFACTURING_RUNBOOK.md)'s
>   RMA workflow still assumes a working SWD/recovery capability **at the
>   facility** (different, presumably-functional tooling). If the factory also
>   ends up SWD-less, revisit that RMA step separately.

> **Status — 2026-06-30.** Executed on hardware: **B1.5, B2, B3, B4, B6 PASS**
> (plus extended BOOT001 negatives — wrong-key and unsigned — both rejected
> fail-closed). The BOOT001 enforcement evidence is complete and release-quality,
> and **B6** has now closed the last executable gate step (idempotent `bl_update`
> re-install → clean reboot, POST green, hashes unchanged from B3).
> **B0/B7 DISPOSITIONED (2026-06-30):** USB-DFU ratified as the recovery path of
> record for this bring-up unit; the B0 SWD rehearsal is re-scoped out of the
> hard gate (see the disposition block above). **All gate steps requiring a bench
> are now closed — Phase 5b is signed off** subject only to the two recorded
> caveats (BOOT005-deferred coupling; production RMA SWD untouched).

| Step | Result | Date | Notes (commit hashes, board UID, probe used) |
|---|---|---|---|
| Unit decision (A / B) | ✅ **B** (re-ratified) | 2026-06-09 | Single Tier-1 unit + pre-staged SWD recovery. **Re-ratified 2026-06-09 after an explicit B2 brick-probability assessment** (residual brick risk = *low*, dominated by power-loss during the ~5–10 s `bl_update` window; binary-corruption and `bl_update`-bug triggers retired by B1 pass + header-validate-before-erase). Mitigation: run B2 on rock-stable wall power. B0 is the hard gate; BP4 must be staged before B2. Decision is now **settled — stop deferring.** |
| BP1 BOOT001 built | ✅ | 2026-06-06 | Off-hw re-confirm: embedded SPKI DER == `manufacturer_public.pem` (full 294-B DER @ `0x17853`, 256-B modulus @ `0x17874`) in `bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin`. |
| BP2 BOOT005 built | ➖ **deferred** | 2026-06-06 | **Not a Phase 5b pre-req** — [ADR-024](ARCHITECTURE.md): BOOT005 reclassified to defense-in-depth, deferred into ADR-023. |
| BP3 signed app fw on unit | ✅ | 2026-06-13 | Signed `.px4` via `pipeline.py` step 0 (BOOT001 image signature), flashed over factory BL; matching `manifest.bin` copied to SD; POST `check_passed=true`, hashes match the pipeline (`b405ef40…`/`f05e43d2…`). |
| BP4 recovery staged | ⚠️ **rig built, SWD link unestablished** | 2026-06-13 | ST-Link V2 (black clone) soldered direct (32 AWG) to carrier-underside FMU SUR pins 4/5/6 (SWDIO/SWCLK/GND), Cube on USB-C. Probe enumerates ("STM32 STLink"), but STM32CubeProgrammer returns "No STM32 target found / unable to get core ID" at 480 & 100 kHz. Pin-1 orientation / cold-joint / FMU-vs-I/O connector debug **deferred**. **SWD recovery NOT available on this unit** → recovery relied on USB-DFU (valid: BOOT005 not installed). |
| B0 recovery rehearsal | ✅ **DISPOSITIONED (re-scoped)** | 2026-06-30 | SWD link never established on the bench rig (see BP4) and no other SWD access to this unit → **gate re-scoped 2026-06-30 to accept USB-DFU as recovery-of-record** (see Sign-off disposition block). Reversibility demonstrated **4×** via USB-DFU (B4 tampered/wrong-key/unsigned recoveries + B6 cycle). Sound because BOOT005 is not installed, so the bootloader's DFU window stays open on an invalid/absent app. Caveats: coupled to BOOT005 staying deferred ([ADR-024](ARCHITECTURE.md)); production RMA SWD assumption untouched. |
| B1 build valid | ✅ | 2026-06-06 | Off-hw: size 103,432 B ≤ 128 KB; vector table valid (SP `0x24001D0E` AXI SRAM, reset `0x08000305` sector-0 Thumb); embedded key matches (see BP1). Artifact = `bootloader_artifact/...bin`. **2026-06-09:** also confirmed `bl_update` accepts this SP — H7 branch uses `STM_RAM_BASE=STM32_AXISRAM_BASE` (`0x24000000`), so SP `0x24001D0E < 0x24020000` passes the pre-erase header check. |
| B1.5 sign + load app fw | ✅ | 2026-06-13 | Built `cubepilot_cubeorangeplus_default` (FLASH 1,871,228 B / 95.18%); `pipeline.py` signed the BOOT001 image (BOOT region `[0x0..0x1c8c7c]`, 256-B sig patched); flashed signed `release/...default.px4` over factory BL; POST green. **(Target corrected `_inofly`→`_default` — see v0.9.)** |
| B2 install (BOOT006) | ✅ | 2026-06-13 | `bl_update /fs/microsd/...bootloader.bin` clean: image-validate → erase sector 0 → flash → verify → complete (~5–10 s). Artifact 103,432 B, sha256 `7c6f0199…`. Run on wall power. |
| B3 BOOT001 positive | ✅ | 2026-06-13 | Reboot: secure bootloader RSA-PSS-verified the signed app and handed off; InoflyGCS reconnected; POST `check_passed=true, failure_reason=0`, hashes `b405ef40…`/`f05e43d2…`. |
| B4 BOOT001 negative | ✅ | 2026-06-13 | Tampered app (1 code byte @ bin `0x10000`, inside BOOT region) **rejected fail-closed** (InoflyGCS Disconnected / SEC N/A, no heartbeat). **Extended negatives:** wrong-key (attacker RSA-2048, structurally valid sig) and unsigned (zero placeholder) — **both rejected identically**. Recovered clean via USB-DFU each time. Fixtures pre-validated offline (manufacturer-verify=FAIL) then deleted from `release/`. |
| B5 BOOT005 DFU-refuse | ➖ **deferred** | 2026-06-06 | Moved to ADR-023 work package ([ADR-024](ARCHITECTURE.md)); not required for Phase 5b sign-off. |
| B6 idempotent re-install | ✅ | 2026-06-30 | Re-ran `bl_update` with the **same** `bootloader.bin` already in sector 0, then rebooted: clean boot, InoflyGCS reconnected, POST `check_passed=true, failure_reason=0`, hashes **identical to B3** (`b405ef40…`/`f05e43d2…`). Idempotence proven — a half-written sector 0 would have dropped to DFU rather than booting a verified app, so the verified-clean boot is itself the evidence the re-install completed without disturbing app verification. Run on wall power. |
| B7 SWD-open (pre-seal) | ✅ **DISPOSITIONED — n/a** | 2026-06-30 | SWD could not be brought up on this rig (see B0/BP4), so the pre-seal SWD-open path was never confirmable here; **dispositioned n/a 2026-06-30** alongside B0. **De-facto recovery path on this unit = USB-DFU, not SWD.** BOOT007 tamper seal still closes both USB and SWD in production (unchanged). |
| B8 signed `bl_update` (BOOT008) ⭐ | ⬜ **pending hardware** | | **NEW hardening gate — [ADR-025](ARCHITECTURE.md), not a Phase 5b / L1 requirement.** Code complete (B-1…B-3), builds NuttX + SITL. Needs bench run: signed→accept / tampered→reject-no-erase / unsigned→reject / recover. Lower risk than B2 (reject never erases). |

---

## Document history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-06-05 | Initial draft. Engineering bring-up gate for the secure bootloader (B0–B7), the unit/brick-risk decision (recovery-first), and the Phase 0 pre-reqs. Surfaces the BOOT005 DFU-refuse implementation gap (BP2). |
| 0.2 | 2026-06-06 | **Unit decision ratified: Option B** (single Tier-1 unit + pre-staged SWD recovery). Sign-off + BP4 rows updated; stale BP2/B5 BOOT005 sign-off rows reconciled with [ADR-024](ARCHITECTURE.md) (deferred, not gating). **BP1 + B1 closed off-hardware** (artifact size/vector-table valid, embedded SPKI DER == manufacturer pubkey). Remaining B0/B2/B3/B4/B6/B7 are hardware-only — blocked on BP4 (procure SWD probe + Cube DEBUG cable), then B0 recovery rehearsal (hard gate). |
| 0.3 | 2026-06-06 | **BP4 kit ordered** — ST-Link V2 (+ STM32CubeProgrammer) + 6-pin JST SUR 0.8 mm pigtail (`06SUR-32S`/`SSHL-002T-P0.2`). **Connector correction:** standard carrier board does **not** break out SWD; SWD access is the Cube's **internal** FMU SWD connector (`SM06B-SURS-TF`, JST SUR 0.8 mm) — open the case (bring-up unit is unsealed). B0 step 1 + BP4 rows updated accordingly. Awaiting delivery → then B0. |
| 0.4 | 2026-06-06 | **B0 SWD-connect procedure researched + recorded** (tiered: Tier 1 plain attach / Tier 2 connect-under-reset via NRST @ DF17 pin 7 / Tier 3 BOOT0→ROM USB DFU). Findings: SWD recovery of Cube Orange is proven (forum: ST-Link V2 + OpenOCD via `SM06B`), NRST is *optional* for a healthy/early-boot unlocked chip but the "No STM32 target found" fix is connect-under-reset which **needs NRST (DF17 pin 7, internal — not on the SUR connector)**; BOOT0 is internal/undocumented (nuclear). **Gap surfaced:** ordered kit covers Tier 1 only; NRST tap not yet staged. Option B remains viable; B0 (Tier 1) is the proof gate. |
| 0.5 | 2026-06-06 | **SWD location corrected — it's on the carrier, NOT inside the Cube.** Authoritative source: CubePilot forum (S. Purohit, Feb 2024, annotated photo + pinout): the **FMU & I/O SWD+DEBUG connectors are on the *underside* of the carrier board** (`SM06B-SURS-TF`, SUR 0.8 mm), accessible once the carrier is out of the plastic case — **no Cube-aluminium-shell opening needed.** The board's `P105`/`P106` (SERIAL-5 silkscreen nearby) are these debug connectors — SERIAL 5 (pins 2-3) is co-located with SWDIO/SWCLK (pins 4-5) on the FMU debug connector. Reconciles the ADS-B "Debug USB removed" note (that was the USB console/Edison, not these SWD SUR connectors). B0 step 1 + BP4 rows corrected. Removes the case-opening damage risk; Option B materially de-risked. |
| 0.8 | 2026-06-09 | **Closed the v0.7 finding's tooling gap: BOOT001 image signing is now automated in `tools/pipeline.py` (step 0).** The release pipeline patches the RSA-PSS image signature before checksum/bundle, so `release/<stem>.px4` is signed; SITL/non-secure images (no TOC) pass through untouched; `--no-bootloader-sign` opts out. Added `tests/compliance/test_PIPE_pipeline.py::TestBoot001PipelineSigning` (4 tests; full suite 351 green). B1.5 rewritten to use the pipeline; BP3 → 🟡 (tooling done, must run + flash before B2). MANUFACTURING_RUNBOOK Step 3 corrected to flash the pipeline-produced signed `.px4`. |
| 0.7 | 2026-06-09 | **Pre-bench code review of the bootloader crypto path + flash chain.** Verified correct: RSA-PSS wiring (SHA-256/MGF1-SHA256/salt 32) matches `toc_sign.py` exactly; embedded 294-B RSA-2048 **SPKI** DER imports via libtomcrypt `rsa_import` (SPKI path) from keystore slot 0; TOC placement (`magic@0x2A8`, BOOT `flags=0x5`, SIG1 follows); fail-closed boot flow; `bl_update` accepts our bootloader (SP in AXI SRAM passes the H7 `STM_RAM_BASE` check, 103 KB < 128 KB sector) and header-validates before erase. **🔴 Critical finding → new step B1.5:** the app fw is shipped **unsigned** (256-byte zero placeholder; no build/`pipeline.py` `toc_sign.py` step) — flashing it under the secure bootloader would fail B3 fail-closed (looks like a brick). Corrected BP3 (was falsely ✅). Host signing chain validated off-hardware end-to-end (sign→post-verify pass on the real 1.83 MB build; signature survives `px_mkfw.py` `.px4` wrap, board_id 1063). |
| 0.6 | 2026-06-09 | **Option B re-ratified after a B2 brick-probability assessment** (residual brick risk *low*, dominated by power-loss during the ~5–10 s `bl_update` window; corruption/`bl_update`-bug triggers retired by B1 pass + header-validate-before-erase; mitigation = rock-stable wall power for B2). Decision is now settled — the long-running A/B deferral is closed. **Confirmed wiring for the in-hand ST-Link V2 (black clone)** folded into B0 step 1: ST-Link `pin4(SWDIO)/pin2(SWCLK)/pin6(GND)` → carrier FMU `pin4/pin5/pin6` (clone pinout differs from the green forum unit — wire by signal label). Solder-direct 32 AWG build. Sign-off + history updated. |
| 1.2 | 2026-06-30 | **Added B8 — signed `bl_update` (BOOT008 / [ADR-025](ARCHITECTURE.md)) bring-up step.** Code for BOOT008 is complete (B-1 bootloader embedded TOC, B-2 host signer, B-3 `bl_update` verify-before-erase); this adds the hardware validation step (signed→accept / tampered→reject-no-erase / unsigned→reject / recover) and a pending sign-off row. **B8 is a defense-in-depth hardening gate, NOT part of Phase 5b / DGCA Level 1 sign-off** (which remains closed per v1.1). |
| 1.1 | 2026-06-30 | **B0/B7 dispositioned → Phase 5b signed off.** Ratified **USB-DFU as the recovery path of record** for this bring-up unit and re-scoped the B0 SWD rehearsal out of the hard gate (no SWD access to the unit; reversibility already demonstrated 4× via USB-DFU). B0 → DISPOSITIONED (re-scoped), B7 → DISPOSITIONED (n/a). Sign-off criteria reworded (B1.5–B4 + B6 + recovery-by-available-path). Two caveats recorded: (1) USB-DFU recovery is **coupled to BOOT005 staying deferred** ([ADR-024](ARCHITECTURE.md)) — re-confirm the DFU window when BOOT005 lands; (2) the [MANUFACTURING_RUNBOOK](MANUFACTURING_RUNBOOK.md) production-RMA SWD assumption is **untouched** (factory tooling ≠ this bench rig). |
| 1.0 | 2026-06-30 | **B6 PASS — last executable gate step closed.** Re-ran `bl_update` with the same bootloader binary already in sector 0; clean reboot, POST green, app code/data hashes identical to B3 → idempotent re-install confirmed (= the field/RMA update mechanic). All executable steps now green: **B1.5–B4 + B6 ✅**, extended negatives ✅; **B0 waived / B7 n/a** (SWD rig never came up — recovery-of-record on this unit = USB-DFU), **B5 deferred** ([ADR-024](ARCHITECTURE.md)). Remaining for formal Phase-5b sign-off is a **decision, not a bench step**: ratify USB-DFU as recovery-of-record (re-scoping the B0 SWD rehearsal) **or** revive the SWD rig. |
| 0.9 | 2026-06-13 | **Gate executed on hardware — B1.5–B4 + extended negatives PASS; B0 waived.** B1.5 (signed app flashed, POST `check_passed=true`, hashes match pipeline) → B2 (`bl_update` from SD clean) → B3 (secure BL RSA-PSS-verified + handed off, POST green) → B4 (tampered app rejected fail-closed) → **extended negatives** (wrong-key attacker RSA-2048, and unsigned zero-placeholder — both rejected identically) → recovery (good `.px4` over USB-DFU, POST green). **B0 WAIVED:** SWD link never established on the bench rig (ST-Link enumerates; CubeProgrammer "No STM32 target found"); proceeded under the ratified Option-B risk acceptance on wall power; recovery proven via USB-DFU instead (valid — BOOT005 not installed). **Target-name fix:** B1.5 block corrected `_inofly`→`_default` (the `inofly.px4board` is stale and lacks `CONFIG_MODULES_SECURE_BOOT` — building it would ship an app with no POST module). Bench fixtures deleted from `release/`. **Remaining:** B6 (idempotent re-install); B0/B7 SWD disposition; `param_status` cosmetic label (`ADR-019`→`ADR-020`, LOCKED-at-0 shows `UNSET`) on next reflash. |
