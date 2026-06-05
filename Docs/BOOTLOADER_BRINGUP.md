# Secure Bootloader Bring-Up Gate (Phase 5b) — Engineering Acceptance

**Document version:** 0.1 (draft, 2026-06-05)
**Scope:** First-ever proof, on real CubeOrange+ silicon, that the
**secure bootloader** (BOOT001 verify + BOOT005 DFU-refuse, installed via
BOOT006 `bl_update`) builds, installs, enforces signatures, and hands off
to the app fw — **and** that a bad install is recoverable.
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
**happy-path production version** of B2–B5 below. This gate proves those
steps actually work on real hardware the *first* time, adds the
**recovery rehearsal (B0)** the runbook's happy path omits, and front-loads
the **implementation-status pre-reqs** the runbook assumes are already met
(see "Pre-reqs" — at least one, BOOT005, is currently unconfirmed).

**No SITL pre-gate for most of this.** Unlike the H-series (each mirrors a
SITL §-step), the bootloader is hardware-boot code — it does not run under
SITL. B1 (build) is the only step provable off-hardware. Everything from B2
on is hardware-only, which is exactly why the recovery story (B0) is the
first gate, not an afterthought.

---

## ⚠️ DECISION REQUIRED — which unit, and the brick risk

Installing the secure bootloader is the **only irreversible-ish step in the
whole program.** After BOOT006 + BOOT005:

- Sector 0 holds *our* bootloader; the factory bootloader is gone.
- DFU is **software-refused** (BOOT005) — the normal "hold BOOT0, re-flash
  over USB" recovery path is closed by our own code.
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
| BP2 | **BOOT005 DFU-refuse is built in.** ADR-014 specifies the secure bootloader software-refuses DFU (ArduPilot pattern). | **CONFIRMED NOT IMPLEMENTED** (2026-06-05). `platforms/nuttx/src/bootloader/stm/stm32_common/main.c` still uses stock PX4 mode-select: `jump_to_app()` on a valid app, else it drops into `bootloader(timeout)` — the standard DFU/USB upload loop — on USB-connect / no-app / timeout. The only Inofly change is BOOT001 (TOC verify, `bl.c:330`). No DFU-refuse exists, and no `bootloader_secure`/`bootloader_dev` split (runbook P1/P2 are aspirational). **Must be implemented** before B5. | ❌ **gap — implement (ADR-014)** |
| BP3 | **Signed app fw already on the unit**, manufacturer-signed (same key as the bootloader's embedded pubkey). | The Tier-1 build is signed and flashed; confirm `ver all` matches the current signed release. | ✅ (Tier 1) |
| BP4 | **Recovery toolchain staged** (Option B) or **spare unit ready** (Option A). | Probe + Cube DEBUG cable on hand; known-good factory sector-0 image captured (MANUFACTURING_RUNBOOK Step 2 reference hash / dump). | ⬜ decision-gated |
| BP5 | **App-fw Tier 1 green on the build under test** (H0–H15, H8 carried). | [HARDWARE_ACCEPTANCE.md sign-off](HARDWARE_ACCEPTANCE.md). | ✅ |
| BP6 | **Known-good app fw `.px4` on hand** to recover the *app-fw* side of B4's negative test. | The signed release `.px4` in `release/`. | ✅ |

> **BP2 is the live blocker — and it is a code task, not just a check.**
> Confirmed 2026-06-05: BOOT005 DFU-refuse is **not implemented**; the
> bootloader still enters the standard DFU upload loop. Until it is added,
> B5 cannot pass and the unit is not in the production threat model (DFU
> stays open → the Path-A bypass ADR-014 exists to close is still open).
> The fix is a targeted change to the mode-select in
> `stm/stm32_common/main.c` (refuse the `bootloader(timeout)` DFU path on
> the secure build — ArduPilot pattern), gated so dev builds keep DFU.
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

1. With the unit running its current (factory or stock) bootloader, connect
   the SWD probe to the Cube 6-pin DEBUG port.
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

### B5 — BOOT005 DFU-refuse
**Covers:** BOOT005; closes the Path-A/DFU bypass.
**Blocked on BP2 (confirm DFU-refuse is actually built in).**
- Attempt to enter DFU/USB-bootloader mode by the documented method for this
  bootloader.
- **The secure bootloader must refuse** to enter DFU.
- **Pass:** DFU entry is refused on hardware. **Fail / not-applicable:** if
  BP2 is unresolved, B5 cannot pass — DFU is still open and the unit is not
  in the production threat model.

### B6 — `bl_update` remains the only sector-0 path / re-install idempotence
**Covers:** BOOT006 robustness.
- Re-run `bl_update` with the same binary; confirm idempotent re-install and
  a clean reboot (this is also the field-update mechanic under RMA).
- Confirm no *other* software path writes sector 0 (DFU refused per B5; SWD
  is hardware, gated by the seal in production).
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
after this gate is green.

---

## Sign-off

Phase 5b is complete when **B0–B7 pass on a real CubeOrange+** (B5 contingent
on BP2), with the unit decision ratified and recovery proven. B0 and B4 are
the load-bearing evidence: B0 proves the work was reversible, B4 proves the
bootloader actually enforces.

| Step | Result | Date | Notes (commit hashes, board UID, probe used) |
|---|---|---|---|
| Unit decision (A / B) | ⬜ | | |
| BP1 BOOT001 built | ⬜ | | |
| BP2 BOOT005 built | ⬜ | | **gap — verify/implement first** |
| BP4 recovery staged | ⬜ | | probe + cable + known-good image |
| B0 recovery rehearsal | ⬜ | | **hard gate before B2** |
| B1 build valid | ⬜ | | |
| B2 install (BOOT006) | ⬜ | | |
| B3 BOOT001 positive | ⬜ | | |
| B4 BOOT001 negative | ⬜ | | release-blocking if it boots |
| B5 BOOT005 DFU-refuse | ⬜ | | contingent on BP2 |
| B6 idempotent re-install | ⬜ | | |
| B7 SWD-open (pre-seal) | ⬜ | | expected; seal closes in production |

---

## Document history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-06-05 | Initial draft. Engineering bring-up gate for the secure bootloader (B0–B7), the unit/brick-risk decision (recovery-first), and the Phase 0 pre-reqs. Surfaces the BOOT005 DFU-refuse implementation gap (BP2). |
