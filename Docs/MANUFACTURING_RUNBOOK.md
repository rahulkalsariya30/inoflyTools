# Manufacturing Runbook — Production Unit Provisioning

**Document version:** 1.0 (initial)
**Date:** 2026-05-04
**Scope:** First-install provisioning of a CubeOrange+ unit at our
manufacturing facility, from receipt to ship.
**Authority:** [ARCHITECTURE.md §12 ADR-013/014/015](ARCHITECTURE.md),
[SECURITY_PLAN.md](../SECURITY_PLAN.md) BOOT001 / BOOT005 / BOOT006 /
BOOT007.

---

## Why this runbook exists

Under the amended (ADR-013) architecture, production-unit security
relies on three operational controls that we — the manufacturer —
must apply correctly **once per unit**, before shipping:

- **BOOT006** — Install our secure bootloader (the BOOT001 verifying
  bootloader, with BOOT005 software DFU-refuse compiled in) via PX4's
  `bl_update` mechanism.
- **BOOT007** — Apply tamper-evident seals to the airframe and the
  Cube enclosure, and record the unit's STM32 96-bit UID together
  with the seal serial in QMS.
- **First-install supply-chain trust** — verify the as-received
  factory PX4 bootloader against a known-good hash before performing
  the first signed-firmware load (this is the only step in the unit's
  lifetime where we trust an unsigned binary, and we close that
  window immediately after).

If any one of these is skipped, the unit's threat model regresses
to "dev board" (T10 / T11 / T13 high). All three are required for a
production unit cleared for regulated airspace.

This runbook also covers the corresponding **RMA workflow** for units
returning with broken seals.

> **Companion docs:**
> - Architectural rationale → [ARCHITECTURE.md](ARCHITECTURE.md)
>   ADR-013 / ADR-014 / ADR-015.
> - Threat-model boundaries (what this runbook is the compensating
>   control *for*) → [THREAT_MODEL.md](THREAT_MODEL.md) §6 and
>   T10 / T11 / T12' / T13.
> - SITL acceptance (must pass before flashing real boards) →
>   [SITL_ACCEPTANCE.md](SITL_ACCEPTANCE.md).

---

## Pre-flight (one-time, before the first unit)

Before running this runbook on any unit, the following must be in
place. These are configuration items, not per-unit steps.

| # | Item | Status check |
|---|------|--------------|
| P1 | Secure bootloader build target available (`cubeorangeplus_bootloader_secure` with `INOFLY_SECURE_BL`) | Build succeeds; binary signed with manufacturer key |
| P2 | Dev bootloader build target available (`cubeorangeplus_bootloader_dev`, no DFU-refuse) | Build succeeds; used only for dev boards, never shipped |
| P3 | Manufacturer keypair generated and the public key embedded in both bootloader binary and app fw at build time (sourced from `pki/manufacturer/public/manufacturer_public.pem`) | `tools/pki/embed_pubkey.py` round-trip green |
| P4 | Factory PX4 bootloader reference hash documented (the unsigned bootloader Hex ships with) | Reference hash recorded in this runbook (Appendix A) and in QMS |
| P5 | Tamper-evident seal vendor + part number selected, stock on hand | Vendor + PN recorded in this runbook (Appendix B); rolling stock visible |
| P6 | QMS entry template for per-unit record exists | Template fields: STM32 96-bit UID, seal serial(s), manufacture date, signed app fw version, signed bootloader version |
| P7 | SITL acceptance passes for the current build | [SITL_ACCEPTANCE.md](SITL_ACCEPTANCE.md) checklist 100% |
| P8 | Dry-run of this runbook completed on a dev unit (no seal applied) | First-unit dry-run signoff in QMS |

If any P-row is not green, this runbook **cannot** be executed on a
production unit. Stop and resolve the gap.

---

## Per-unit provisioning sequence

Every step is required. Steps are numbered to match QMS entry fields.
Time estimate: ~30 minutes per unit once Pre-flight is settled.

### Step 1 — Receive

- Inspect the as-shipped Hex packaging for tamper damage. If the Hex
  factory seal is broken on receipt, **quarantine** the unit and
  open a supplier RMA with Hex. Do not proceed.
- Record the Hex packaging serial in QMS.

### Step 2 — Verify factory bootloader hash

- Connect CubeOrange+ to the provisioning host via USB.
- Read sector 0 (bootloader region, 128 KB at `0x08000000`) using
  the provisioning host's read tool. *This step uses the standard
  Hex-shipped factory PX4 bootloader, which is still trusted at
  this point.*
- Compute SHA-256 of the read bytes.
- Compare against the **factory bootloader reference hash**
  (Appendix A).
- If the hash matches → record `factory_bl_hash_ok = true` in QMS
  and continue.
- If the hash does **not** match → **quarantine** the unit. Do not
  proceed. This indicates a supply-chain compromise (factory
  bootloader differs from our reference), or our reference hash is
  stale (check Appendix A's "as of" date — if Hex has updated their
  factory bootloader, validate the new one and update Appendix A
  before processing more units).

> **Why this step matters.** The factory PX4 bootloader trusts
> anything — it is the one supply-chain trust window in the unit's
> lifetime. Every later install path (BOOT001, BOOT006) is gated by
> signature verification, but Step 3 below uses the factory
> bootloader to load our first signed app fw. We need to verify the
> factory bootloader *itself* before that load, otherwise an attacker
> in the supply chain could have substituted a backdoored factory
> bootloader. See [THREAT_MODEL.md §7.4 residual risk #4](THREAT_MODEL.md).

### Step 3 — Load first signed app fw via QGC

- Open QGroundControl on the provisioning host.
- Use Vehicle Setup → Firmware → Load Custom Firmware to load our
  **signed app fw release** (the same .fwbundle / .px4 we ship).
- The factory bootloader accepts the load (it does not verify
  signatures — but the binary we are loading is still the
  manufacturer-signed app fw, so the trust handover begins here).
- Wait for completion; observe the device reboot.
- Confirm the running app fw reports the expected version
  (`MAVLink AUTOPILOT_VERSION` or the QGC summary panel).
- Record `app_fw_version` in QMS.

### Step 4 — Install secure bootloader from SD (`bl_update`)

> **AMENDED 2026-05-24 (ADR-022 executed).** The secure bootloader is
> **no longer bundled in the app fw ROMFS** — it is installed from the SD
> card as a one-shot. (The old flow issued `flashbootloader` and the app
> fw extracted the bootloader from ROMFS; that path is retired because
> the ROMFS bundle cost ~103 KB of app FLASH.)

- Place `secure_bootloader.bin` on the SD card (copy via card reader, or
  upload via QGC MAVLink-FTP to `/fs/microsd/`). The canonical artifact
  is `boards/cubepilot/cubeorangeplus/bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin`
  in the PX4 fork — the BOOT001 bootloader with the embedded manufacturer
  pubkey.
- From QGC's MAVLink Console (or `nsh` over USB), run:
  `bl_update /fs/microsd/cubepilot_cubeorangeplus_bootloader.bin`.
  The running app fw validates the image header, erases sector 0, writes
  the secure bootloader, and verifies (~5–10 s).
- Wait for completion and reboot the device.
- Observe boot progress LEDs / serial output to confirm the secure
  bootloader is now running.
- Delete `/fs/microsd/cubepilot_cubeorangeplus_bootloader.bin` after a
  confirmed install (one-shot use).

> **Important.** From this step onward, the unit's sector 0 contains our
> secure bootloader (BOOT001 + BOOT005 + embedded manufacturer pubkey).
> DFU mode is now software-refused; `bl_update` is the only sector-0
> write path; SWD is still open until the seal is applied in Step 8.
> Because the bootloader is no longer field-updatable via OTA (ADR-022),
> a future bootloader change requires this same SD one-shot under a
> broken-seal RMA.

### Step 5 — Verify secure bootloader hash

- Read sector 0 again from the provisioning host (this is the
  *last time* sector 0 is externally readable on a production
  unit — once the seal is applied, SWD readout requires breaking
  the seal).
- Compute SHA-256 of the read bytes.
- Compare against the **secure bootloader reference hash** for the
  current build version (recorded in `pki/manufacturer/build_artifacts/`
  or equivalent build-output location).
- If the hash matches → record `secure_bl_hash_ok = true` and the
  hash value itself in QMS. Continue.
- If the hash does **not** match → re-trigger `bl_update` once
  (sometimes a flash retry resolves transient issues). If the hash
  still does not match after one retry, **quarantine** the unit and
  investigate (likely causes: build artifact corruption, ROMFS
  bundling regression in the app fw build).

### Step 6 — Verify signature enforcement (positive path)

- Reboot the unit.
- Confirm the secure bootloader successfully verifies the running
  app fw signature (BOOT001) and hands off to the app fw.
- Confirm the app fw's POST publishes `firmware_integrity_status`
  with `check_passed=true`.
- Confirm the unit reaches normal "ready" state in QGC.
- Record `boot_path_signed_ok = true` in QMS.

### Step 7 — Verify signature enforcement (negative path)

> **One-shot test that proves the chain is enforcing.** This
> step *must* fail closed; if it succeeds, the secure bootloader
> is not enforcing signatures and the unit cannot ship.

- Take an **intentionally tampered app fw** — typically a copy of
  the production app fw with a single byte flipped in the signed
  region. Keep this artifact in the manufacturing fixture only;
  do not version-control or distribute it.
- Attempt to load it via QGC's firmware-load path.
- The secure bootloader **must** refuse to launch the tampered
  binary. Expected indicators:
  - Bootloader logs the failure (LED pattern + on-flash log entry).
  - App fw does not start; QGC reports loss of MAVLink heartbeat.
  - Reboot does not recover (unit holds in bootloader-error state
    until a valid app fw is loaded).
- Re-flash the production app fw to recover the unit.
- Record `boot_path_unsigned_rejected = true` in QMS.
- If this step does **not** fail closed → **quarantine** the unit
  and investigate immediately. This indicates a regression in
  BOOT001's verification logic, which is a release-blocking bug.

### Step 8 — Apply tamper-evident seal

- Use the seal vendor + PN listed in Appendix B.
- Apply seal #1 across the airframe shell joint(s) such that
  opening the airframe to reach the Cube enclosure visibly damages
  the seal.
- Apply seal #2 across the Cube enclosure joint(s) such that
  opening the Cube to reach the SWD/JTAG / BOOT0 pads visibly
  damages the seal.
- Photograph the sealed unit (both seals visible) and attach to
  the QMS record.
- Record `seal1_serial`, `seal2_serial`, and `seal_applied_date`
  in QMS.

> **Why two seals.** SWD/JTAG and BOOT0 are physically inside the
> Cube, but the Cube is inside the airframe. A single airframe
> seal does not protect against a service-tech who legitimately
> opens the airframe for an unrelated repair (e.g. battery
> replacement). The Cube seal closes that gap.

### Step 9 — Record STM32 UID

- Read the STM32 96-bit Unique Device ID via MAVLink (the running
  app fw exposes it; alternatively, use `param show SYS_AUTOSTART_ID`
  or read register `UID_BASE = 0x1FF1E800` if needed).
- Record the UID as a hex string in QMS, paired with
  `seal1_serial` and `seal2_serial`.
- The `(UID, seal1_serial, seal2_serial)` triple is the unit's
  per-lifetime fingerprint.

### Step 10 — Final unit record

- Verify the QMS entry contains all of:
  - Hex packaging serial
  - factory_bl_hash_ok = true
  - app_fw_version
  - secure_bl_hash + secure_bl_hash_ok = true
  - boot_path_signed_ok = true
  - boot_path_unsigned_rejected = true
  - seal1_serial, seal2_serial, seal_applied_date, sealed-unit photo
  - STM32 UID
  - manufacture_date
  - QC operator signoff
- Mark the unit "ready to ship" in QMS.

### Step 11 — Ship

- Pack and ship per existing logistics SOP.
- The unit is now in the production trust state: any future
  sector-0 update has to go through `bl_update` from a
  manufacturer-signed app fw release.

---

## RMA workflow

Any unit returning to our facility — for any reason — passes through
this workflow before being re-deployed.

### RMA-1 — Receive and inspect

- Confirm the unit's STM32 UID matches the QMS record (this catches
  unit substitution at the supplier or in the field).
- Inspect both seals.

### RMA-2 — Branch on seal state

| Both seals intact and serials match QMS | Either seal broken or serial does not match |
|---|---|
| Unit is in known production state. Re-flash the latest signed app fw release if needed (via QGC, normal UPD001 path; no `bl_update` required). Update QMS entry with RMA reason and disposition. Return to service. | **Quarantine.** Do **not** re-fly without re-provisioning. |

### RMA-3 — Re-provision (broken-seal path)

- Treat the unit as untrusted. Specifically:
  - Do **not** assume the bootloader in sector 0 is still ours —
    SWD access has been possible since the seal broke.
- Re-run **the entire per-unit provisioning sequence** above,
  starting from Step 2 (verify factory bootloader hash). Note that
  Step 2 may now require a full erase + re-flash of the factory
  bootloader using SWD if the running bootloader is not the factory
  bootloader (e.g. ours has been replaced and we cannot trust it).
  This is the unhappy-path branch and may require Hex-side
  intervention; document the case in the RMA record.
- Apply **new** seals (seal #1 and seal #2) — do not reuse old
  seal serials.
- Generate a **new** QMS record (new manufacture_date) and link it
  to the original record via the STM32 UID; preserve the original
  record for audit.
- Mark the original record "RMA-reprovisioned, see record N."

### RMA-4 — Disposal of broken-seal unsuccessful re-provisioning

If RMA-3 cannot complete (e.g. factory bootloader cannot be
restored, or SWD-level damage is suspected), **destroy** the unit
according to e-waste SOP. Do not return-to-service or re-sell.
Document destruction in QMS.

---

## Audit trail

Every per-unit provisioning and every RMA passes through QMS and is
auditable. Records to be retained for the full unit lifetime + 3
years (or per the prevailing DGCA recordkeeping requirement,
whichever is longer):

- Per-unit provisioning record (Step 10 fields)
- Per-unit RMA records (each RMA-3 case generates a new linked record)
- Reference-hash updates (Appendix A revisions): date, reviewer, old
  vs. new hash
- Seal vendor / PN changes (Appendix B revisions): date, reviewer,
  old vs. new vendor + PN

---

## Appendix A — Factory bootloader reference hash

> **TBD before first production run.** Hex's factory PX4 bootloader
> is shipped pre-loaded; we need to read sector 0 from one or more
> known-good as-received units, agree on the canonical reference,
> and record it here.

| Field | Value |
|-------|-------|
| Reference hash (SHA-256) | _TBD_ |
| Hex carrier revision | CubeOrange+ (specific Hex revision TBD) |
| Bootloader version (per Hex docs, if known) | _TBD_ |
| Captured by | _Operator_ |
| Captured date | _Date_ |
| Notes | First-unit pre-flight item; see Pre-flight P4. |

When Hex updates their factory bootloader, this row needs a fresh
capture + reviewer signoff before processing the first unit of the
new revision.

---

## Appendix B — Seal vendor and part number

> **TBD before first production run.** Vendor selection is part of
> Pre-flight P5. Acceptable seal types: holographic tamper-evident,
> void-pattern destructible, or equivalent — must leave clearly
> visible damage on any peeling attempt.

| Field | Value |
|-------|-------|
| Vendor | _TBD_ |
| Part number — airframe seal | _TBD_ |
| Part number — Cube enclosure seal | _TBD_ |
| Serial range allocation method | _TBD (sequential per shipment? UID-derived?)_ |
| Selected by | _Operator_ |
| Selected date | _Date_ |

---

## Document history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-05-04 | Initial. Created as ADR-013/015 deliverable, replacing the retired RDP_BURN_RUNBOOK.md. Covers per-unit provisioning sequence, RMA workflow, and audit-trail requirements. Appendices A (factory bootloader reference hash) and B (seal vendor/PN) are placeholders to be filled before the first production run. |
