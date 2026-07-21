# Executive Summary

## What this document is

This is the firmware-security compliance submission for **DGCA UAS Type Certification, Level 1**, against **Section 7.1** of the Certification Scheme for UAS. It shows, requirement by requirement, how our drone's flight-control firmware meets each condition, and provides the evidence.

## Who we are

We are the **Firmware Manufacturer** — we build and cryptographically sign the flight-control firmware, generate its checksums, and enforce integrity on the drone. We are **not** the Certification Body; the Certification Body is a separate party that witnesses the tests and may counter-sign our checksums.

## What is being certified

| | |
|---|---|
| Flight controller | CubePilot CubeOrange+ (STM32H743 microcontroller) |
| Firmware | PX4-based (our secured fork) |
| Ground control software | QGroundControl (our secured fork) |
| Exact build under certification | recorded in **Part 5 — Certified Build Identity** |

## What Section 7.1 requires, in plain terms

Section 7.1 asks a manufacturer to prove four things:

1. **Firmware tamper avoidance (7.1 a)** — the drone must refuse to operate if its firmware has been changed by anything other than an authorized, signed update. It self-checks at every power-on and blocks arming on any mismatch.
2. **Safe and secure firmware update (7.1 b)** — a firmware update is accepted only if it carries the manufacturer's digital signature; the drone verifies it, and the change is logged.
3. **Secure change of flight parameters (7.1 c)** — safety-critical settings (altitude, speed, fence, airframe) cannot be changed to unsafe values by an operator; only a signed firmware release can change the certified values.
4. **Log file signing (additional)** — the drone's security log is signed so any tampering is detectable offline.

## Compliance at a glance

| Section 7.1 area | Status | How it is achieved (plain) | Proof |
|---|---|---|---|
| a — Firmware tamper avoidance | **Conforms** | Every boot re-computes the firmware's checksums and verifies the manufacturer signature; any mismatch blocks arming and is logged. | Part 3 §1–4; Part 6 |
| b — Secure firmware update | **Conforms** | Updates are accepted only if signed by the manufacturer; verified at the ground station, on the drone, and again at boot. | Part 3 §5; Part 6 |
| c — Secure flight parameters | **Conforms** | Certified limits are compiled into the signed firmware; operators cannot exceed them; every attempt is logged. | Part 3 §6; Part 6 |
| Log signing | **Conforms** | The security log is signed with the manufacturer key; tampering is detectable offline. | Part 3 §7; Part 6 |

**Overall:** all Section 7.1 controls are **implemented and validated on real hardware** (CubeOrange+). An automated test suite of 358 checks passes. The formal declaration is in **Part 1 — Certificate of Compliance**.

## The single idea behind the whole design

One **manufacturer signing key** is the root of trust. Its secret half never leaves the manufacturer; its public half is built into the drone. The drone trusts only what that key has signed — firmware, checksums, updates, and its own log. Everything in this document is an application of that one idea.

## How to read this document

The document is organized in parts. An auditor can read them in order, or jump to Part 3:

| Part | Contents | For |
|---|---|---|
| 1 — Certificate of Compliance | The formal signed declaration + a conformance summary table + open items for the Certification Body | The headline: what we declare and where each item is evidenced |
| 2 — System Architecture | How the security works, with diagrams (trust model, boot sequence, update paths) | Context to understand Part 3 |
| 3 — §7.1 Compliance Mapping | Each Section 7.1 clause quoted, then how we satisfy it, with evidence | **The heart of the submission** |
| 4 — Annexure E Conformance | Security-level (Level 1) determination, point by point | The security-level determination, cross-checked against the Annexure E criteria |
| 5 — Certified Build Identity | The exact firmware this certificate applies to (versions, checksums, key fingerprint) | Pins the certificate to one specific build |
| 6 — Test Evidence | Captured results from the hardware tests, per clause | The proof behind the "Conforms" claims |

A **Glossary** of terms and acronyms follows this summary. Every technical term used in the parts is defined there in plain language.

## What we ask of the Certification Body

A short list of items are the Certification Body's to confirm or perform (detailed in Part 1 §5): confirm the signing-key provenance approach (we adopt a CCA certificate for production), counter-sign the registered checksums, and witness the live test session (Part 6 / the test runbook).
