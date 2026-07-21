# Glossary — terms and acronyms

Plain-language definitions of every technical term used in this document. Nothing here is needed to understand the Executive Summary; use it while reading Parts 2–6.

## Roles and parties

| Term | Meaning |
|---|---|
| **FM (Flight Module / Firmware Manufacturer)** | Us — the party that builds and signs the flight-control firmware and enforces integrity on the drone. |
| **CB (Certification Body)** | The independent party that witnesses the tests and may counter-sign the checksums. Not us. |
| **Operator** | The end user who flies the drone. Can fly and set mission values, but cannot alter certified firmware or limits. |
| **DGCA** | Directorate General of Civil Aviation — the Indian regulator whose Certification Scheme this submission addresses. |

## Hardware and software

| Term | Meaning |
|---|---|
| **CubeOrange+** | The flight-controller hardware being certified. Contains the STM32H743 microcontroller. |
| **STM32H743** | The microcontroller (the "brain" chip) on the CubeOrange+. All security checks run here. |
| **Flight controller (FC)** | The CubeOrange+ board running the firmware. |
| **PX4** | The open-source flight-control firmware platform our firmware is based on. |
| **QGroundControl (QGC)** | The ground-station software (runs on a laptop) used to load firmware and monitor the drone. |
| **MCU** | Microcontroller unit — the STM32H743 chip. |
| **SD card** | Removable storage on the flight controller; holds the manifest, the MAVLink link-signing key, and the audit log. (The manufacturer's private signing key is never on the drone.) |

## Cryptography (the security building blocks)

| Term | Meaning |
|---|---|
| **Root of trust** | The one trusted anchor the whole system is built on — here, the manufacturer's signing key. |
| **Key pair (public / private)** | Two matching keys. The **private** key signs (kept secret by the manufacturer); the **public** key verifies signatures (built into the drone). What one signs, only the other can verify. |
| **RSA-2048** | The specific public-key cryptography and key size used. 2048-bit is a standard, widely certified strength. |
| **RSA-PSS** | The specific, modern RSA signature scheme used for every signature in the system. |
| **SHA-256** | The secure hashing algorithm (SHA-2 family) used for all checksums. Turns any file into a fixed 256-bit fingerprint; changing one bit changes the fingerprint. |
| **Signature** | A cryptographic seal made with the private key that proves "the manufacturer produced this, unaltered." Verified with the public key. |
| **Hash / checksum** | A SHA-256 fingerprint of some data. Used to detect any change. |
| **Fingerprint (of a key)** | A short SHA-256 hash identifying a specific key, so two parties can confirm they hold the same key. |
| **CCA certificate** | A document-signing digital certificate issued by India's Controller of Certifying Authorities. The intended production source of the manufacturer key. |
| **libtomcrypt / OpenSSL** | The cryptography software libraries. libtomcrypt runs the checks on the drone; OpenSSL does the signing on the manufacturer's computer. They interoperate. |

## Firmware integrity concepts

| Term | Meaning |
|---|---|
| **Manifest** | A small signed file on the drone holding the registered checksums (code + data), the board ID, and the manufacturer signature. The drone checks against this at boot. |
| **Registered checksum** | The official SHA-256 checksum of the certified firmware, submitted to the CB and stored in the manifest. |
| **Code hash** | The SHA-256 checksum of the firmware **code** section. |
| **Data hash** | The SHA-256 checksum of the firmware **data** section — the table holding the certified flight-parameter values. Kept separate from the code hash so parameters can be revised independently. |
| **POST (Power-On Self-Test)** | The integrity self-check the drone runs automatically at every power-on: it re-computes the checksums from live memory and verifies the signature, then decides whether the drone may arm. |
| **Arming** | Enabling the motors so the drone can fly. A failed POST **blocks arming** — the drone cannot take off. |
| **Board ID** | A number identifying the hardware model (CubeOrange+ = 1063). Prevents firmware for one board running on another. |
| **Bootloader / verifying bootloader** | The first code that runs at power-on. Ours **verifies the firmware's signature** before launching it — an unsigned firmware won't run. |
| **bl_update** | The controlled mechanism used to install/update the bootloader; it verifies a signature before writing. |

## Runtime and update concepts

| Term | Meaning |
|---|---|
| **Update bundle (.fwbundle)** | The single signed file the operator loads in the ground station to update firmware. Contains the firmware plus its signed manifest. |
| **verify_update** | The on-drone check that inspects a staged update and accepts it only if the manufacturer signature (and board ID) are valid. |
| **Reason code** | A number the drone reports saying **why** a check failed. POST: 1 = manifest missing, 2 = checksum/CRC, 3 = signature, 4 = code changed, 5 = data/parameters changed, 6 = wrong board. Update staging uses its own shorter list (2 = corrupt, 3 = signature, 4 = wrong board), so an update rejection with reason 4 means wrong board, not changed code. These make each test result unambiguous. |
| **CRC (CRC32)** | A quick corruption check on a file. A broken CRC (reason 2) means the file was damaged or altered. |
| **Audit log** | The drone's **security event log** (SD card): every POST result, update attempt, and blocked parameter change. Signed so tampering is detectable. Different from the flight telemetry log. |
| **uORB** | PX4's internal messaging system; how the POST result is published to the arming logic. (Implementation detail.) |

## Flight-parameter protection

| Term | Meaning |
|---|---|
| **Compliance parameter** | A safety-critical setting the certificate controls (max altitude, max speed, fence range, airframe type, signing mode). Its certified value is compiled into the signed firmware. |
| **CAPPED parameter** | A tunable mission limit (e.g. max altitude 120 m). The operator may set any value **up to** the certified ceiling for a flight, but never above it; the setting does not persist across reboots. |
| **LOCKED parameter** | A fixed configuration (e.g. airframe type). The operator cannot change it at all; only a signed firmware release can. |
| **MAVLink signing** | Authentication of the link between the ground station and the drone. Only a ground station that knows the drone's passphrase (which derives the key) can command it. |

## Physical protection

| Term | Meaning |
|---|---|
| **Tamper-evident seal** | A serialized physical seal on the airframe and enclosure. Reaching the debug port to bypass software protection requires visibly breaking it; broken seals are caught on return inspection. |
| **TPM / TEE** | Dedicated hardware security modules (a Trusted Platform Module or Trusted Execution Environment). The STM32H743 has neither; we achieve Level 1 in software plus the verifying bootloader and seal — see Part 4. |

## Internal identifiers (appear in evidence)

Requirement and decision IDs such as **POST001–004, UPD001, PAR001, PAIR001, LOG001, ROT001/002, BOOT001–008, ADR-nnn** are our internal traceability labels linking a requirement to its code and tests. An auditor does not need to memorize them; each is explained where it first appears, and the full list is in the traceability table at the end of Part 3.
