# Tools Reference — Testing & Manufacturing Toolchain
## For the DGCA §7.1 evaluation

**Purpose.** Explains every tool and script the auditor will see during the demo — what it does, which requirement it serves, and how it is invoked. Grouped by role: manufacturer signing pipeline, provisioning, verification, and fixture generation.

**Last updated:** 2026-07-10

> All tools run with Python 3.13 from the repo root (`d:\Projects\Drone`). On Windows use `py -3`; in WSL use `python3`. OpenSSL is the host crypto backend; the flight module uses libtomcrypt (they interoperate on RSA-PSS/SHA-256).

---

## 1. Manufacturer signing pipeline

These run **offline on the manufacturer's machine**, where the private key lives. They turn a built firmware image into signed, provisionable artifacts.

### `tools/pipeline.py` — full release pipeline (one command)
- **Requirement:** PIPE (chains CHK001 → SIG001 → PKG001 → PRV001), BOOT008.
- **Does:** takes a `.px4` firmware image and runs the whole chain — computes the separate code/data SHA-256 checksums, signs the manifest (RSA-PSS), builds the distributable `.fwbundle`, and exports the 373-byte binary manifest for the flight module. On hardware builds, `--elf` makes it hash the exact flash ranges the device re-hashes at POST, and it also signs the bootloader image (BOOT008).
- **Run:**
  ```bash
  python tools/pipeline.py <firmware.px4> --output-dir release/
  # hardware:
  python tools/pipeline.py <fw.px4> --board-id 1063 --elf <fw.elf> --output-dir release/
  ```
- **Outputs:** `release/<name>_manifest.json` (checksums, for CB), `_signed.json` (signed wrapper), `_manifest.bin` (for FM), `.fwbundle` (for GCS).

### `tools/checksum/checksum.py` — CHK001
- **Does:** computes SHA-256 of the **code part** and the **data part separately** (code = firmware + read-only data excluding the `.compliance_params` table; data = the compliance-parameter flash table). Produces the manifest JSON with both hashes.
- **Why separate:** DGCA §7.1 a.ii(b) — lets data/parameters be revised in future without re-checksumming code.

### `tools/signer/signer.py` — SIG001
- **Does:** signs the manifest with the manufacturer **private key** using RSA-PSS (SHA-256, MGF1-SHA256, salt=32). Emits a base64 signature in a JSON bundle. Proves the checksums were produced by the legitimate manufacturer and are unaltered.

### `tools/bundler/bundler.py` — PKG001
- **Does:** packages the firmware `.px4` + the signed manifest (+ the binary `update_manifest.bin`) into a single `.fwbundle` (zip). This is the one file the operator receives and loads in the GCS. Any modification breaks the signature.

### `tools/pki/keygen.py` — ROT001
- **Does:** generates the RSA-2048 manufacturer keypair. Private key → `pki/manufacturer/private/` (never committed). Public key → `pki/manufacturer/public/manufacturer_public.pem` (retained for the CB — the root-of-trust verification key).
- **Note:** run once at manufacturer setup. Not run during the demo — the keypair already exists.

### `tools/pki/embed_pubkey.py` — ROT002
- **Does:** converts the public-key PEM to a C header (`firmware/include/manufacturer_pubkey.h`, DER SubjectPublicKeyInfo, ~294 bytes) so it can be compiled into the firmware and bootloader. This is the key the FM verifies every signature against.

### `tools/signer/toc_sign.py` / `tools/signer/sign_bootloader.py` — BOOT001 / BOOT008
- **`toc_sign.py`:** TOC-aware signer for the verifying bootloader — signs the app-firmware image so the bootloader can verify it at launch (BOOT001).
- **`sign_bootloader.py`:** signs the secure **bootloader** `.bin` so on-device `bl_update` verifies it before erasing sector 0 (BOOT008). Manufacturing one-liner after building the bootloader target.

---

## 2. Provisioning (onto the flight module / SITL)

### `tools/provisioning/export_manifest.py` — PRV001
- **Does:** converts the signed JSON bundle to the compact **binary manifest** (`manifest.bin`) the NuttX firmware reads at boot (JSON can't be parsed efficiently at boot). Magic `INOFLY03`, format v3: hashes + board_id + version + RSA-PSS signature + CRC32.
- **Self-check:** `--verify` re-validates CRC + signature before you provision. Expected: `Verification: passed`.

### `tools/provisioning/provision_sitl.py` — SITL bring-up
- **Does:** generates a manifest from the test bundle, signs it, and writes `manifest.bin` into SITL storage so `secure_boot` POST has a real manifest to check. Used only on the SITL track.

### `tools/provisioning/provision_signing_key.py` — PAIR001
- **Does:** derives the 32-byte MAVLink signing key as `SHA256(passphrase)` and writes the 40-byte key file to the drone's SD (`mavlink/mavlink-signing-key.bin`). The operator types the **same passphrase** into QGC, which derives the same key — so only that GCS can command the drone. Records only the key's SHA-256 fingerprint on the manufacturer side (never the passphrase).
- **Run:**
  ```bash
  python tools/provisioning/provision_signing_key.py --drone-id DEMO01 --passphrase dgca_sitl_test
  ```

---

## 3. Verification (offline, manufacturer/CB side)

### `tools/verify_audit_log.py` — LOG001 verification
- **Does:** proves a downloaded audit log is authentic and untampered. Decrypts `audit_log.sig` with the **private key**, computes SHA-256 of `audit_log.bin`, and compares. Prints `PASS: audit log signature is authentic` (exit 0) or fails if the log was edited.
- **Run:**
  ```bash
  python tools/verify_audit_log.py --log audit_log.bin --sig audit_log.sig \
      --key pki/manufacturer/private/manufacturer_private.pem
  ```

### `tools/decode_audit_log.py` — LOG001 human-readable render
- **Does:** renders the binary audit log in plain English with IST + UTC timestamps — POST results (pass and fail), firmware-update attempts, arming blocks, compliance-parameter violations. Optionally runs the signature check in the same call (`--key`).
- **Run:** `python tools/decode_audit_log.py audit_log.bin`

### `tools/generate_compliance_report.py` — Phase 6.5
- **Does:** runs the full pytest suite (358 tests) and generates the requirement-by-requirement compliance matrix (`Docs/compliance_report.txt` + `.json`) — the machine-checked evidence to hand the auditor first.
- **Run:** `python tools/generate_compliance_report.py --run-tests`

---

## 4. Fixture generators (for the negative-path demonstrations)

These create the artifacts used to demonstrate that tampered/unauthorized inputs are rejected. Outputs are gitignored (test fixtures, not shipped).

### `tools/regenerate_test_fixtures.py` — UPD001 positive/negative
- **Does:** creates `test_firmware.fwbundle` (correctly signed — must PASS) and `test_firmware_tampered.fwbundle` (signed then one signature byte flipped — must FAIL). Used in demo D5/D6.

### `tools/regenerate_attacker_fixtures.py` — signature-mismatch path (reason=3)
- **Does:** creates artifacts **correctly signed with a non-manufacturer (attacker) keypair** — valid CRC, valid structure, but the signature fails against the embedded manufacturer public key. Exercises the RSA-PSS branch (reason=3), which byte-flip tests never reach. Aborts if any artifact accidentally verifies under the manufacturer key. Output in `.attacker_fixtures/`.

### `tools/make_hash_mismatch_manifest.py` — organic hash mismatch (reason 4/5, hardware)
- **Does:** takes a real validly-signed manifest, swaps `code_hash` (or keeps code correct and swaps `data_hash`), then **re-signs with the manufacturer key**. CRC and signature both pass on-device, so POST reaches the hash comparison and fails with reason=4 (code) or reason=5 (data) against real flash. This proves the on-silicon hash-compute itself is correct — the one thing SITL cannot show.
- **Run:** `python tools/make_hash_mismatch_manifest.py <manifest.bin> --mutate code --output <out.bin>`

### `tools/make_wrong_boardid_manifest.py` — board_id mismatch (update reason=4, hardware)
- **Does:** rewrites `board_id` in a real manifest and re-signs. Staged as `update_manifest.bin`, `secure_boot verify_update` rejects it with reason=4 (board_id mismatch) against the real STM32-derived board_id. Refuses to emit a value equal to the compiled board_id so the fixture can't false-pass.

---

## 5. On-device console commands (flight module)

Not host tools, but the auditor will see these at the `nsh>` / `pxh>` console. Full list in [AUDIT_DEMO_SCRIPT.md](AUDIT_DEMO_SCRIPT.md) Appendix A.

| Command | Purpose |
|---|---|
| `listener firmware_integrity_status` | Show the POST result (pass/fail + reason, code/data hashes) |
| `secure_boot audit_status` | Audit-log entry count / state |
| `secure_boot param_status` | Compliance-parameter guard state |
| `secure_boot verify_update` / `clear_update` | Verify / drop a staged firmware update |
| `param show/set <NAME>` | Exercise compliance-parameter enforcement (D7) |
| `commander check` / `commander arm` | Exercise the arming gate |

---

## 6. Quick tool → requirement → demo index

| Tool | Requirement | Demo step |
|---|---|---|
| `pipeline.py` | PIPE / CHK001 / SIG001 / PKG001 / PRV001 | D2 |
| `checksum.py` | CHK001 | D2 |
| `signer.py` | SIG001 | D2 |
| `bundler.py` | PKG001 | D5 |
| `keygen.py` / `embed_pubkey.py` | ROT001 / ROT002 | D1 |
| `export_manifest.py` | PRV001 | D2 (hardware provisioning) |
| `provision_signing_key.py` | PAIR001 | D8 |
| `verify_audit_log.py` / `decode_audit_log.py` | LOG001 | D9 |
| `generate_compliance_report.py` | Phase 6.5 (all) | D0 |
| `regenerate_test_fixtures.py` | UPD001 | D5 / D6 |
| `regenerate_attacker_fixtures.py` | UPD001 (reason=3) | D6 |
| `make_hash_mismatch_manifest.py` | POST002/003 (reason 4/5) | D4-b |
| `make_wrong_boardid_manifest.py` | POST004 / UPD001 (reason=4) | (hardware H15) |
