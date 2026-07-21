# Production Signing Key — CCA Certificate Provisioning
## How the production manufacturer key is obtained from a CCA certificate and used in the signing chain

**Purpose.** The bench/reference builds are signed with a self-generated test key. For **production certification** the manufacturer signing key is adopted from a **CCA-issued document-signing certificate** (Controller of Certifying Authorities, Government of India), in line with common industry practice. This document is the step-by-step procedure to extract the key from the CCA certificate and wire it into our existing signing pipeline.

**Last updated:** 2026-07-10 · **Applies to:** production manufacturing only (dev/SITL continue to use the self-generated test key).

> **One-line summary:** the CCA certificate gives us a PEM private key + public key; we drop those into `pki/manufacturer/` in place of the test key, rebuild + re-embed, and **keep our existing RSA-PSS signing scheme unchanged**. The key *source* changes; the crypto does not.

---

## 0. Prerequisites and constraints — read before buying the certificate

| Constraint | Why it matters | Action |
|---|---|---|
| **The CCA certificate MUST be RSA-2048** | Our architecture is sized for RSA-2048: 256-byte signatures, ~294-byte DER public key embedded in the bootloader (sector-0 budget) and app firmware, and the 373-byte binary manifest format. An RSA-3072/4096 CCA cert would break the bootloader flash budget and the manifest layout. | When purchasing the CCA document-signing certificate, **specify RSA-2048**. Verify after extraction (step 3). |
| **Private-key exportability** | The commands below assume a soft `.PFX` file (exportable private key). Many CCA certificates ship on a **hardware crypto token** (USB, e.g. ePass/SafeNet) where the private key is **non-exportable** by policy. | Confirm with the CCA/distributor whether you are getting an **exportable `.PFX`** (Case A) or a **token-bound key** (Case B — see §6). Prefer an exportable soft certificate for this workflow. |
| **Signing scheme is ours** | A common `openssl dgst -sha256 -sign` command produces a PKCS#1 v1.5 signature. Our device verifier (libtomcrypt) expects **RSA-PSS (SHA-256, MGF1-SHA256, salt 32)**. | Use the CCA cert **only as the key source**. Do all signing with our tools (`pipeline.py` / `signer.py`), which apply RSA-PSS. Do **not** use a plain `openssl dgst` signing command. |
| **Key change = full rebuild** | The public key is compiled into both the bootloader and the app firmware, and every manifest/bundle is signed with the private key. | After swapping keys you must **rebuild firmware + bootloader, re-embed the pubkey, re-sign, and re-provision**. Treat as a key rotation (§5). |
| **Private key handling** | `-nodes` writes an **unencrypted** private key to disk. | Do this only on the **offline signing machine**. Never commit it (`pki/manufacturer/private/` is gitignored). Store the master copy on encrypted offline media / HSM. |

---

## 1. Obtain the CCA document-signing certificate

Per the reference procedure:

1. Purchase a **document-signing digital certificate** from a CCA-licensed Certifying Authority or distributor (e.g. certificate.digital). Provide the organization's legal documents as part of CA identity verification.
2. **Specify RSA-2048** (see §0).
3. Receive the certificate as a **`.PFX`** (PKCS#12) file with an import password. (Or on a hardware token — Case B, §6.)

Keep the `.PFX` and its password on the offline signing machine only.

## 2. Extract the private key into our pipeline

All commands run on the **offline signing machine**, from the repo root. Replace `cca_cert.pfx` with the actual filename.

```bash
# 2a. Extract the private key (unencrypted PEM, PKCS#8) into the manufacturer private slot.
openssl pkcs12 -in cca_cert.pfx -nocerts -nodes \
  | openssl pkcs8 -topk8 -nocrypt \
  -out pki/manufacturer/private/manufacturer_private.pem
#   (enter the .PFX import password when prompted)

# Lock down permissions (owner read/write only)
chmod 600 pki/manufacturer/private/manufacturer_private.pem
```

This overwrites the test private key with the CCA-derived one. Our `signer.py` loads this exact path via `load_pem_private_key(..., password=None)` and signs with RSA-PSS — no code change.

## 3. Derive and verify the public key

```bash
# 3a. Derive the public key from the private key into the manufacturer public slot.
openssl rsa -in pki/manufacturer/private/manufacturer_private.pem \
  -pubout -out pki/manufacturer/public/manufacturer_public.pem

# 3b. VERIFY it is RSA-2048 (must print "Public-Key: (2048 bit)").
openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -noout -text | head -1

# 3c. Record the new key fingerprint (goes into BUILD_IDENTITY.md).
openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -outform DER \
  | openssl dgst -sha256
```

If 3b does not say **2048 bit**, stop — the certificate is the wrong key size (see §0).

> The CCA certificate also contains the X.509 public certificate itself (subject = your organization, issuer = the CA). Retain the full certificate chain (`openssl pkcs12 -in cca_cert.pfx -clcerts -nokeys -out cca_cert.pem`) to give the CB, since it is what ties the public key to your legal identity — this is the actual value the CCA certificate adds over a self-generated key.

## 4. Embed the public key into firmware and bootloader

```bash
# 4a. Regenerate the C header that compiles the pubkey into the app firmware.
python tools/pki/embed_pubkey.py
#   → firmware/include/manufacturer_pubkey.h now carries the CCA-derived pubkey (DER)

# 4b. The bootloader embeds the same key from pki/manufacturer/public/manufacturer_public.pem
#     at build time — no separate step, but the bootloader MUST be rebuilt (step 5).
```

## 5. Rebuild, re-sign, re-provision (key rotation)

Because the embedded public key changed, every downstream artifact must be regenerated:

```bash
# 5a. Rebuild the app firmware (WSL) — now embeds the CCA pubkey.
cd ~/PX4-Autopilot && make cubepilot_cubeorangeplus_default

# 5b. Rebuild the secure bootloader — now embeds the CCA pubkey.
make cubepilot_cubeorangeplus_bootloader     # (target name per the fork)

# 5c. Run the full release pipeline with the CCA private key (default path is already set;
#     --private-key shown explicitly for clarity). Signs manifest + bundle + bootloader (BOOT008)
#     with the CCA key, using our RSA-PSS scheme.
BUILD=~/PX4-Autopilot/build/cubepilot_cubeorangeplus_default
python tools/pipeline.py \
    $BUILD/cubepilot_cubeorangeplus_default.px4 \
    --board-id 1063 \
    --elf $BUILD/cubepilot_cubeorangeplus_default.elf \
    --private-key pki/manufacturer/private/manufacturer_private.pem \
    --public-key  pki/manufacturer/public/manufacturer_public.pem \
    --output-dir release/

# 5d. Provision the freshly-signed manifest + bootloader to the unit
#     (SD copy or bl_update per MANUFACTURING_RUNBOOK.md).

# 5e. Update Docs/audit/BUILD_IDENTITY.md with the production values:
#     new key fingerprint (3c), new code_hash/data_hash, bootloader hash, version.
```

**Verification after rotation:** boot the unit and confirm `listener firmware_integrity_status` → `check_passed: True`. Attempt an old-key-signed bundle and confirm it is now **rejected** (reason=3) — proving the device is bound to the new CCA key, not the old test key.

## 6. Case B — CCA private key is non-exportable (hardware token)

If the CCA certificate's private key is bound to a hardware token and cannot be exported, §2's `openssl pkcs12` extraction will not yield a private key. Two options:

- **Preferred (no code change):** on a machine with the token, use a PKCS#11-aware OpenSSL to sign, and route our tooling's signing step through it. This requires a small signing shim (our `signer.py` currently loads a file-based PEM key); adding a PKCS#11 signing path is a scoped change, not an architectural one. **Not yet implemented** — flag as production tooling work if Case B applies.
- **Alternative:** request an **exportable soft certificate** (`.PFX`) from the CA for the signing role, keeping the token for interactive document signing. This matches the reference (which uses a `.PFX`).

The public-key embedding (step 4) and device verification are identical in both cases — only *where the private key lives and how signing is invoked* differs.

## 7. What changes vs. what stays the same

| Stays the same | Changes |
|---|---|
| Signing scheme (RSA-PSS, SHA-256, MGF1, salt 32) | Key **source**: CCA certificate instead of `keygen.py` |
| Tools (`pipeline.py`, `signer.py`, `embed_pubkey.py`) | The two PEM files in `pki/manufacturer/` |
| Manifest format, bundle format, device verifier | The embedded pubkey (⇒ rebuild fw + bootloader) |
| Board, POST, arming gate, audit log | Key fingerprint in `BUILD_IDENTITY.md` |

## 8. Checklist (production key cut-over)

- [ ] CCA document-signing certificate purchased, **RSA-2048**, exportable `.PFX` (or Case B decided)
- [ ] Private key extracted to `pki/manufacturer/private/manufacturer_private.pem` (offline machine, `chmod 600`)
- [ ] Public key derived; **verified 2048-bit**; fingerprint recorded
- [ ] Full X.509 certificate chain retained for the CB
- [ ] `embed_pubkey.py` run; firmware + bootloader rebuilt
- [ ] Pipeline re-run with CCA key; manifest + bundle + bootloader re-signed
- [ ] Unit re-provisioned; POST passes; old-key artifact now rejected (reason=3)
- [ ] `BUILD_IDENTITY.md` updated with production values; test-key fingerprint removed
- [ ] `CERTIFICATE_OF_COMPLIANCE.md §3` provenance updated from "test key" to CCA production key

---

**Related:** [CERTIFICATE_OF_COMPLIANCE.md §3](CERTIFICATE_OF_COMPLIANCE.md) (provenance statement), [BUILD_IDENTITY.md §5](BUILD_IDENTITY.md) (key fingerprint fields), [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) (pipeline/signer/embed_pubkey), [../MANUFACTURING_RUNBOOK.md](../MANUFACTURING_RUNBOOK.md) (unit provisioning + sealing).
