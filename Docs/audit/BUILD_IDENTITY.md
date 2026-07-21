# Certified Build Identity Sheet
## The exact firmware artifact this certification applies to

**Purpose.** A Certificate of Compliance certifies *a specific firmware build*, not "the firmware" in general. This sheet pins the certificate to a single, reproducible artifact by recording its version, source revision, checksums, target board, bootloader, and signing-key fingerprint. If any of these values changes, it is a different build and requires its own identity sheet.

**Last updated:** 2026-07-10

> ⚠️ **This sheet currently records the latest BENCH build (test key).** It is a *template populated with real reference values* so the format and provenance are clear. For the production certification, regenerate every value from the production build signed with the **production** manufacturer key, and replace the "test key" fingerprint. Fields that must be finalized for production are marked **[FINALIZE]**.

---

## 1. Firmware image identity

| Field | Value (reference bench build — B9, 2026-07-09) |
|---|---|
| Product | CubePilot CubeOrange+ flight controller |
| Board ID | **1063** (CubeOrange+; compiled `SECURE_BOOT_BOARD_ID=1063`) |
| Firmware family | PX4 (inoflyPilot fork) with `secure_boot` module |
| Firmware version string | `0.1`-class dev build **[FINALIZE — set production version, e.g. `1.0.0`]** |
| PX4 source git hash | `c4aa2811ebdb2ccad105334411ed1751ed5ed40f` |
| App firmware `.px4` SHA-256 | `db5d6f9e0f36ad6c10d16baf65b16a03cf9ab964fe6c922e634cda78550078f4` |

## 2. Registered checksums (in the signed manifest)

| Field | Value |
|---|---|
| `code_hash` (SHA-256, flash `[_stext .. _compliance_params_start)`) | `2078492570ee1e195279828dc42244f4ce697b0de2c968adeed5b8e964c02c5d` |
| `data_hash` (SHA-256, flash `[_compliance_params_start .. _compliance_params_end)`) | `a3e97baed053cd2c55528397c0c3d97df2524fb2929ff23e896c08f040c1dffb` |
| Hash algorithm | SHA-256 (FIPS 180-4) |

These are the values POST re-computes from live flash on every boot and compares against the manifest. They are furnished to the Certification Body as the **registered checksums** (§7.1 a.ii).

## 3. Binary manifest (provisioned to the flight module)

| Field | Value |
|---|---|
| File | `/fs/microsd/inofly/manifest.bin` |
| Magic | `INOFLY03` |
| Format version | 3 |
| Size | 373 bytes |
| SHA-256 (this build's manifest.bin) | `130f415b87acaca63165201a1ff2134d23c6bcf8e01f526dd56023fd62791e51` |
| Integrity | CRC32 + RSA-PSS signature over the payload |

## 4. Bootloader

| Field | Value |
|---|---|
| Secure bootloader image — SHA-256 of the release artifact file | `66bf50f6542acc71c726c94a8a811be013d4be245b8abeca01289779d8ac1333` |
| On-device reported bootloader hash (bench unit; covers the boot region, so it differs from the file hash above by measurement range) | `3a404d9a…` (short) — record full hash from the target at production **[FINALIZE]** |
| Install / update path | signed `bl_update` (BOOT008 — verifies RSA-PSS signature before erasing sector 0) |
| Size | 108,160 B (≈105.6 KB of the 128 KB sector-0 budget) |

## 5. Signing key (root of trust)

| Field | Value |
|---|---|
| Key type | RSA-2048, self-managed (see provenance note below) |
| Public key (retained for Certification Body) | `pki/manufacturer/public/manufacturer_public.pem` |
| Public key encoding on device | DER SubjectPublicKeyInfo (~294 bytes), compiled into bootloader + app fw |
| **DER SHA-256 fingerprint (current TEST key)** | `f52ab7731ca86ea15aa152b605a87369da236b76ce99e7bd09b381b7af928dd5` |
| Signature scheme | RSA-PSS (SHA-256, MGF1-SHA256, salt length 32) |
| Signature size | 256 bytes |
| **Production key fingerprint** | **[FINALIZE — regenerate production key, insert its DER SHA-256]** |

> **Provenance:** the value above is the **bench/test key** — a self-generated raw RSA keypair, not a certificate (verified 2026-07-10: the public PEM parses as a bare `PUBLIC KEY`, not an X.509 cert; private half is an unencrypted PEM on the build machine). **For production the key is adopted from a CCA-issued RSA-2048 document-signing certificate** (decided 2026-07-10). Extraction + cut-over procedure: [PRODUCTION_KEY_PROVISIONING.md](PRODUCTION_KEY_PROVISIONING.md). Replace the fingerprint above with the CCA-derived production key's fingerprint at cut-over. See also [CERTIFICATE_OF_COMPLIANCE.md §3](CERTIFICATE_OF_COMPLIANCE.md).

## 6. Compliance parameters baked into this build (`.compliance_params`, covered by `data_hash`)

| Parameter | Kind | Registered value |
|---|---|---|
| `GF_MAX_VER_DIST` | CAPPED | 120 m |
| `GF_MAX_HOR_DIST` | CAPPED | 500 m |
| `MPC_XY_VEL_MAX` | CAPPED | 15 m/s |
| `SYS_AUTOSTART` | LOCKED | 4001 |
| `CA_AIRFRAME` | LOCKED | 0 (Multirotor) |
| `MAV_SIGN_CFG` | LOCKED | 1 (signing required) |

## 7. How to reproduce these values

```bash
# App fw / manifest hashes:
sha256sum <build>/cubepilot_cubeorangeplus_default.px4
sha256sum <build>/cubepilot_cubeorangeplus_default_manifest.bin

# code_hash / data_hash / board_id / git_hash (from the signed manifest):
cat <build>/cubepilot_cubeorangeplus_default_manifest.json

# Public-key DER fingerprint:
openssl pkey -pubin -in pki/manufacturer/public/manufacturer_public.pem -outform DER | openssl dgst -sha256

# Bootloader hash:
sha256sum <build>/cubepilot_cubeorangeplus_bootloader.bin
```

## 8. Sign-off

| | Name | Signature | Date |
|---|---|---|---|
| Build produced by | | | |
| Verified against target by | | | |
| Approved for certification by | | | |
