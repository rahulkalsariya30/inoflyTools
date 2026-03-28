"""
tools/provisioning/provision_sitl.py

Provision a test manifest into PX4 SITL storage for end-to-end testing.
Requirement: POST001 integration test

WHY this script exists:
  FirmwareIntegrityChecker needs a real manifest.bin in SITL storage to
  exercise the full check path (CRC + ECDSA). Without it, secure_boot
  always returns REASON_NO_MANIFEST.

  This script creates a test manifest signed with the real manufacturer
  private key and copies it to the SITL storage directory, so that
  running 'secure_boot start' in SITL produces check_passed=True.

  NOTE: The hash comparison steps (_verify_code_hash, _verify_data_hash)
  are stubbed in SITL (return true), so this tests the CRC and ECDSA
  paths only. Hash verification is completed in Phase 2.5 for NuttX.

USAGE:
  python tools/provisioning/provision_sitl.py

  Then in SITL shell:
    secure_boot start
    listener firmware_integrity_status -n 1
    → check_passed: True
"""

import sys
import shutil
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.provisioning.export_manifest import export_binary_manifest, save_binary_manifest, verify_binary_manifest

# ── Paths ──────────────────────────────────────────────────────────────────

PRIVATE_KEY_PATH = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"
PUBLIC_KEY_PATH  = PROJECT_ROOT / "pki" / "manufacturer" / "public"  / "manufacturer_public.pem"

# SITL storage: PX4_STORAGEDIR = "." relative to where PX4 is launched from.
# When running: cd ~/PX4-Autopilot/build/px4_sitl_default && PX4_SIM_MODEL=shell ./bin/px4 ...
# the manifest path is ./inofly/manifest.bin inside that directory.
SITL_BUILD_DIR   = Path.home() / "PX4-Autopilot" / "build" / "px4_sitl_default"
SITL_MANIFEST    = SITL_BUILD_DIR / "inofly" / "manifest.bin"

# ── Test manifest data ─────────────────────────────────────────────────────
#
# We use placeholder hashes because:
#   - There is no real firmware binary to hash in SITL
#   - _verify_code_hash and _verify_data_hash are stubbed (return true) in SITL
#   - What we ARE testing: CRC32 integrity + ECDSA signature verification
#
# The signature covers these exact values, so if the C++ code reconstructs
# the same payload and verifies against the baked-in public key, the check passes.

TEST_BUNDLE = {
    "manifest": {
        "algorithm":        "SHA-256",
        "firmware_version": "1.14.0-sitl-test",
        "source_file":      "px4_sitl_default.px4",
        "board_id":         50,             # OrangeCube board ID
        "git_hash":         "sitl-test",
        "code_checksum":    "a" * 64,       # placeholder SHA-256 (all 0xAA bytes)
        "data_checksum":    "b" * 64,       # placeholder SHA-256 (all 0xBB bytes)
        "generated_at":     "2026-01-01T00:00:00+00:00",
    },
    "signature":  "placeholder-not-used-binary-manifest-has-its-own-signature",
    "signed_at":  "2026-01-01T00:00:01+00:00",
}


def main():
    print("=" * 60)
    print("SITL Manifest Provisioning Tool")
    print("=" * 60)

    # Sanity checks
    if not PRIVATE_KEY_PATH.exists():
        print(f"[FAIL] Private key not found: {PRIVATE_KEY_PATH}")
        print("       Run tools/pki/keygen.py first.")
        sys.exit(1)

    if not SITL_BUILD_DIR.exists():
        print(f"[FAIL] SITL build directory not found: {SITL_BUILD_DIR}")
        print("       Run: make px4_sitl_default  (in WSL2)")
        sys.exit(1)

    # Step 1: Export binary manifest (signs with private key)
    print("\n[1/3] Exporting binary manifest...")
    binary = export_binary_manifest(TEST_BUNDLE, private_key_path=PRIVATE_KEY_PATH)
    print(f"      Size: {len(binary)} bytes")

    # Step 2: Verify locally before writing to SITL
    print("\n[2/3] Verifying manifest signature locally...")
    valid = verify_binary_manifest(binary, PUBLIC_KEY_PATH)

    if not valid:
        print("[FAIL] Local verification failed — manifest will not pass on drone either.")
        sys.exit(1)

    print("      [OK] CRC and ECDSA signature verified")

    # Step 3: Write to SITL storage
    print(f"\n[3/3] Writing to SITL storage...")
    save_binary_manifest(binary, SITL_MANIFEST)
    print(f"      [OK] Manifest written to: {SITL_MANIFEST}")

    print("\n" + "=" * 60)
    print("Provisioning complete.")
    print()
    print("Now start SITL and run:")
    print("  cd ~/PX4-Autopilot/build/px4_sitl_default")
    print("  PX4_SIM_MODEL=shell ./bin/px4 -s ../../ROMFS/px4fmu_common/init.d-posix/rcS")
    print()
    print("In pxh> shell:")
    print("  secure_boot start")
    print("  listener firmware_integrity_status -n 1")
    print()
    print("Expected: check_passed: True, failure_reason: 0")
    print("=" * 60)


if __name__ == "__main__":
    main()
