"""
tools/provisioning/provision_audit_key.py

Provision the audit log signing key into PX4 SITL storage for testing.
Requirement: LOG001 — Signed audit log

WHY this script exists:
  SecurityAuditLogger needs a private key to sign audit log entries.
  On real hardware, this will be the device TPM key (Phase 4).
  For SITL testing, we use the manufacturer private key as a stand-in.

  This script copies the manufacturer private key to the SITL storage
  directory where SecurityAuditLogger expects to find it.

  The code path is identical — only the key source changes in Phase 4
  (file read → TPM handle).

USAGE:
  python tools/provisioning/provision_audit_key.py

  Then in SITL shell:
    secure_boot start
    secure_boot audit_status
    → signing_key: loaded
"""

import sys
import shutil
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# ── Paths ──────────────────────────────────────────────────────────────────

PRIVATE_KEY_PATH = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"

# SITL storage: PX4_STORAGEDIR = "." relative to where PX4 is launched from.
# Provision both headless and Gazebo paths (same pattern as provision_sitl.py).
SITL_BUILD_DIR = Path.home() / "PX4-Autopilot" / "build" / "px4_sitl_default"

DESTINATIONS = [
    SITL_BUILD_DIR / "inofly" / "audit_signing_key.pem",           # headless
    SITL_BUILD_DIR / "rootfs" / "inofly" / "audit_signing_key.pem", # Gazebo
]


def main():
    print("=" * 60)
    print("SITL Audit Signing Key Provisioning Tool")
    print("Requirement: LOG001")
    print("=" * 60)

    # Sanity checks
    if not PRIVATE_KEY_PATH.exists():
        print(f"\n[FAIL] Private key not found: {PRIVATE_KEY_PATH}")
        print("       Run tools/pki/keygen.py first.")
        sys.exit(1)

    if not SITL_BUILD_DIR.exists():
        print(f"\n[FAIL] SITL build directory not found: {SITL_BUILD_DIR}")
        print("       Run: make px4_sitl_default  (in WSL2)")
        sys.exit(1)

    print(f"\nSource key: {PRIVATE_KEY_PATH}")
    print()
    print("NOTE: Using manufacturer key as stand-in for device TPM key.")
    print("      Phase 4 will replace this with hardware-bound device key.")
    print()

    for dest in DESTINATIONS:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PRIVATE_KEY_PATH, dest)
        print(f"  [OK] {dest}")

    print()
    print("=" * 60)
    print("Provisioning complete.")
    print()
    print("In SITL shell:")
    print("  secure_boot start")
    print("  secure_boot audit_status")
    print()
    print("Expected: signing_key: loaded")
    print("=" * 60)


if __name__ == "__main__":
    main()
