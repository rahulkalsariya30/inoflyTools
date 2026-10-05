"""
tools/provisioning/provision_signing_key.py

Provision a MAVLink signing key for GCS-FC pairing via passphrase derivation.
Requirement: PAIR001 — GCS-FC pairing via MAVLink signing

WHY this script exists:
  The Annexure E communication requirement is that only authorized GCS software can
  communicate with the drone. PX4 has built-in MAVLink v2 message
  signing — both PX4 and QGC need to share a 32-byte key.

  QGC's UI (Settings -> Telemetry -> Signing Keys -> Add Key) accepts
  only a *passphrase* and derives the 32-byte key as SHA256(passphrase).
  This script does the same on the drone side, so the keys match.
  Earlier versions of this script generated random key bytes — that
  flow is incompatible with QGC's UI and has been retired.

OPERATIONAL NOTE — 1:1 pairing depends on operator discipline:
  Each drone MUST be provisioned with a unique passphrase that the
  operator keeps secret. Reusing a passphrase across drones means any
  GCS that knows it can command any of those drones, defeating the
  pairing intent. The script warns on detected reuse but does not
  refuse — the procedural control is the human, not the script.

USAGE:
  Interactive (recommended — passphrase doesn't enter shell history):
    python tools/provisioning/provision_signing_key.py --drone-id DRONE_001

  Scripted (CI / automation only — passphrase appears in shell history):
    python tools/provisioning/provision_signing_key.py \\
        --drone-id DRONE_001 --passphrase "my_passphrase"

  Hardware (write key directly to drone SD card mount):
    python tools/provisioning/provision_signing_key.py \\
        --drone-id DRONE_001 --hardware-mount /media/sdcard

  Then in QGC (one time per operator install):
    Settings -> Telemetry -> Signing Keys -> Add Key
    Name: anything,  Passphrase: <same passphrase used here>
"""

import argparse
import getpass
import hashlib
import struct
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# ── Paths ──────────────────────────────────────────────────────────────────

SITL_BUILD_DIR = Path.home() / "PX4-Autopilot" / "build" / "px4_sitl_default"

# PX4 SITL reads the signing key from these paths. Both must be written
# because different SITL launch modes (headless vs Gazebo) use different ones.
SITL_DESTINATIONS = [
    SITL_BUILD_DIR / "mavlink" / "mavlink-signing-key.bin",
    SITL_BUILD_DIR / "rootfs" / "mavlink" / "mavlink-signing-key.bin",
]

# Operator-side record (fingerprint only — never the passphrase or raw key bytes).
SIGNING_KEYS_DIR = PROJECT_ROOT / "pki" / "manufacturer" / "signing_keys"

# ── Key file format (matches PX4 MavlinkSignControl) ───────────────────────
# 32 bytes: secret key  +  8 bytes: initial timestamp (uint64 LE)
SIGNING_KEY_SIZE = 32
TIMESTAMP_SIZE   = 8
KEY_FILE_SIZE    = SIGNING_KEY_SIZE + TIMESTAMP_SIZE

# MAVLink signing timestamp epoch — 2015-01-01T00:00:00Z, 10us resolution.
MAVLINK_EPOCH = 1420070400

# Passphrase length floor — short passphrases are trivially brute-forceable.
MIN_PASSPHRASE_LEN = 8


def derive_signing_key(passphrase: str) -> bytes:
    """Derive the 32-byte MAVLink signing key from an operator passphrase.

    Matches QGC's MAVLinkSigningKeys::addKey() which computes SHA256(passphrase).
    Same passphrase on both sides -> same key -> messages verify.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty")
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def generate_initial_timestamp() -> bytes:
    """Initial MAVLink signing timestamp: us-since-2015-01-01 / 10, uint64 LE."""
    mavlink_us = int((time.time() - MAVLINK_EPOCH) * 1e6)
    return struct.pack("<Q", mavlink_us // 10)


def build_key_file(key_bytes: bytes, timestamp_bytes: Optional[bytes] = None) -> bytes:
    """Build the 40-byte key file content (32-byte key + 8-byte timestamp)."""
    if timestamp_bytes is None:
        timestamp_bytes = generate_initial_timestamp()
    assert len(key_bytes) == SIGNING_KEY_SIZE
    assert len(timestamp_bytes) == TIMESTAMP_SIZE
    return key_bytes + timestamp_bytes


def save_key_file(content: bytes, path: Path) -> None:
    """Write key file to disk, creating parent directories as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def check_passphrase_reuse(key_hex: str, this_drone_id: str) -> Optional[str]:
    """Scan operator records for the same key fingerprint under a different drone-id.

    Returns the conflicting drone-id if found, else None.
    """
    if not SIGNING_KEYS_DIR.exists():
        return None
    for info_file in SIGNING_KEYS_DIR.glob("*_signing_key.txt"):
        try:
            text = info_file.read_text(encoding="utf-8")
        except OSError:
            continue
        if key_hex in text:
            other_id = info_file.stem.replace("_signing_key", "")
            if other_id != this_drone_id:
                return other_id
    return None


def prompt_passphrase() -> str:
    """Read passphrase from terminal (hidden) with confirmation."""
    pw1 = getpass.getpass("Passphrase: ")
    pw2 = getpass.getpass("Confirm passphrase: ")
    if pw1 != pw2:
        print("ERROR: passphrases do not match", file=sys.stderr)
        sys.exit(2)
    if len(pw1) < MIN_PASSPHRASE_LEN:
        print(f"ERROR: passphrase must be at least {MIN_PASSPHRASE_LEN} characters",
              file=sys.stderr)
        sys.exit(2)
    return pw1


def main():
    parser = argparse.ArgumentParser(
        description="Provision MAVLink signing key from operator passphrase (PAIR001)"
    )
    parser.add_argument(
        "--drone-id",
        required=True,
        help="Unique drone identifier (e.g., DRONE_001). Used for the operator record filename.",
    )
    parser.add_argument(
        "--passphrase",
        help="Operator passphrase. Omit for interactive hidden prompt (recommended).",
    )
    parser.add_argument(
        "--hardware-mount",
        type=Path,
        help="Path to mounted drone SD card root. If given, also writes "
             "<mount>/mavlink/mavlink-signing-key.bin.",
    )
    parser.add_argument(
        "--no-sitl",
        action="store_true",
        help="Don't write to local SITL storage (useful when only provisioning hardware).",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("MAVLink Signing Key Provisioning Tool")
    print("Requirement: PAIR001 (Annexure E - communication requirement)")
    print("=" * 60)

    # Step 1: get passphrase
    passphrase = args.passphrase if args.passphrase else prompt_passphrase()
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        print(f"ERROR: passphrase must be at least {MIN_PASSPHRASE_LEN} characters",
              file=sys.stderr)
        sys.exit(2)

    # Step 2: derive key + build 40-byte file
    print(f"\n[1/4] Deriving signing key for {args.drone_id}...")
    key = derive_signing_key(passphrase)
    timestamp = generate_initial_timestamp()
    key_file = build_key_file(key, timestamp)
    print(f"      Key fingerprint (SHA256, hex): {key.hex()}")
    print(f"      File size: {len(key_file)} bytes")

    # Step 3: warn on passphrase reuse across drone-ids
    print(f"\n[2/4] Checking for passphrase reuse across drone-ids...")
    other_id = check_passphrase_reuse(key.hex(), args.drone_id)
    if other_id is not None:
        print(f"      [WARN] This passphrase was previously provisioned for '{other_id}'.")
        print(f"             Reusing passphrases across drones defeats the 1:1 pairing")
        print(f"             property — any GCS with this passphrase can command both drones.")
        print(f"             Use a unique passphrase per drone for production deployments.")
    else:
        print(f"      [OK] Passphrase fingerprint not seen for any other drone.")

    # Step 4: save operator record (fingerprint only — never the passphrase
    # or raw key bytes; raw key would let anyone with repo access talk to drones)
    print(f"\n[3/4] Saving operator record (fingerprint only)...")
    info_path = SIGNING_KEYS_DIR / f"{args.drone_id}_signing_key.txt"
    info_path.parent.mkdir(parents=True, exist_ok=True)
    info_path.write_text(
        f"MAVLink Signing Key Record — {args.drone_id}\n"
        f"Provisioned: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        f"\n"
        f"Key fingerprint (SHA256 of passphrase, hex): {key.hex()}\n"
        f"File size: {KEY_FILE_SIZE} bytes (32-byte key + 8-byte timestamp)\n"
        f"\n"
        f"OPERATOR INSTRUCTIONS:\n"
        f"  In QGC: Settings -> Telemetry -> Signing Keys -> Add Key\n"
        f"  Name:       {args.drone_id} (or any label)\n"
        f"  Passphrase: <the passphrase used at provisioning — keep secret>\n"
        f"\n"
        f"This record stores ONLY the fingerprint so two records can be compared\n"
        f"for passphrase-reuse checks. It does NOT contain the passphrase or the\n"
        f"raw key bytes. The operator must memorize / safely store the passphrase\n"
        f"out-of-band; if lost, re-provision the drone with a new passphrase.\n"
    )
    print(f"      [OK] {info_path}")

    # Step 5: write key file to SITL and/or hardware mount
    print(f"\n[4/4] Writing key file to destinations...")
    written = 0
    if not args.no_sitl:
        if SITL_BUILD_DIR.exists():
            for dest in SITL_DESTINATIONS:
                save_key_file(key_file, dest)
                print(f"      [OK] SITL:     {dest}")
                written += 1
        else:
            print(f"      [SKIP] SITL build dir not found ({SITL_BUILD_DIR})")
    else:
        print(f"      [SKIP] SITL (--no-sitl)")

    if args.hardware_mount is not None:
        hw_dest = args.hardware_mount / "mavlink" / "mavlink-signing-key.bin"
        save_key_file(key_file, hw_dest)
        print(f"      [OK] Hardware: {hw_dest}")
        written += 1

    if written == 0:
        print(f"      [WARN] No destinations written. Use --hardware-mount, or build "
              f"SITL first.")

    print("\n" + "=" * 60)
    print("Provisioning complete.")
    print()
    print(f"Drone ID:        {args.drone_id}")
    print(f"Key fingerprint: {key.hex()[:16]}...{key.hex()[-8:]}")
    print()
    print("Operator setup (one time per QGC install):")
    print("  1. Open QGC -> Settings -> Telemetry -> Signing Keys -> Add Key")
    print("  2. Enter the SAME passphrase you used here")
    print("  3. Connect to drone — signing is automatic")
    print()
    print("NOTE: MAV_SIGN_CFG=1 is locked by PAR001.")
    print("      Non-USB connections REQUIRE matching message signing.")
    print("=" * 60)


if __name__ == "__main__":
    main()
