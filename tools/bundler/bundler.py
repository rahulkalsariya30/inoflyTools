"""
tools/bundler/bundler.py

Firmware Update Bundle Packager
Requirement: PKG001 - Package signed firmware into a distributable update bundle

WHY a bundle?
  A vendor receives ONE file. It contains everything needed to update a drone
  and verify the update is authentic:
    - The firmware binary (.px4) to flash onto the flight controller
    - The signed manifest (checksums + manufacturer signature) to register

  The bundle ties the firmware and its signed proof together. You cannot swap
  the firmware for a different version while keeping the original signature —
  the checksums in the manifest would no longer match.

BUNDLE FORMAT:
  A ZIP file with a .fwbundle extension. ZIP was chosen because:
    - Human-readable: unzip it and inspect the contents
    - Auditable: any tool can verify the contents without our software
    - Standard: no custom binary parsing needed

  Contents:
    firmware.px4          — the firmware binary (copy of the original .px4)
    signed_manifest.json  — signed manifest from Phase 1.3 (signer.py)
    bundle_info.json      — top-level metadata (version, board, created_at)

VENDOR WORKFLOW:
  Manufacturer runs: keygen → checksum → sign → package (this tool)
  Vendor receives:   firmware_v1.14.0_cubeorange.fwbundle
  QGC plugin (Phase 4) opens bundle, verifies signature, flashes firmware
"""

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.signer.signer import verify_bundle as _verify_signed_bundle, load_signed_bundle

BUNDLER_VERSION = "1.0.0"


def create_bundle(
    px4_path: Path,
    signed_manifest: dict,
    output_path: Path,
) -> Path:
    """
    Package a firmware file and its signed manifest into a .fwbundle file.

    Args:
        px4_path:        Path to the .px4 firmware file
        signed_manifest: The signed bundle dict from signer.sign_manifest()
        output_path:     Where to write the .fwbundle file

    Returns:
        Path to the created bundle file
    """
    px4_path = Path(px4_path)
    output_path = Path(output_path)

    if not px4_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {px4_path}")

    # Validate the signed manifest has required fields before bundling
    required = {"manifest", "signature", "signed_at"}
    missing = required - set(signed_manifest.keys())
    if missing:
        raise ValueError(f"Signed manifest is missing fields: {missing}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build the top-level bundle_info — describes what's in the bundle
    # without requiring the consumer to parse the manifest
    manifest_data = signed_manifest["manifest"]
    bundle_info = {
        "bundler_version": BUNDLER_VERSION,
        "firmware_version": manifest_data.get("firmware_version", "unknown"),
        "board_id": manifest_data.get("board_id", 0),
        "firmware_file": px4_path.name,
        "algorithm": manifest_data.get("algorithm", "SHA-256"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Store firmware binary
        zf.write(px4_path, arcname="firmware.px4")

        # Store signed manifest (manifest + signature)
        zf.writestr(
            "signed_manifest.json",
            json.dumps(signed_manifest, indent=4)
        )

        # Store bundle info (human-readable summary at top level)
        zf.writestr(
            "bundle_info.json",
            json.dumps(bundle_info, indent=4)
        )

    print(f"[OK] Bundle created: {output_path}")
    print(f"     Firmware:        {px4_path.name}")
    print(f"     Version:         {bundle_info['firmware_version']}")
    print(f"     Board ID:        {bundle_info['board_id']}")
    return output_path


def verify_bundle(bundle_path: Path, public_key_path: Path) -> bool:
    """
    Verify the signature inside a .fwbundle file.

    Opens the bundle, extracts the signed manifest, and checks that the
    manufacturer signature is valid. Does NOT verify that the firmware
    binary matches the checksums — that happens on the drone at boot (POST).

    Returns:
        True if the signature is valid, False otherwise
    """
    bundle_path = Path(bundle_path)

    if not bundle_path.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()

        # Check all expected files are present
        for required_file in ["firmware.px4", "signed_manifest.json", "bundle_info.json"]:
            if required_file not in names:
                raise ValueError(
                    f"Bundle is missing '{required_file}'. "
                    "This bundle may be corrupt or tampered with."
                )

        signed_manifest = json.loads(zf.read("signed_manifest.json"))

    return _verify_signed_bundle(signed_manifest, public_key_path=public_key_path)


def inspect_bundle(bundle_path: Path) -> dict:
    """
    Read bundle metadata without verifying the signature.
    Useful for displaying bundle info in QGC before installing.

    Returns:
        The bundle_info dict from inside the bundle
    """
    bundle_path = Path(bundle_path)

    with zipfile.ZipFile(bundle_path, "r") as zf:
        return json.loads(zf.read("bundle_info.json"))


def extract_firmware(bundle_path: Path, output_dir: Path) -> Path:
    """
    Extract only the firmware .px4 file from a bundle.
    Used by QGC plugin (Phase 4) after signature verification.

    Returns:
        Path to the extracted .px4 file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(bundle_path, "r") as zf:
        zf.extract("firmware.px4", path=output_dir)

    return output_dir / "firmware.px4"


if __name__ == "__main__":
    import argparse

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.checksum.checksum import generate_manifest
    from tools.signer.signer import sign_manifest
    from tools.pki.keygen import PUBLIC_KEY_PATH

    parser = argparse.ArgumentParser(
        description="Package a PX4 firmware file into a signed .fwbundle for distribution."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--version", default="", help="Firmware version string")
    parser.add_argument("--output", default="", help="Output path for .fwbundle file")
    parser.add_argument("--verify", action="store_true", help="Verify bundle after creation")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        sys.exit(1)

    # Default output name based on firmware file
    output_path = Path(args.output) if args.output else px4_path.with_suffix(".fwbundle")

    print(f"Step 1/3 — Computing checksums...")
    manifest = generate_manifest(px4_path, firmware_version=args.version)

    print(f"Step 2/3 — Signing manifest...")
    signed = sign_manifest(manifest)

    print(f"Step 3/3 — Packaging bundle...")
    create_bundle(px4_path, signed, output_path)

    if args.verify:
        print(f"\nVerifying bundle signature...")
        valid = verify_bundle(output_path, public_key_path=PUBLIC_KEY_PATH)
        print(f"[{'OK' if valid else 'FAIL'}] Signature: {'valid' if valid else 'INVALID'}")
        if not valid:
            sys.exit(1)
