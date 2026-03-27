"""
tools/checksum/checksum.py

SHA-256 Checksum Tool
Requirement: CHK001 - Compute checksums of firmware code part and data part separately

WHY separate code and data checksums?
  - DGCA Level 1 requires checksums for both parts independently
  - Code part  = the compiled firmware binary (instructions + constants)
  - Data part  = the default parameter set shipped with the firmware
  - Keeping them separate means: if default parameters change, only the data
    checksum changes — the code checksum stays the same, proving the firmware
    binary itself was not touched. This matters for re-certification.

WHY SHA-256?
  - DGCA Level 1 specifies SHA-2 family minimum
  - SHA-256 is the standard choice: well-understood, hardware-accelerated,
    supported everywhere including PX4's libtomcrypt

.px4 FILE FORMAT:
  A .px4 file is a JSON container. Key fields:
    "image"         — firmware binary, zlib-compressed then base64-encoded
    "parameter_xml" — default parameter set, zlib-compressed then base64-encoded
  We extract, decompress, and hash each field separately.
"""

import base64
import hashlib
import json
import zlib
from pathlib import Path
from datetime import datetime, timezone


def extract_image_bytes(px4_path: Path) -> bytes:
    """
    Extract raw firmware binary bytes from a .px4 file.
    The image field is base64(zlib(raw_bytes)) — we reverse that.
    """
    with open(px4_path, "r") as f:
        firmware = json.load(f)

    if "image" not in firmware:
        raise ValueError(f"No 'image' field found in {px4_path}. Is this a valid .px4 file?")

    compressed = base64.b64decode(firmware["image"])
    raw_bytes = zlib.decompress(compressed)
    return raw_bytes


def extract_parameter_bytes(px4_path: Path) -> bytes:
    """
    Extract raw parameter XML bytes from a .px4 file.
    The parameter_xml field is base64(zlib(raw_bytes)) — we reverse that.

    Returns empty bytes if the .px4 file has no embedded parameters
    (older firmware builds may omit this field).
    """
    with open(px4_path, "r") as f:
        firmware = json.load(f)

    if "parameter_xml" not in firmware:
        # Not all builds embed parameters — return empty bytes rather than failing
        return b""

    compressed = base64.b64decode(firmware["parameter_xml"])
    raw_bytes = zlib.decompress(compressed)
    return raw_bytes


def compute_code_checksum(px4_path: Path) -> str:
    """
    Compute SHA-256 checksum of the firmware code part.
    Code part = the compiled firmware binary extracted from the .px4 image field.

    Returns:
        Hex string of the SHA-256 digest (64 characters)
    """
    image_bytes = extract_image_bytes(px4_path)
    digest = hashlib.sha256(image_bytes).hexdigest()
    return digest


def compute_data_checksum(px4_path: Path) -> str:
    """
    Compute SHA-256 checksum of the firmware data part.
    Data part = the default parameter XML embedded in the .px4 file.

    If no parameter_xml is present, returns SHA-256 of empty bytes.
    This is deterministic and reproducible — two builds with identical
    parameters will produce identical data checksums.

    Returns:
        Hex string of the SHA-256 digest (64 characters)
    """
    param_bytes = extract_parameter_bytes(px4_path)
    digest = hashlib.sha256(param_bytes).hexdigest()
    return digest


def generate_manifest(px4_path: Path, firmware_version: str = "") -> dict:
    """
    Generate a checksum manifest for a .px4 firmware file.

    The manifest contains:
      - code_checksum: SHA-256 of firmware binary
      - data_checksum: SHA-256 of default parameter set
      - firmware_version: version string (from .px4 or caller-provided)
      - source_file: original .px4 filename
      - generated_at: ISO timestamp (UTC)
      - algorithm: always "SHA-256" — documents what was used

    This manifest is what gets registered on the flight module and
    checked on every boot (POST).
    """
    with open(px4_path, "r") as f:
        firmware_meta = json.load(f)

    # Use provided version, fall back to version embedded in .px4
    version = firmware_version or firmware_meta.get("version", "unknown")

    manifest = {
        "algorithm": "SHA-256",
        "firmware_version": version,
        "source_file": Path(px4_path).name,
        "board_id": firmware_meta.get("board_id", 0),
        "git_hash": firmware_meta.get("git_hash", ""),
        "code_checksum": compute_code_checksum(px4_path),
        "data_checksum": compute_data_checksum(px4_path),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return manifest


def save_manifest(manifest: dict, output_path: Path) -> None:
    """
    Save checksum manifest to a JSON file.
    This file will later be signed by the firmware signer (Phase 1.3).
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=4)
    print(f"[OK] Manifest saved to: {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Compute SHA-256 checksums of PX4 firmware code and data parts."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--version", default="", help="Firmware version string (optional)")
    parser.add_argument("--output", default="", help="Output path for manifest JSON (optional)")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        exit(1)

    print(f"Computing checksums for: {px4_path.name}")
    manifest = generate_manifest(px4_path, firmware_version=args.version)

    print(f"  Code checksum (SHA-256): {manifest['code_checksum']}")
    print(f"  Data checksum (SHA-256): {manifest['data_checksum']}")
    print(f"  Board ID:                {manifest['board_id']}")
    print(f"  Firmware version:        {manifest['firmware_version']}")

    if args.output:
        save_manifest(manifest, Path(args.output))
    else:
        print("\nFull manifest:")
        print(json.dumps(manifest, indent=4))
