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

MODES OF OPERATION:
  1. SITL (default): Extract image from .px4 JSON and hash it. The .px4 file
     contains base64(zlib(firmware_bytes)). Code and data extracted from it.

  2. Hardware (--code-bin / --data-bin): Hash pre-extracted ELF section binaries.
     The user runs objcopy in WSL to extract .text and .data sections from the
     ELF, then passes those binary files here. This ensures the hashes match
     what the FC computes from flash at runtime (POST002/POST003).

     Extraction commands (run in WSL after building):
       arm-none-eabi-objcopy -O binary --only-section=.text firmware.elf code.bin
       arm-none-eabi-objcopy -O binary --only-section=.data firmware.elf data.bin
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


def compute_file_checksum(file_path: Path) -> str:
    """
    Compute SHA-256 checksum of a raw binary file.
    Used for hardware builds where code/data sections are extracted from ELF.

    Returns:
        Hex string of the SHA-256 digest (64 characters)
    """
    data = Path(file_path).read_bytes()
    if len(data) == 0:
        raise ValueError(f"Binary file is empty: {file_path}")
    return hashlib.sha256(data).hexdigest()


def generate_manifest(
    px4_path: Path,
    firmware_version: str = "",
    board_id: int = None,
    code_bin_path: Path = None,
    data_bin_path: Path = None,
) -> dict:
    """
    Generate a checksum manifest for a firmware file.

    The manifest contains:
      - code_checksum: SHA-256 of firmware code section
      - data_checksum: SHA-256 of firmware data section
      - firmware_version: version string (from .px4 or caller-provided)
      - source_file: original .px4 filename
      - generated_at: ISO timestamp (UTC)
      - algorithm: always "SHA-256" — documents what was used

    For hardware builds (when code_bin_path/data_bin_path are provided):
      - code_checksum = SHA-256 of the .text section binary (matches POST002)
      - data_checksum = SHA-256 of the .data section binary (matches POST003)

    For SITL builds (default):
      - code_checksum = SHA-256 of the image from .px4 file
      - data_checksum = SHA-256 of parameter_xml from .px4 file

    Args:
        px4_path:       Path to the .px4 firmware file
        firmware_version: Override version string
        board_id:       Override board ID (default: read from .px4)
        code_bin_path:  Path to extracted .text section binary (hardware mode)
        data_bin_path:  Path to extracted .data section binary (hardware mode)
    """
    with open(px4_path, "r") as f:
        firmware_meta = json.load(f)

    # Use provided version, fall back to version embedded in .px4
    version = firmware_version or firmware_meta.get("version", "unknown")

    # Board ID: explicit override > .px4 metadata > 0
    manifest_board_id = board_id if board_id is not None else firmware_meta.get("board_id", 0)

    # Compute checksums: hardware mode (ELF sections) or SITL mode (.px4 image)
    if code_bin_path is not None:
        code_hash = compute_file_checksum(code_bin_path)
    else:
        code_hash = compute_code_checksum(px4_path)

    if data_bin_path is not None:
        data_hash = compute_file_checksum(data_bin_path)
    else:
        data_hash = compute_data_checksum(px4_path)

    manifest = {
        "algorithm": "SHA-256",
        "firmware_version": version,
        "source_file": Path(px4_path).name,
        "board_id": manifest_board_id,
        "git_hash": firmware_meta.get("git_hash", ""),
        "code_checksum": code_hash,
        "data_checksum": data_hash,
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
    parser.add_argument("--board-id", type=int, default=None,
                        help="Override board ID (default: read from .px4)")
    parser.add_argument("--code-bin", default=None,
                        help="Path to extracted .text section binary (hardware mode)")
    parser.add_argument("--data-bin", default=None,
                        help="Path to extracted .data section binary (hardware mode)")
    parser.add_argument("--output", default="", help="Output path for manifest JSON (optional)")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        exit(1)

    code_bin = Path(args.code_bin) if args.code_bin else None
    data_bin = Path(args.data_bin) if args.data_bin else None

    if code_bin and not code_bin.exists():
        print(f"[ERROR] Code binary not found: {code_bin}")
        exit(1)
    if data_bin and not data_bin.exists():
        print(f"[ERROR] Data binary not found: {data_bin}")
        exit(1)

    mode = "hardware (ELF sections)" if code_bin else "SITL (.px4 image)"
    print(f"Computing checksums for: {px4_path.name}  [{mode}]")
    manifest = generate_manifest(
        px4_path,
        firmware_version=args.version,
        board_id=args.board_id,
        code_bin_path=code_bin,
        data_bin_path=data_bin,
    )

    print(f"  Code checksum (SHA-256): {manifest['code_checksum']}")
    print(f"  Data checksum (SHA-256): {manifest['data_checksum']}")
    print(f"  Board ID:                {manifest['board_id']}")
    print(f"  Firmware version:        {manifest['firmware_version']}")

    if args.output:
        save_manifest(manifest, Path(args.output))
    else:
        print("\nFull manifest:")
        print(json.dumps(manifest, indent=4))
