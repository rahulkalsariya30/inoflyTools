"""
tools/checksum/checksum.py

SHA-256 Checksum Tool
Requirement: CHK001 - Compute checksums of firmware code part and data part separately

WHY separate code and data checksums?
  - DGCA Level 1 requires checksums for both parts independently
  - Code part  = compiled firmware code + read-only data (everything except
    the .compliance_params table)
  - Data part  = the .compliance_params table (PAR001 protected parameters)
  - Keeping them separate means: if a compliance parameter value changes,
    only the data checksum changes — the code checksum stays byte-identical,
    proving the firmware binary itself was not touched. (See ADR-018.)

WHY SHA-256?
  - DGCA Level 1 specifies SHA-2 family minimum
  - SHA-256 is the standard choice: well-understood, hardware-accelerated,
    supported everywhere including PX4's libtomcrypt

MODES OF OPERATION:
  1. SITL / dev (default): Extract image from .px4 JSON and hash it. The .px4
     file contains base64(zlib(firmware_bytes)). Convenient for early-pipeline
     testing; does NOT match what the FC POST hashes on real hardware.

  2. Hardware (--elf): Single-input model. Pass the firmware ELF; the tool
     reads symbols `_stext`, `_compliance_params_start`, `_compliance_params_end`
     and hashes the same FLASH byte ranges the FC POST hashes:
        code_hash = SHA256(flash[_stext .. _compliance_params_start])
        data_hash = SHA256(flash[_compliance_params_start .. _compliance_params_end])
     This guarantees host-vs-FC hash equivalence on hardware.

  3. Legacy (--code-bin / --data-bin): DEPRECATED. Two pre-extracted section
     binaries. Cannot reproduce the FC byte ranges (the FC range spans .text
     + .rodata + .data's LMA copy, not just .text). Kept for one release with
     a deprecation warning; will be removed.
"""

import base64
import hashlib
import json
import warnings
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


# ---------------------------------------------------------------------------
# Hardware mode (ELF) — slice FLASH byte ranges by linker symbol address
# ---------------------------------------------------------------------------
#
# The FC POST (FirmwareIntegrityChecker._hash_flash_range) reads contiguous
# FLASH bytes between three linker symbols:
#     _stext, _compliance_params_start, _compliance_params_end.
# These symbols are placed inside FLASH-resident sections (linker script
# `boards/cubepilot/cubeorangeplus/nuttx-config/scripts/script.ld`), so for
# them VMA == LMA — the symbol value is the FLASH (load) address.
#
# The FLASH image is the concatenation of every PT_LOAD segment's file bytes,
# indexed by p_paddr (LMA). We rebuild that image from the ELF and slice the
# two ranges. This is what `arm-none-eabi-objcopy -O binary` would produce,
# without needing the toolchain on the host.

_REQUIRED_SYMBOLS = ("_stext", "_compliance_params_start", "_compliance_params_end")


def _read_elf_symbols(elf_path: Path) -> dict:
    """Return a {name: value} dict for the symbols POST hashing depends on."""
    # Local import: pyelftools is only needed for hardware mode.
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    found = {}
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if sym.name in _REQUIRED_SYMBOLS:
                    found[sym.name] = sym.entry["st_value"]

    missing = [s for s in _REQUIRED_SYMBOLS if s not in found]
    if missing:
        raise ValueError(
            f"ELF {elf_path} is missing required linker symbols: {missing}. "
            "Was it built with the .compliance_params section in the linker script?"
        )
    return found


def _extract_flash_range(elf_path: Path, lma_start: int, lma_end: int) -> bytes:
    """
    Return FLASH bytes in the half-open address range [lma_start, lma_end),
    reconstructed from the ELF's PT_LOAD segments. p_paddr is the load (LMA);
    p_filesz file bytes from each segment occupy [p_paddr, p_paddr+p_filesz).

    The range may span multiple PT_LOAD segments (PX4 firmware uses separate
    segments for .text+.rodata, .data's LMA copy, .compliance_params, etc.).
    We collect the overlapping slice from each segment, sort by address, and
    concatenate. If the segments don't tile the requested range contiguously
    (a gap that would be 0xff erase bytes in actual FLASH), we raise — silent
    gap-fill would diverge from the FC's linear flash read.
    """
    from elftools.elf.elffile import ELFFile

    if lma_end < lma_start:
        raise ValueError(f"lma_end ({lma_end:#x}) < lma_start ({lma_start:#x})")

    pieces = []  # list of (segment_lma_start, bytes-slice-of-segment-overlapping-range)
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            seg_start = seg.header.p_paddr
            seg_end = seg_start + seg.header.p_filesz
            if seg_end <= lma_start or seg_start >= lma_end:
                continue  # no overlap
            overlap_start = max(seg_start, lma_start)
            overlap_end = min(seg_end, lma_end)
            offset = overlap_start - seg_start
            length = overlap_end - overlap_start
            pieces.append((overlap_start, seg.data()[offset:offset + length]))

    if not pieces:
        raise ValueError(
            f"FLASH range [{lma_start:#x}, {lma_end:#x}) has no PT_LOAD coverage."
        )

    pieces.sort(key=lambda p: p[0])
    out = bytearray()
    cursor = lma_start
    for piece_start, piece_bytes in pieces:
        if piece_start > cursor:
            raise ValueError(
                f"FLASH range [{lma_start:#x}, {lma_end:#x}) has a gap at "
                f"[{cursor:#x}, {piece_start:#x}) — no PT_LOAD covers it. "
                "Hashing this would silently fill with bytes that diverge from "
                "the FC's actual flash read."
            )
        if piece_start < cursor:
            # Overlapping segments — should not happen in a well-formed firmware
            # ELF, but guard anyway.
            overlap = cursor - piece_start
            piece_bytes = piece_bytes[overlap:]
            piece_start = cursor
        out.extend(piece_bytes)
        cursor = piece_start + len(piece_bytes)

    if cursor != lma_end:
        raise ValueError(
            f"FLASH range [{lma_start:#x}, {lma_end:#x}) ends short at "
            f"{cursor:#x} — last PT_LOAD doesn't cover up to lma_end."
        )

    return bytes(out)


def hash_flash_ranges_from_elf(elf_path: Path) -> tuple:
    """
    Compute (code_hash, data_hash) by slicing the FLASH byte ranges that the
    FC POST hashes, directly from the ELF's PT_LOAD segments.

    Returns:
        (code_hash_hex, data_hash_hex) — both 64-char SHA-256 hex strings.
    """
    elf_path = Path(elf_path)
    syms = _read_elf_symbols(elf_path)

    code_bytes = _extract_flash_range(
        elf_path, syms["_stext"], syms["_compliance_params_start"]
    )
    data_bytes = _extract_flash_range(
        elf_path, syms["_compliance_params_start"], syms["_compliance_params_end"]
    )

    if len(code_bytes) == 0:
        raise ValueError("Empty code range: _stext == _compliance_params_start")
    # Empty data range is a real possibility (zero compliance params) — allow it.

    return (
        hashlib.sha256(code_bytes).hexdigest(),
        hashlib.sha256(data_bytes).hexdigest(),
    )


def generate_manifest(
    px4_path: Path,
    firmware_version: str = "",
    board_id: int = None,
    elf_path: Path = None,
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

    Mode selection (highest priority first):
      1. elf_path           — hardware mode. Hashes the same FLASH byte ranges
                              the FC POST does. This is what real signing uses.
      2. code_bin_path /
         data_bin_path      — DEPRECATED two-file mode. Emits a warning.
      3. (default)          — SITL mode: hashes the .px4 image and parameter_xml.

    Args:
        px4_path:       Path to the .px4 firmware file
        firmware_version: Override version string
        board_id:       Override board ID (default: read from .px4)
        elf_path:       Path to firmware ELF (hardware mode)
        code_bin_path:  Path to extracted .text section binary (DEPRECATED)
        data_bin_path:  Path to extracted .data section binary (DEPRECATED)
    """
    with open(px4_path, "r") as f:
        firmware_meta = json.load(f)

    # Use provided version, fall back to version embedded in .px4
    version = firmware_version or firmware_meta.get("version", "unknown")

    # Board ID: explicit override > .px4 metadata > 0
    manifest_board_id = board_id if board_id is not None else firmware_meta.get("board_id", 0)

    if elf_path is not None:
        # Hardware mode: hash the same FLASH ranges the FC POST hashes.
        if code_bin_path is not None or data_bin_path is not None:
            raise ValueError(
                "--elf cannot be combined with --code-bin/--data-bin; pick one mode."
            )
        code_hash, data_hash = hash_flash_ranges_from_elf(elf_path)
    elif code_bin_path is not None or data_bin_path is not None:
        warnings.warn(
            "--code-bin/--data-bin is deprecated and will be removed; use --elf "
            "to hash the same FLASH ranges the FC POST hashes (ADR-018).",
            DeprecationWarning,
            stacklevel=2,
        )
        code_hash = (compute_file_checksum(code_bin_path)
                     if code_bin_path is not None else compute_code_checksum(px4_path))
        data_hash = (compute_file_checksum(data_bin_path)
                     if data_bin_path is not None else compute_data_checksum(px4_path))
    else:
        # SITL mode: hash the .px4 image and embedded parameter_xml.
        code_hash = compute_code_checksum(px4_path)
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
    parser.add_argument("--elf", default=None,
                        help="Path to firmware ELF (hardware mode — hashes the "
                             "same FLASH ranges the FC POST hashes)")
    parser.add_argument("--code-bin", default=None,
                        help="DEPRECATED: pre-extracted .text section binary")
    parser.add_argument("--data-bin", default=None,
                        help="DEPRECATED: pre-extracted .data section binary")
    parser.add_argument("--output", default="", help="Output path for manifest JSON (optional)")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        exit(1)

    elf_path = Path(args.elf) if args.elf else None
    code_bin = Path(args.code_bin) if args.code_bin else None
    data_bin = Path(args.data_bin) if args.data_bin else None

    if elf_path and not elf_path.exists():
        print(f"[ERROR] ELF not found: {elf_path}")
        exit(1)
    if code_bin and not code_bin.exists():
        print(f"[ERROR] Code binary not found: {code_bin}")
        exit(1)
    if data_bin and not data_bin.exists():
        print(f"[ERROR] Data binary not found: {data_bin}")
        exit(1)

    if elf_path:
        mode = "hardware (ELF — FC POST byte ranges)"
    elif code_bin or data_bin:
        mode = "hardware (DEPRECATED two-file)"
    else:
        mode = "SITL (.px4 image)"
    print(f"Computing checksums for: {px4_path.name}  [{mode}]")
    manifest = generate_manifest(
        px4_path,
        firmware_version=args.version,
        board_id=args.board_id,
        elf_path=elf_path,
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
