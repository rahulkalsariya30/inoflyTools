"""
tests/compliance/test_CHK001_checksum.py

Compliance tests for CHK001 — SHA-256 firmware checksum generation

Requirement: CHK001
  - Compute SHA-256 checksum of firmware CODE PART separately
  - Compute SHA-256 checksum of firmware DATA PART separately
  - Checksums must be deterministic (same input = same output, always)
  - Algorithm must be SHA-256 (not MD5, not SHA-1)
  - Manifest must record algorithm, version, board_id, and timestamp
"""

import base64
import hashlib
import json
import struct
import warnings
import zlib
import pytest
from pathlib import Path

# Add project root to path so we can import our tools
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.checksum.checksum import (
    compute_code_checksum,
    compute_data_checksum,
    extract_image_bytes,
    extract_parameter_bytes,
    generate_manifest,
    hash_flash_ranges_from_elf,
    save_manifest,
)


# ---------------------------------------------------------------------------
# Fixtures — build fake .px4 files for testing without a real PX4 build
# ---------------------------------------------------------------------------

def make_px4_file(tmp_path, image_bytes: bytes, param_bytes: bytes = b"", version: str = "1.0.0-test", board_id: int = 50) -> Path:
    """
    Create a minimal .px4 JSON file with the given image and parameter bytes.
    Mirrors the format produced by PX4's Tools/px_mkfw.py.
    """
    firmware = {
        "magic": "PX4FWv1",
        "board_id": board_id,
        "board_revision": 0,
        "version": version,
        "git_hash": "abc123def456",
        "build_time": 1700000000,
        "image_size": len(image_bytes),
        "image": base64.b64encode(zlib.compress(image_bytes, 9)).decode("utf-8"),
    }
    if param_bytes:
        firmware["parameter_xml_size"] = len(param_bytes)
        firmware["parameter_xml"] = base64.b64encode(zlib.compress(param_bytes, 9)).decode("utf-8")

    tmp_path.mkdir(parents=True, exist_ok=True)
    px4_path = tmp_path / "test_firmware.px4"
    px4_path.write_text(json.dumps(firmware, indent=4))
    return px4_path


@pytest.fixture
def sample_firmware(tmp_path):
    """A .px4 file with known image and parameter content."""
    image = b"\x7fELF" + b"\x00" * 256  # Fake ELF header + padding
    params = b'<parameters version="1"><parameter name="TEST">42</parameter></parameters>'
    return make_px4_file(tmp_path, image_bytes=image, param_bytes=params)


@pytest.fixture
def firmware_no_params(tmp_path):
    """A .px4 file with no parameter_xml field (older builds)."""
    image = b"\x7fELF" + b"\x01" * 128
    return make_px4_file(tmp_path, image_bytes=image, param_bytes=b"")


# ---------------------------------------------------------------------------
# CHK001 — Code part checksum tests
# ---------------------------------------------------------------------------

class TestCHK001_CodeChecksum:

    def test_CHK001_code_checksum_returns_string(self, sample_firmware):
        result = compute_code_checksum(sample_firmware)
        assert isinstance(result, str)

    def test_CHK001_code_checksum_is_64_chars(self, sample_firmware):
        """SHA-256 hex digest is always 64 hex characters."""
        result = compute_code_checksum(sample_firmware)
        assert len(result) == 64

    def test_CHK001_code_checksum_is_hex(self, sample_firmware):
        """Digest must be valid hexadecimal — no other characters."""
        result = compute_code_checksum(sample_firmware)
        assert all(c in "0123456789abcdef" for c in result)

    def test_CHK001_code_checksum_is_deterministic(self, sample_firmware):
        """Same firmware file must always produce same checksum."""
        result1 = compute_code_checksum(sample_firmware)
        result2 = compute_code_checksum(sample_firmware)
        assert result1 == result2

    def test_CHK001_code_checksum_matches_manual_sha256(self, sample_firmware):
        """Verify the checksum matches what we'd compute manually."""
        # Extract the image bytes the same way the function does
        image_bytes = extract_image_bytes(sample_firmware)
        expected = hashlib.sha256(image_bytes).hexdigest()
        result = compute_code_checksum(sample_firmware)
        assert result == expected

    def test_CHK001_different_firmware_produces_different_code_checksum(self, tmp_path):
        """Two different firmware binaries must produce different checksums."""
        fw1 = make_px4_file(tmp_path / "fw1", image_bytes=b"\x00" * 100)
        fw2 = make_px4_file(tmp_path / "fw2", image_bytes=b"\xFF" * 100)
        assert compute_code_checksum(fw1) != compute_code_checksum(fw2)

    def test_CHK001_single_byte_change_changes_code_checksum(self, tmp_path):
        """Even one changed byte in firmware must change the checksum."""
        image_a = bytearray(b"\x7fELF" + b"\x00" * 200)
        image_b = bytearray(image_a)
        image_b[50] = 0xFF  # Flip one byte

        fw_a = make_px4_file(tmp_path / "fwa", image_bytes=bytes(image_a))
        fw_b = make_px4_file(tmp_path / "fwb", image_bytes=bytes(image_b))
        assert compute_code_checksum(fw_a) != compute_code_checksum(fw_b)


# ---------------------------------------------------------------------------
# CHK001 — Data part checksum tests
# ---------------------------------------------------------------------------

class TestCHK001_DataChecksum:

    def test_CHK001_data_checksum_returns_string(self, sample_firmware):
        result = compute_data_checksum(sample_firmware)
        assert isinstance(result, str)

    def test_CHK001_data_checksum_is_64_chars(self, sample_firmware):
        result = compute_data_checksum(sample_firmware)
        assert len(result) == 64

    def test_CHK001_data_checksum_is_deterministic(self, sample_firmware):
        """Same parameter set must always produce same checksum."""
        result1 = compute_data_checksum(sample_firmware)
        result2 = compute_data_checksum(sample_firmware)
        assert result1 == result2

    def test_CHK001_data_checksum_matches_manual_sha256(self, sample_firmware):
        """Verify the data checksum matches what we'd compute manually."""
        param_bytes = extract_parameter_bytes(sample_firmware)
        expected = hashlib.sha256(param_bytes).hexdigest()
        result = compute_data_checksum(sample_firmware)
        assert result == expected

    def test_CHK001_no_params_returns_sha256_of_empty(self, firmware_no_params):
        """Firmware without parameter_xml should hash empty bytes — not crash."""
        result = compute_data_checksum(firmware_no_params)
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_CHK001_code_and_data_checksums_are_different(self, sample_firmware):
        """Code and data checksums must differ — they hash different content."""
        code = compute_code_checksum(sample_firmware)
        data = compute_data_checksum(sample_firmware)
        assert code != data

    def test_CHK001_different_params_produce_different_data_checksum(self, tmp_path):
        """Changing default parameters must change the data checksum."""
        image = b"\x7fELF" + b"\x00" * 100
        params_a = b'<parameters><param name="SPEED">10</param></parameters>'
        params_b = b'<parameters><param name="SPEED">20</param></parameters>'

        fw_a = make_px4_file(tmp_path / "fwa", image_bytes=image, param_bytes=params_a)
        fw_b = make_px4_file(tmp_path / "fwb", image_bytes=image, param_bytes=params_b)

        assert compute_data_checksum(fw_a) != compute_data_checksum(fw_b)

    def test_CHK001_same_params_different_code_keeps_data_checksum_stable(self, tmp_path):
        """
        If only the firmware binary changes but parameters stay the same,
        the data checksum must NOT change.
        This is the whole point of separating code and data checksums.
        """
        params = b'<parameters><param name="ALT">100</param></parameters>'
        fw_v1 = make_px4_file(tmp_path / "fw1", image_bytes=b"\x00" * 100, param_bytes=params)
        fw_v2 = make_px4_file(tmp_path / "fw2", image_bytes=b"\xFF" * 100, param_bytes=params)

        assert compute_data_checksum(fw_v1) == compute_data_checksum(fw_v2)
        assert compute_code_checksum(fw_v1) != compute_code_checksum(fw_v2)


# ---------------------------------------------------------------------------
# CHK001 — Manifest tests
# ---------------------------------------------------------------------------

class TestCHK001_Manifest:

    def test_CHK001_manifest_contains_required_fields(self, sample_firmware):
        manifest = generate_manifest(sample_firmware)
        required = {"algorithm", "code_checksum", "data_checksum", "firmware_version",
                    "source_file", "board_id", "generated_at"}
        assert required.issubset(manifest.keys())

    def test_CHK001_manifest_algorithm_is_sha256(self, sample_firmware):
        """Manifest must explicitly record SHA-256 — auditors need to know."""
        manifest = generate_manifest(sample_firmware)
        assert manifest["algorithm"] == "SHA-256"

    def test_CHK001_manifest_source_file_is_filename(self, sample_firmware):
        manifest = generate_manifest(sample_firmware)
        assert manifest["source_file"] == "test_firmware.px4"

    def test_CHK001_manifest_board_id_matches_firmware(self, sample_firmware):
        manifest = generate_manifest(sample_firmware)
        assert manifest["board_id"] == 50  # matches what make_px4_file sets

    def test_CHK001_manifest_version_uses_caller_override(self, sample_firmware):
        """Caller can override the version string (e.g. to add build suffix)."""
        manifest = generate_manifest(sample_firmware, firmware_version="2.0.0-rc1")
        assert manifest["firmware_version"] == "2.0.0-rc1"

    def test_CHK001_manifest_version_falls_back_to_px4_version(self, sample_firmware):
        """Without override, version comes from the .px4 file itself."""
        manifest = generate_manifest(sample_firmware)
        assert manifest["firmware_version"] == "1.0.0-test"

    def test_CHK001_manifest_save_creates_json_file(self, sample_firmware, tmp_path):
        manifest = generate_manifest(sample_firmware)
        output_path = tmp_path / "checksums" / "manifest.json"
        save_manifest(manifest, output_path)

        assert output_path.exists()
        loaded = json.loads(output_path.read_text())
        assert loaded["algorithm"] == "SHA-256"
        assert loaded["code_checksum"] == manifest["code_checksum"]
        assert loaded["data_checksum"] == manifest["data_checksum"]

    def test_CHK001_manifest_save_creates_parent_dirs(self, sample_firmware, tmp_path):
        """save_manifest should create any missing parent directories."""
        output_path = tmp_path / "deep" / "nested" / "path" / "manifest.json"
        manifest = generate_manifest(sample_firmware)
        save_manifest(manifest, output_path)
        assert output_path.exists()


# ---------------------------------------------------------------------------
# CHK001 — Hardware mode (--elf): hash the FLASH ranges the FC POST hashes
# ---------------------------------------------------------------------------
#
# These tests exercise hash_flash_ranges_from_elf without depending on a real
# 2 MB PX4 firmware ELF (too big for a fixture). _build_minimal_elf assembles
# a valid ELF32-LE ARM image with the three linker symbols POST cares about
# (_stext, _compliance_params_start, _compliance_params_end) and one or more
# PT_LOAD segments. The host code reads symbols + LOAD segments — that's the
# entire surface we need to cover here. The host-vs-FC equivalence on a real
# build is verified out-of-band by the SITL acceptance gate.

def _build_minimal_elf(segments, symbols):
    """
    Build a minimal valid ELF32-LE ARM file in memory.

    segments: list of (lma_address, raw_bytes) — one PT_LOAD each.
    symbols:  dict {name: address} — emitted as global SHN_ABS symbols.

    The output is just enough to round-trip through pyelftools: an ELF
    header, program headers (one per segment), .shstrtab, .symtab, .strtab,
    and section headers. No real .text/.data sections — this firmware is
    not meant to execute, only to be parsed by our reader.
    """
    EHDR_SIZE, PHDR_SIZE, SHDR_SIZE = 52, 32, 40
    PT_LOAD = 1
    SHT_SYMTAB, SHT_STRTAB = 2, 3
    SHN_ABS = 0xfff1
    STB_GLOBAL, STT_NOTYPE = 1, 0
    info_global = (STB_GLOBAL << 4) | STT_NOTYPE

    # Section name string table.
    shstrtab = b'\x00.shstrtab\x00.symtab\x00.strtab\x00'
    off_shstrtab_name = shstrtab.index(b'.shstrtab\x00')
    off_symtab_name   = shstrtab.index(b'.symtab\x00')
    off_strtab_name   = shstrtab.index(b'.strtab\x00')

    # Symbol name string table.
    strtab = b'\x00'
    sym_name_offsets = {}
    for name in symbols:
        sym_name_offsets[name] = len(strtab)
        strtab += name.encode() + b'\x00'

    # Symbol table — first entry is the mandatory null symbol.
    symtab = struct.pack('<IIIBBH', 0, 0, 0, 0, 0, 0)
    for name, addr in symbols.items():
        symtab += struct.pack(
            '<IIIBBH',
            sym_name_offsets[name], addr, 0,
            info_global, 0, SHN_ABS,
        )

    NUM_PHDRS = len(segments)
    NUM_SHDRS = 4  # null, .shstrtab, .symtab, .strtab
    cur = EHDR_SIZE + NUM_PHDRS * PHDR_SIZE

    seg_offsets = []
    for _lma, data in segments:
        seg_offsets.append(cur)
        cur += len(data)

    shstrtab_off, cur = cur, cur + len(shstrtab)
    symtab_off,   cur = cur, cur + len(symtab)
    strtab_off,   cur = cur, cur + len(strtab)
    shoff = cur

    e_ident = b'\x7fELF\x01\x01\x01\x00' + b'\x00' * 8  # ELFCLASS32 ELFDATA2LSB EV_CURRENT
    ehdr = e_ident + struct.pack(
        '<HHIIIIIHHHHHH',
        2,                                   # ET_EXEC
        40,                                  # EM_ARM
        1,                                   # EV_CURRENT
        segments[0][0] if segments else 0,   # e_entry
        EHDR_SIZE,                           # e_phoff
        shoff,                               # e_shoff
        0,                                   # e_flags
        EHDR_SIZE, PHDR_SIZE, NUM_PHDRS,
        SHDR_SIZE, NUM_SHDRS,
        1,                                   # e_shstrndx (.shstrtab is section 1)
    )

    phdrs = b''
    for (lma, data), file_off in zip(segments, seg_offsets):
        phdrs += struct.pack(
            '<IIIIIIII',
            PT_LOAD, file_off, lma, lma,
            len(data), len(data),
            5,                               # PF_R | PF_X
            4,                               # alignment
        )

    null_shdr     = struct.pack('<IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shstrtab_shdr = struct.pack('<IIIIIIIIII',
                                off_shstrtab_name, SHT_STRTAB, 0, 0,
                                shstrtab_off, len(shstrtab), 0, 0, 1, 0)
    symtab_shdr   = struct.pack('<IIIIIIIIII',
                                off_symtab_name, SHT_SYMTAB, 0, 0,
                                symtab_off, len(symtab),
                                3,           # sh_link -> .strtab is section 3
                                1,           # sh_info: index of first global symbol
                                4, 16)
    strtab_shdr   = struct.pack('<IIIIIIIIII',
                                off_strtab_name, SHT_STRTAB, 0, 0,
                                strtab_off, len(strtab), 0, 0, 1, 0)

    out = bytearray()
    out += ehdr
    out += phdrs
    for _lma, data in segments:
        out += data
    out += shstrtab + symtab + strtab
    out += null_shdr + shstrtab_shdr + symtab_shdr + strtab_shdr
    return bytes(out)


@pytest.fixture
def synth_elf(tmp_path):
    """
    A minimal ELF that mirrors the PX4 FLASH layout the FC POST hashes.

    Memory map (mirrors cubeorangeplus script.ld):
      0x08020000 _stext               +-- code range (0x100 bytes) --+
      0x08020100 _compliance_params_start                            |
                                      +-- data range (0x60 bytes) --+
      0x08020160 _compliance_params_end

    Two PT_LOAD segments — that's the realistic case (PX4 has separate
    LOAD entries for .text+.rodata, .data LMA, .compliance_params, etc.),
    and it exercises the multi-segment-concat path in _extract_flash_range.
    """
    code_bytes = bytes((i & 0xff for i in range(0x100)))
    data_bytes = bytes((0xa0 | (i & 0xf) for i in range(0x60)))
    elf_bytes = _build_minimal_elf(
        segments=[
            (0x08020000, code_bytes),
            (0x08020100, data_bytes),
        ],
        symbols={
            "_stext":                   0x08020000,
            "_compliance_params_start": 0x08020100,
            "_compliance_params_end":   0x08020160,
        },
    )
    elf_path = tmp_path / "synth.elf"
    elf_path.write_bytes(elf_bytes)
    return elf_path, code_bytes, data_bytes


class TestCHK001_HardwareElfMode:
    """ADR-018: hash the same FLASH ranges the FC POST hashes."""

    def test_CHK001_elf_code_hash_matches_manual_sha256(self, synth_elf):
        elf_path, code_bytes, _ = synth_elf
        code_hash, _ = hash_flash_ranges_from_elf(elf_path)
        assert code_hash == hashlib.sha256(code_bytes).hexdigest()

    def test_CHK001_elf_data_hash_matches_manual_sha256(self, synth_elf):
        elf_path, _, data_bytes = synth_elf
        _, data_hash = hash_flash_ranges_from_elf(elf_path)
        assert data_hash == hashlib.sha256(data_bytes).hexdigest()

    def test_CHK001_elf_code_and_data_hashes_differ(self, synth_elf):
        elf_path, _, _ = synth_elf
        code_hash, data_hash = hash_flash_ranges_from_elf(elf_path)
        assert code_hash != data_hash

    def test_CHK001_elf_changing_compliance_param_byte_keeps_code_hash_stable(self, tmp_path):
        """Mutating a byte inside .compliance_params must not change code_hash —
        that's the entire point of placing the table in its own FLASH section."""
        code_bytes = b"\x11" * 0x100
        data_a = b"\x22" * 0x60
        data_b = bytearray(data_a); data_b[10] = 0x77

        symbols = {
            "_stext":                   0x08020000,
            "_compliance_params_start": 0x08020100,
            "_compliance_params_end":   0x08020160,
        }
        elf_a = tmp_path / "a.elf"
        elf_b = tmp_path / "b.elf"
        elf_a.write_bytes(_build_minimal_elf(
            [(0x08020000, code_bytes), (0x08020100, bytes(data_a))], symbols))
        elf_b.write_bytes(_build_minimal_elf(
            [(0x08020000, code_bytes), (0x08020100, bytes(data_b))], symbols))

        code_a, data_a_hash = hash_flash_ranges_from_elf(elf_a)
        code_b, data_b_hash = hash_flash_ranges_from_elf(elf_b)
        assert code_a == code_b
        assert data_a_hash != data_b_hash

    def test_CHK001_elf_missing_symbol_raises(self, tmp_path):
        elf_path = tmp_path / "no_symbol.elf"
        elf_path.write_bytes(_build_minimal_elf(
            segments=[(0x08020000, b"\x00" * 0x10)],
            symbols={"_stext": 0x08020000},  # missing the two _compliance_params_*
        ))
        with pytest.raises(ValueError, match="missing required linker symbols"):
            hash_flash_ranges_from_elf(elf_path)

    def test_CHK001_elf_gap_between_segments_raises(self, tmp_path):
        """Silently 0xff-filling a gap would diverge from the FC's flash read."""
        # Code range [_stext .. _compliance_params_start) spans both segments AND
        # the gap between them — must raise rather than silently fill.
        symbols = {
            "_stext":                   0x08020000,
            "_compliance_params_start": 0x08020090,
            "_compliance_params_end":   0x080200a0,
        }
        elf_path = tmp_path / "gap.elf"
        elf_path.write_bytes(_build_minimal_elf(
            segments=[
                (0x08020000, b"\x00" * 0x40),  # [0x...000, 0x...040)
                # GAP: 0x...040 .. 0x...080  — no segment here
                (0x08020080, b"\x00" * 0x20),  # [0x...080, 0x...0a0)
            ],
            symbols=symbols,
        ))
        with pytest.raises(ValueError, match="gap"):
            hash_flash_ranges_from_elf(elf_path)


class TestCHK001_ManifestModeSelection:
    """generate_manifest mode dispatch and deprecation behavior."""

    def test_CHK001_manifest_elf_mode_uses_elf_hashes(self, sample_firmware, synth_elf):
        elf_path, code_bytes, data_bytes = synth_elf
        manifest = generate_manifest(sample_firmware, elf_path=elf_path)
        assert manifest["code_checksum"] == hashlib.sha256(code_bytes).hexdigest()
        assert manifest["data_checksum"] == hashlib.sha256(data_bytes).hexdigest()

    def test_CHK001_manifest_elf_with_code_bin_raises(self, sample_firmware, synth_elf, tmp_path):
        elf_path, _, _ = synth_elf
        bin_path = tmp_path / "code.bin"; bin_path.write_bytes(b"\x00" * 16)
        with pytest.raises(ValueError, match="cannot be combined"):
            generate_manifest(sample_firmware, elf_path=elf_path, code_bin_path=bin_path)

    def test_CHK001_manifest_legacy_two_file_emits_deprecation(self, sample_firmware, tmp_path):
        code_bin = tmp_path / "code.bin"; code_bin.write_bytes(b"\xaa" * 32)
        data_bin = tmp_path / "data.bin"; data_bin.write_bytes(b"\xbb" * 16)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            manifest = generate_manifest(sample_firmware,
                                         code_bin_path=code_bin, data_bin_path=data_bin)
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)
        # Behavior preserved: legacy mode still hashes the two binaries directly.
        assert manifest["code_checksum"] == hashlib.sha256(b"\xaa" * 32).hexdigest()
        assert manifest["data_checksum"] == hashlib.sha256(b"\xbb" * 16).hexdigest()
