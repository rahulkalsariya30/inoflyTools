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
