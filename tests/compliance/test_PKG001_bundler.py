"""
tests/compliance/test_PKG001_bundler.py

Compliance tests for PKG001 — Firmware update bundle packaging

Requirement: PKG001
  - Bundle must contain firmware, signed manifest, and bundle_info
  - Signature inside the bundle must be verifiable
  - Bundle must reject installation if any file is missing
  - Firmware and signed manifest cannot be swapped independently
  - Bundle metadata must accurately reflect the firmware contents
"""

import base64
import json
import zipfile
import zlib
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.bundler.bundler import (
    create_bundle,
    verify_bundle,
    inspect_bundle,
    extract_firmware,
)
from tools.pki.keygen import generate_keypair
from tools.signer.signer import sign_manifest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_px4_file(tmp_path: Path, image_bytes: bytes = b"\x7fELF" + b"\x00" * 256) -> Path:
    """Create a minimal .px4 file for testing."""
    firmware = {
        "magic": "PX4FWv1",
        "board_id": 50,
        "version": "1.14.0-test",
        "git_hash": "abc123",
        "build_time": 1700000000,
        "image_size": len(image_bytes),
        "image": base64.b64encode(zlib.compress(image_bytes, 9)).decode("utf-8"),
    }
    px4_path = tmp_path / "test_firmware.px4"
    px4_path.write_text(json.dumps(firmware, indent=4))
    return px4_path


@pytest.fixture
def keypair(tmp_path):
    private_pem, public_pem = generate_keypair()
    private_path = tmp_path / "private" / "manufacturer_private.pem"
    public_path  = tmp_path / "public"  / "manufacturer_public.pem"
    private_path.parent.mkdir(parents=True)
    public_path.parent.mkdir(parents=True)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return {"private": private_path, "public": public_path}


@pytest.fixture
def sample_manifest():
    return {
        "algorithm": "SHA-256",
        "firmware_version": "1.14.0-test",
        "source_file": "test_firmware.px4",
        "board_id": 50,
        "git_hash": "abc123",
        "code_checksum": "a" * 64,
        "data_checksum": "b" * 64,
        "generated_at": "2026-01-01T00:00:00+00:00",
    }


@pytest.fixture
def signed_manifest(sample_manifest, keypair):
    return sign_manifest(sample_manifest, private_key_path=keypair["private"])


@pytest.fixture
def bundle_path(tmp_path, signed_manifest, keypair):
    """A fully created .fwbundle file."""
    px4_path = make_px4_file(tmp_path)
    output = tmp_path / "output" / "firmware.fwbundle"
    create_bundle(px4_path, signed_manifest, output)
    return output, keypair


# ---------------------------------------------------------------------------
# PKG001 — Bundle creation tests
# ---------------------------------------------------------------------------

class TestPKG001_BundleCreation:

    def test_PKG001_create_bundle_produces_file(self, tmp_path, signed_manifest, keypair):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "firmware.fwbundle"
        result = create_bundle(px4_path, signed_manifest, output)
        assert result.exists()

    def test_PKG001_bundle_is_valid_zip(self, tmp_path, signed_manifest):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        assert zipfile.is_zipfile(output)

    def test_PKG001_bundle_contains_firmware(self, tmp_path, signed_manifest):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        with zipfile.ZipFile(output) as zf:
            assert "firmware.px4" in zf.namelist()

    def test_PKG001_bundle_contains_signed_manifest(self, tmp_path, signed_manifest):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        with zipfile.ZipFile(output) as zf:
            assert "signed_manifest.json" in zf.namelist()

    def test_PKG001_bundle_contains_bundle_info(self, tmp_path, signed_manifest):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        with zipfile.ZipFile(output) as zf:
            assert "bundle_info.json" in zf.namelist()

    def test_PKG001_bundle_firmware_bytes_match_original(self, tmp_path, signed_manifest):
        """The firmware stored in the bundle must be byte-for-byte identical to the source."""
        px4_path = make_px4_file(tmp_path)
        original_bytes = px4_path.read_bytes()
        output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        with zipfile.ZipFile(output) as zf:
            bundled_bytes = zf.read("firmware.px4")
        assert bundled_bytes == original_bytes

    def test_PKG001_missing_firmware_file_raises_error(self, tmp_path, signed_manifest):
        with pytest.raises(FileNotFoundError):
            create_bundle(tmp_path / "nonexistent.px4", signed_manifest, tmp_path / "out.fwbundle")

    def test_PKG001_incomplete_signed_manifest_raises_error(self, tmp_path):
        """Must reject a manifest missing the signature field."""
        px4_path = make_px4_file(tmp_path)
        incomplete = {"manifest": {}, "signed_at": "2026-01-01"}  # missing "signature"
        with pytest.raises(ValueError, match="missing fields"):
            create_bundle(px4_path, incomplete, tmp_path / "out.fwbundle")

    def test_PKG001_create_bundle_creates_parent_directories(self, tmp_path, signed_manifest):
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "deep" / "nested" / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        assert output.exists()


# ---------------------------------------------------------------------------
# PKG001 — Bundle verification tests
# ---------------------------------------------------------------------------

class TestPKG001_BundleVerification:

    def test_PKG001_valid_bundle_verifies_successfully(self, bundle_path):
        path, keypair = bundle_path
        result = verify_bundle(path, public_key_path=keypair["public"])
        assert result is True

    def test_PKG001_wrong_public_key_fails_verification(self, bundle_path, tmp_path):
        """A different manufacturer's key must not verify our bundle."""
        path, _ = bundle_path
        _, different_public_pem = generate_keypair()
        different_key = tmp_path / "other_public.pem"
        different_key.write_bytes(different_public_pem)
        result = verify_bundle(path, public_key_path=different_key)
        assert result is False

    def test_PKG001_tampered_manifest_fails_verification(self, tmp_path, signed_manifest, keypair):
        """
        If someone replaces signed_manifest.json inside the ZIP with a tampered
        version, verification must fail.
        """
        px4_path = make_px4_file(tmp_path)
        bundle_output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, bundle_output)

        # Tamper: modify the manifest inside the ZIP
        tampered_manifest = json.loads(json.dumps(signed_manifest))
        tampered_manifest["manifest"]["code_checksum"] = "f" * 64

        tampered_bundle = tmp_path / "tampered.fwbundle"
        with zipfile.ZipFile(bundle_output, "r") as zin:
            with zipfile.ZipFile(tampered_bundle, "w") as zout:
                for item in zin.infolist():
                    if item.filename == "signed_manifest.json":
                        zout.writestr(item, json.dumps(tampered_manifest, indent=4))
                    else:
                        zout.writestr(item, zin.read(item.filename))

        result = verify_bundle(tampered_bundle, public_key_path=keypair["public"])
        assert result is False

    def test_PKG001_bundle_missing_signed_manifest_raises_error(self, tmp_path, signed_manifest, keypair):
        """A bundle without signed_manifest.json is corrupt — must raise ValueError."""
        px4_path = make_px4_file(tmp_path)
        bundle_output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, bundle_output)

        # Build a stripped bundle without signed_manifest.json
        stripped = tmp_path / "stripped.fwbundle"
        with zipfile.ZipFile(bundle_output, "r") as zin:
            with zipfile.ZipFile(stripped, "w") as zout:
                for item in zin.infolist():
                    if item.filename != "signed_manifest.json":
                        zout.writestr(item, zin.read(item.filename))

        with pytest.raises(ValueError, match="missing"):
            verify_bundle(stripped, public_key_path=keypair["public"])

    def test_PKG001_nonexistent_bundle_raises_error(self, tmp_path, keypair):
        with pytest.raises(FileNotFoundError):
            verify_bundle(tmp_path / "nonexistent.fwbundle", public_key_path=keypair["public"])


# ---------------------------------------------------------------------------
# PKG001 — Inspect and extract tests
# ---------------------------------------------------------------------------

class TestPKG001_InspectAndExtract:

    def test_PKG001_inspect_returns_bundle_info(self, bundle_path):
        path, _ = bundle_path
        info = inspect_bundle(path)
        assert "firmware_version" in info
        assert "board_id" in info
        assert "created_at" in info
        assert "bundler_version" in info

    def test_PKG001_inspect_board_id_matches_firmware(self, bundle_path):
        path, _ = bundle_path
        info = inspect_bundle(path)
        assert info["board_id"] == 50  # matches make_px4_file fixture

    def test_PKG001_inspect_firmware_version_matches(self, bundle_path):
        path, _ = bundle_path
        info = inspect_bundle(path)
        assert info["firmware_version"] == "1.14.0-test"

    def test_PKG001_extract_firmware_creates_px4_file(self, bundle_path, tmp_path):
        path, _ = bundle_path
        extract_dir = tmp_path / "extracted"
        result = extract_firmware(path, extract_dir)
        assert result.exists()
        assert result.suffix == ".px4"

    def test_PKG001_extracted_firmware_matches_original(self, tmp_path, signed_manifest, keypair):
        """Extracted firmware must be identical to what was bundled."""
        px4_path = make_px4_file(tmp_path)
        original_bytes = px4_path.read_bytes()

        bundle_output = tmp_path / "firmware.fwbundle"
        create_bundle(px4_path, signed_manifest, bundle_output)

        extract_dir = tmp_path / "extracted"
        extracted = extract_firmware(bundle_output, extract_dir)

        assert extracted.read_bytes() == original_bytes
