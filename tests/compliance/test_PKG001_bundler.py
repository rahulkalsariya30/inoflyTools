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
import hashlib
import json
import zipfile
import zlib
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tools.bundler.bundler import (
    create_bundle,
    verify_bundle,
    inspect_bundle,
    extract_firmware,
    UPDATE_IMAGE_NAME,
    UPDATE_META_NAME,
)
from tools.checksum.checksum import generate_manifest
from tools.pki.keygen import generate_keypair
from tools.signer.signer import sign_manifest

# Synthetic hardware build (signed TOC image + matching ELF) — shared with
# the ADR-023 suite, which owns the builder.
from test_ADR023_sd_update import build_synthetic_setup


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


# ---------------------------------------------------------------------------
# PKG001 — v1.2 staged-update artifacts (ADR-023 A-8)
# ---------------------------------------------------------------------------

@pytest.fixture
def hw_setup(tmp_path, keypair):
    """Synthetic hardware build signed with this test's manufacturer key."""
    return build_synthetic_setup(tmp_path, keypair["private"].read_bytes())


@pytest.fixture
def hw_signed_manifest(hw_setup, keypair):
    """Checksum manifest in ELF mode (the hashes the FC POST computes),
    signed — what the pipeline hands create_bundle in hardware mode."""
    manifest = generate_manifest(hw_setup["signed_px4"], elf_path=hw_setup["elf_path"])
    return sign_manifest(manifest, private_key_path=keypair["private"])


@pytest.fixture
def hw_bundle(tmp_path, hw_setup, hw_signed_manifest, keypair):
    output = tmp_path / "hw.fwbundle"
    create_bundle(hw_setup["signed_px4"], hw_signed_manifest, output,
                  private_key_path=keypair["private"],
                  elf_path=hw_setup["elf_path"])
    return output


def _rewrite_bundle(src: Path, dst: Path, replace: dict = None, drop: set = None):
    """Copy a bundle, replacing/removing entries — the tamper helper."""
    replace = replace or {}
    drop = drop or set()
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            if item.filename in drop:
                continue
            data = replace.get(item.filename, zin.read(item.filename))
            zout.writestr(item, data)
    return dst


class TestPKG001_UpdateArtifacts:
    """Hardware bundles must carry device-contract-valid SD-staging artifacts;
    SITL bundles must not; verification must catch every tampered combination."""

    def test_PKG001_hw_bundle_contains_update_artifacts(self, hw_bundle):
        with zipfile.ZipFile(hw_bundle) as zf:
            names = zf.namelist()
        assert UPDATE_IMAGE_NAME in names
        assert UPDATE_META_NAME in names

    def test_PKG001_sitl_bundle_has_no_update_artifacts(self, tmp_path, signed_manifest):
        """No ELF -> no staged-update path -> the entries must be absent, not
        present-but-empty."""
        px4_path = make_px4_file(tmp_path)
        output = tmp_path / "sitl.fwbundle"
        create_bundle(px4_path, signed_manifest, output)
        with zipfile.ZipFile(output) as zf:
            names = zf.namelist()
        assert UPDATE_IMAGE_NAME not in names
        assert UPDATE_META_NAME not in names

    def test_PKG001_update_image_is_the_signed_flash_image(self, hw_bundle, hw_setup):
        with zipfile.ZipFile(hw_bundle) as zf:
            assert zf.read(UPDATE_IMAGE_NAME) == hw_setup["signed_image"]

    def test_PKG001_update_meta_matches_device_contract(self, hw_bundle, hw_setup):
        with zipfile.ZipFile(hw_bundle) as zf:
            meta = json.loads(zf.read(UPDATE_META_NAME))
            image = zf.read(UPDATE_IMAGE_NAME)
        assert meta["image_size"] == len(image)
        assert meta["code_len"] == hw_setup["code_len"]
        assert meta["data_len"] == hw_setup["data_len"]
        assert meta["code_len"] + meta["data_len"] == meta["image_size"] - 256
        assert meta["sha256"] == hashlib.sha256(image).hexdigest()

    def test_PKG001_bundle_info_records_update_image(self, hw_bundle):
        info = inspect_bundle(hw_bundle)
        assert info["update_image"]["image_size"] > 0

    def test_PKG001_hw_bundle_verifies(self, hw_bundle, keypair):
        assert verify_bundle(hw_bundle, public_key_path=keypair["public"]) is True

    def test_PKG001_unsigned_px4_with_elf_refused(self, tmp_path, hw_setup,
                                                  hw_signed_manifest, keypair):
        """An image still carrying the zero signature placeholder would be
        refused by the bootloader — packaging it must fail on the host."""
        with pytest.raises(ValueError, match="placeholder"):
            create_bundle(hw_setup["unsigned_px4"], hw_signed_manifest,
                          tmp_path / "bad.fwbundle",
                          private_key_path=keypair["private"],
                          elf_path=hw_setup["elf_path"])

    def test_PKG001_failed_artifact_build_leaves_no_bundle(self, tmp_path, hw_setup,
                                                           hw_signed_manifest, keypair):
        """The artifacts are built before the zip is opened, so a refusal must
        not leave a half-written bundle a release process could pick up."""
        output = tmp_path / "half.fwbundle"
        with pytest.raises(ValueError):
            create_bundle(hw_setup["unsigned_px4"], hw_signed_manifest, output,
                          private_key_path=keypair["private"],
                          elf_path=hw_setup["elf_path"])
        assert not output.exists()

    def test_PKG001_image_without_meta_raises(self, hw_bundle, tmp_path, keypair):
        stripped = _rewrite_bundle(hw_bundle, tmp_path / "no_meta.fwbundle",
                                   drop={UPDATE_META_NAME})
        with pytest.raises(ValueError, match="counterpart"):
            verify_bundle(stripped, public_key_path=keypair["public"])

    def test_PKG001_meta_without_image_raises(self, hw_bundle, tmp_path, keypair):
        stripped = _rewrite_bundle(hw_bundle, tmp_path / "no_image.fwbundle",
                                   drop={UPDATE_IMAGE_NAME})
        with pytest.raises(ValueError, match="counterpart"):
            verify_bundle(stripped, public_key_path=keypair["public"])

    def test_PKG001_tampered_update_image_caught_by_meta(self, hw_bundle, tmp_path,
                                                         hw_setup, keypair):
        """Swapping the image without touching the meta trips the transport
        integrity check (sha256 mismatch)."""
        tampered_image = bytearray(hw_setup["signed_image"])
        tampered_image[hw_setup["code_len"] - 8] ^= 0x01
        tampered = _rewrite_bundle(hw_bundle, tmp_path / "tampered.fwbundle",
                                   replace={UPDATE_IMAGE_NAME: bytes(tampered_image)})
        with pytest.raises(ValueError, match="sha256"):
            verify_bundle(tampered, public_key_path=keypair["public"])

    def test_PKG001_tampered_image_with_fixed_meta_fails_rsa(self, hw_bundle, tmp_path,
                                                             hw_setup, keypair):
        """An attacker who also fixes up the (unsigned) meta sidecar gets past
        the transport check — the RSA-PSS gate must still refuse the image.
        This is the check that mirrors the bootloader's verify-before-erase."""
        tampered_image = bytearray(hw_setup["signed_image"])
        tampered_image[hw_setup["code_len"] - 8] ^= 0x01
        tampered_image = bytes(tampered_image)
        with zipfile.ZipFile(hw_bundle) as zf:
            meta = json.loads(zf.read(UPDATE_META_NAME))
        meta["sha256"] = hashlib.sha256(tampered_image).hexdigest()
        tampered = _rewrite_bundle(
            hw_bundle, tmp_path / "tampered_fixed.fwbundle",
            replace={UPDATE_IMAGE_NAME: tampered_image,
                     UPDATE_META_NAME: json.dumps(meta) + "\n"})
        assert verify_bundle(tampered, public_key_path=keypair["public"]) is False

    def test_PKG001_garbage_update_image_raises(self, hw_bundle, tmp_path, keypair):
        """A replaced image with no parseable TOC is structural corruption."""
        garbage = b"\xde\xad\xbe\xef" * 1024
        meta = {"image_size": len(garbage), "code_len": 4000, "data_len": 96,
                "sha256": hashlib.sha256(garbage).hexdigest()}
        tampered = _rewrite_bundle(
            hw_bundle, tmp_path / "garbage.fwbundle",
            replace={UPDATE_IMAGE_NAME: garbage,
                     UPDATE_META_NAME: json.dumps(meta) + "\n"})
        with pytest.raises(ValueError, match="TOC"):
            verify_bundle(tampered, public_key_path=keypair["public"])
