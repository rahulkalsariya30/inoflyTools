"""
tests/compliance/test_PIPE_pipeline.py

End-to-end pipeline tests
Verifies the full release workflow: checksum → sign → bundle → binary manifest
"""

import json
import base64
import zlib
import struct
import sys
from pathlib import Path

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.pipeline import run_pipeline, PipelineResult
from tools.pki.keygen import generate_keypair  # returns (private_pem, public_pem) bytes
from tools.signer.signer import verify_bundle
from tools.bundler.bundler import verify_bundle as verify_fwbundle
from tools.provisioning.export_manifest import verify_binary_manifest, TOTAL_SIZE
from tools.signer.toc_sign import (
    verify_image,
    TOC_START_MAGIC,
    TOC_END_MAGIC,
    TOC_OFFSET_DEFAULT,
    APP_LOAD_ADDRESS_DEFAULT,
    RSA_2048_SIG_LEN,
)


@pytest.fixture
def temp_keys(tmp_path):
    """Generate a fresh keypair for testing."""
    private_pem, public_pem = generate_keypair()
    private_key = tmp_path / "test_private.pem"
    public_key = tmp_path / "test_public.pem"
    private_key.write_bytes(private_pem)
    public_key.write_bytes(public_pem)
    return private_key, public_key


@pytest.fixture
def fake_px4(tmp_path):
    """Create a realistic fake .px4 firmware file."""
    firmware_binary = b"\x00" * 1024 + b"PX4_FIRMWARE_CODE" + b"\xff" * 512
    param_xml = b"<parameters><param name='COM_ARM_CHK'>1</param></parameters>"

    px4_data = {
        "image": base64.b64encode(zlib.compress(firmware_binary)).decode(),
        "parameter_xml": base64.b64encode(zlib.compress(param_xml)).decode(),
        "board_id": 140,
        "version": "1.14.0-test",
        "git_hash": "abc123def456",
    }

    px4_path = tmp_path / "test_firmware.px4"
    with open(px4_path, "w") as f:
        json.dump(px4_data, f)

    return px4_path


class TestPipeline:
    """Full pipeline integration tests."""

    def test_PIPE_pipeline_completes_successfully(self, fake_px4, temp_keys, tmp_path):
        """Pipeline runs to completion with all verifications passing."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        assert result.all_verified is True

    def test_PIPE_pipeline_creates_all_artifacts(self, fake_px4, temp_keys, tmp_path):
        """Pipeline produces bundle, binary manifest, and signed JSON."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        assert result.fwbundle_path.exists()
        assert result.binary_manifest_path.exists()
        assert result.fwbundle_path.suffix == ".fwbundle"
        assert result.binary_manifest_path.suffix == ".bin"

    def test_PIPE_binary_manifest_is_correct_size(self, fake_px4, temp_keys, tmp_path):
        """Binary manifest must match TOTAL_SIZE (security_manifest_t struct)."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        binary = result.binary_manifest_path.read_bytes()
        assert len(binary) == TOTAL_SIZE

    def test_PIPE_binary_manifest_has_correct_magic(self, fake_px4, temp_keys, tmp_path):
        """Binary manifest starts with INOFLY03 magic (v3 RSA-2048)."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        binary = result.binary_manifest_path.read_bytes()
        assert binary[:8] == b"INOFLY03"

    def test_PIPE_all_artifacts_independently_verifiable(self, fake_px4, temp_keys, tmp_path):
        """Each artifact can be verified independently after pipeline."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        # Verify signed bundle JSON
        assert verify_bundle(result.signed_bundle, public_key_path=public_key)

        # Verify .fwbundle
        assert verify_fwbundle(result.fwbundle_path, public_key_path=public_key)

        # Verify binary manifest
        binary = result.binary_manifest_path.read_bytes()
        assert verify_binary_manifest(binary, public_key_path=public_key)

    def test_PIPE_manifest_contains_correct_checksums(self, fake_px4, temp_keys, tmp_path):
        """Checksums in manifest are SHA-256 hex strings (64 chars)."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        assert len(result.manifest["code_checksum"]) == 64
        assert len(result.manifest["data_checksum"]) == 64
        assert result.manifest["algorithm"] == "SHA-256"

    def test_PIPE_version_override_propagates(self, fake_px4, temp_keys, tmp_path):
        """Explicit version string overrides the one in the .px4 file."""
        private_key, public_key = temp_keys
        output_dir = tmp_path / "release"

        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=output_dir,
            firmware_version="2.0.0-override",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        assert result.manifest["firmware_version"] == "2.0.0-override"

    def test_PIPE_missing_firmware_raises_error(self, temp_keys, tmp_path):
        """Pipeline fails clearly if firmware file doesn't exist."""
        private_key, public_key = temp_keys

        with pytest.raises(FileNotFoundError, match="Firmware not found"):
            run_pipeline(
                px4_path=tmp_path / "nonexistent.px4",
                output_dir=tmp_path / "release",
                private_key_path=private_key,
                public_key_path=public_key,
                verbose=False,
            )

    def test_PIPE_missing_private_key_raises_error(self, fake_px4, tmp_path):
        """Pipeline fails clearly if private key is missing."""
        with pytest.raises(FileNotFoundError, match="Private key not found"):
            run_pipeline(
                px4_path=fake_px4,
                output_dir=tmp_path / "release",
                private_key_path=tmp_path / "nonexistent.pem",
                public_key_path=tmp_path / "nonexistent_pub.pem",
                verbose=False,
            )

    def test_PIPE_pipeline_is_deterministic_checksums(self, fake_px4, temp_keys, tmp_path):
        """Running pipeline twice on same firmware produces same checksums."""
        private_key, public_key = temp_keys

        r1 = run_pipeline(
            px4_path=fake_px4,
            output_dir=tmp_path / "run1",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )
        r2 = run_pipeline(
            px4_path=fake_px4,
            output_dir=tmp_path / "run2",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )

        assert r1.manifest["code_checksum"] == r2.manifest["code_checksum"]
        assert r1.manifest["data_checksum"] == r2.manifest["data_checksum"]


def _build_toc_bin(code_size: int = 4096) -> bytes:
    """
    Minimal .bin mirroring the cubeorangeplus layout the verifying bootloader
    expects: a two-entry image TOC (BOOT + SIG1) at TOC_OFFSET_DEFAULT, with a
    256-byte ZERO signature placeholder after the BOOT region — exactly what a
    normally-built (unsigned) app fw carries.
    """
    load = APP_LOAD_ADDRESS_DEFAULT
    toc = TOC_OFFSET_DEFAULT
    total = code_size + RSA_2048_SIG_LEN
    b = bytearray(total)
    for i in range(toc):                       # pretend vectors + bootdelay
        b[i] = (i * 7 + 0x42) & 0xFF
    struct.pack_into("<II", b, toc, TOC_START_MAGIC, 1)
    struct.pack_into("<4sIII4BI", b, toc + 8,
                     b"BOOT", load, load + code_size, 0, 1, 0, 0, 0x05, 0)
    struct.pack_into("<4sIII4BI", b, toc + 8 + 24,
                     b"SIG1", load + code_size, load + code_size + RSA_2048_SIG_LEN,
                     0, 0, 0, 0, 0, 0)
    struct.pack_into("<I", b, toc + 8 + 24 + 24, TOC_END_MAGIC)
    for i in range(toc + 8 + 24 + 24 + 4, code_size):  # pretend code
        b[i] = (i * 13 + 0x99) & 0xFF
    # SIG region [code_size .. code_size+256) stays zero — the placeholder.
    return bytes(b)


def _wrap_px4(bin_data: bytes, tmp_path: Path, name: str = "hw_firmware.px4") -> Path:
    """Wrap a raw image into a .px4 the way px_mkfw does (zlib+base64)."""
    px4 = {
        "image": base64.b64encode(zlib.compress(bin_data, 9)).decode(),
        "image_size": len(bin_data),
        "board_id": 1063,
        "version": "1.0.0-test",
        "magic": "PX4FWv1",
    }
    p = tmp_path / name
    p.write_text(json.dumps(px4))
    return p


@pytest.fixture
def hw_px4(tmp_path):
    """A hardware-style .px4 carrying an image TOC + zero signature placeholder."""
    return _wrap_px4(_build_toc_bin(), tmp_path)


class TestBoot001PipelineSigning:
    """BOOT001: the pipeline must patch the app-fw image signature for hardware
    secure images, and must NOT touch SITL/non-secure images (no TOC)."""

    def _sig_region_verifies(self, px4_path: Path, public_key: Path) -> bool:
        """Decode a .px4, locate the SIG region via the TOC, and verify it."""
        img = zlib.decompress(base64.b64decode(json.loads(px4_path.read_text())["image"]))
        return verify_image(img, public_key.read_bytes())

    def test_BOOT001_pipeline_signs_hardware_image(self, hw_px4, temp_keys, tmp_path):
        """A .px4 with a TOC gets a valid RSA-PSS image signature, and the
        emitted firmware verifies under the manufacturer public key."""
        private_key, public_key = temp_keys
        result = run_pipeline(
            px4_path=hw_px4,
            output_dir=tmp_path / "release",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )
        assert result.bootloader_image_signed is True
        # The shipped firmware is the SIGNED image, and it verifies on-device-equivalently.
        assert self._sig_region_verifies(result.firmware_path, public_key)

    def test_BOOT001_unsigned_input_would_fail_verify(self, hw_px4, temp_keys):
        """Guard: the *input* placeholder image does NOT verify — proving the
        signing step is what makes the difference (not a vacuous assertion)."""
        _private_key, public_key = temp_keys
        assert self._sig_region_verifies(hw_px4, public_key) is False

    def test_BOOT001_pipeline_skips_sitl_image(self, fake_px4, temp_keys, tmp_path):
        """A SITL/non-secure .px4 (no TOC) is passed through unsigned, and the
        pipeline still completes — signing is correctly a no-op, not an error."""
        private_key, public_key = temp_keys
        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=tmp_path / "release",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )
        assert result.bootloader_image_signed is False
        assert result.all_verified is True

    def test_BOOT001_no_sign_flag_disables_signing(self, hw_px4, temp_keys, tmp_path):
        """--no-bootloader-sign (sign_bootloader_image=False) leaves even a
        hardware image unsigned, for out-of-band signing workflows."""
        private_key, public_key = temp_keys
        result = run_pipeline(
            px4_path=hw_px4,
            output_dir=tmp_path / "release",
            private_key_path=private_key,
            public_key_path=public_key,
            sign_bootloader_image=False,
            verbose=False,
        )
        assert result.bootloader_image_signed is False
