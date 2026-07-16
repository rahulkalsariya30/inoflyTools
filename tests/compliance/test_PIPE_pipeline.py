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


# ---------------------------------------------------------------------------
# ADR-023 (A-8): hardware pipeline emits the SD-staging artifacts
# ---------------------------------------------------------------------------

# The synthetic build lives with the ADR-023 suite (same directory).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ADR023_sd_update import build_synthetic_setup  # noqa: E402
from tools.bundler.bundler import UPDATE_IMAGE_NAME, UPDATE_META_NAME  # noqa: E402
from tools.checksum.checksum import extract_image_bytes  # noqa: E402
from tools.make_a10_fixtures import parse_staged_image, region_digests  # noqa: E402
import hashlib  # noqa: E402
import zipfile  # noqa: E402


class TestADR023PipelineSdArtifacts:
    """Hardware runs (ELF given) must emit loose UPDATE.BIN + UPDATE.MTA that
    are byte-identical to the bundle's artifacts and satisfy the device
    contract; SITL runs must emit neither."""

    @pytest.fixture
    def hw_run(self, temp_keys, tmp_path):
        private_key, public_key = temp_keys
        # The pipeline gets the UNSIGNED px4 — step 0 signs the image itself.
        setup = build_synthetic_setup(tmp_path, private_key.read_bytes())
        result = run_pipeline(
            px4_path=setup["unsigned_px4"],
            output_dir=tmp_path / "release",
            elf_path=setup["elf_path"],
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )
        return setup, result, public_key

    def test_ADR023_pipeline_emits_loose_sd_files(self, hw_run):
        _setup, result, _pub = hw_run
        assert result.update_image_path.name == "UPDATE.BIN"
        assert result.update_meta_path.name == "UPDATE.MTA"
        assert result.update_image_path.exists()
        assert result.update_meta_path.exists()

    def test_ADR023_loose_files_match_bundle_artifacts(self, hw_run):
        """The bench SD copies must be byte-identical to what QGC will later
        extract from the bundle — one artifact, two delivery paths."""
        _setup, result, _pub = hw_run
        with zipfile.ZipFile(result.fwbundle_path) as zf:
            assert result.update_image_path.read_bytes() == zf.read(UPDATE_IMAGE_NAME)
            assert result.update_meta_path.read_bytes() == zf.read(UPDATE_META_NAME)

    def test_ADR023_update_bin_is_the_step0_signed_image(self, hw_run):
        """UPDATE.BIN must be the exact image the shipped .px4 carries (the
        BOOT001-signed one), not a re-extraction of the unsigned input."""
        _setup, result, public_key = hw_run
        update_bin = result.update_image_path.read_bytes()
        assert update_bin == extract_image_bytes(result.firmware_path)
        assert verify_image(update_bin, public_key.read_bytes()) is True

    def test_ADR023_update_meta_satisfies_device_contract(self, hw_run):
        setup, result, _pub = hw_run
        meta = json.loads(result.update_meta_path.read_text())
        raw = result.update_image_path.read_bytes()
        signed_len, image_size = parse_staged_image(raw)
        assert meta["image_size"] == len(raw) == image_size
        assert meta["code_len"] + meta["data_len"] == signed_len
        assert meta["code_len"] == setup["code_len"]
        assert meta["data_len"] == setup["data_len"]
        assert meta["sha256"] == hashlib.sha256(raw).hexdigest()

    def test_ADR023_update_bin_binds_to_pipeline_manifest(self, hw_run):
        """Gate-1 preview: the emitted image's region digests must equal the
        manifest checksums the pipeline signed — the exact binding the device
        enforces before rebooting into the bootloader."""
        _setup, result, _pub = hw_run
        meta = json.loads(result.update_meta_path.read_text())
        code, data, _ = region_digests(result.update_image_path.read_bytes(),
                                       meta["code_len"], meta["data_len"])
        assert code == result.manifest["code_checksum"]
        assert data == result.manifest["data_checksum"]

    def test_ADR023_sitl_run_emits_no_sd_files(self, fake_px4, temp_keys, tmp_path):
        private_key, public_key = temp_keys
        result = run_pipeline(
            px4_path=fake_px4,
            output_dir=tmp_path / "release",
            private_key_path=private_key,
            public_key_path=public_key,
            verbose=False,
        )
        assert result.update_image_path is None
        assert result.update_meta_path is None
        assert not (tmp_path / "release" / "UPDATE.BIN").exists()
        assert not (tmp_path / "release" / "UPDATE.MTA").exists()

    def test_ADR023_bundle_update_manifest_signed_with_pipeline_key(self, hw_run):
        """Regression for the latent create_bundle key bug: the bundle's
        embedded update_manifest.bin must verify under the key the pipeline
        ran with, not whatever sits at the default key path."""
        _setup, result, public_key = hw_run
        from tools.provisioning.export_manifest import verify_binary_manifest
        with zipfile.ZipFile(result.fwbundle_path) as zf:
            binary = zf.read("update_manifest.bin")
        assert verify_binary_manifest(binary, public_key_path=public_key) is True
