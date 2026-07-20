"""
tests/compliance/test_PRV001_export_manifest.py

Compliance tests for PRV001 — Binary manifest export for drone provisioning

Requirement: PRV001
  - Binary manifest must be exactly 373 bytes (v4 format with RSA-2048)
  - Must contain correct magic bytes "INOFLY04"
  - CRC32 must cover all fields except itself
  - RSA-PSS signature must be verifiable with manufacturer public key
  - Tampered fields must fail verification — INCLUDING created_at, which is
    inside the signed payload as of v4 (anti-rollback hardening: the FC's
    apply/promotion checks compare created_at, so it must be unforgeable)
  - Must reject oversized firmware version strings safely
"""

import binascii
import json
import struct
import zlib
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.provisioning.export_manifest import (
    export_binary_manifest,
    verify_binary_manifest,
    save_binary_manifest,
    _build_signable_payload,
    _compute_crc32,
    MAGIC, FORMAT_VERSION, HASH_LEN, SIG_MAX_LEN, VERSION_LEN, TOTAL_SIZE, STRUCT_FORMAT,
)
from tools.pki.keygen import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair(tmp_path):
    private_pem, public_pem = generate_keypair()
    private_path = tmp_path / "private.pem"
    public_path  = tmp_path / "public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return {"private": private_path, "public": public_path}


@pytest.fixture
def sample_bundle():
    """A realistic signed bundle as produced by signer.sign_manifest()."""
    return {
        "manifest": {
            "algorithm": "SHA-256",
            "firmware_version": "1.14.0-test",
            "source_file": "test_firmware.px4",
            "board_id": 50,
            "git_hash": "abc123",
            "code_checksum": "a" * 64,
            "data_checksum": "b" * 64,
            "generated_at": "2026-01-01T00:00:00+00:00",
        },
        "signature": "fakesignaturebase64==",
        "signed_at": "2026-01-01T00:00:01+00:00",
    }


@pytest.fixture
def binary_manifest(sample_bundle, keypair):
    return export_binary_manifest(sample_bundle, private_key_path=keypair["private"])


# ---------------------------------------------------------------------------
# PRV001 — Binary format tests
# ---------------------------------------------------------------------------

class TestPRV001_BinaryFormat:

    def test_PRV001_output_is_exactly_373_bytes(self, binary_manifest):
        assert len(binary_manifest) == TOTAL_SIZE
        assert len(binary_manifest) == 373

    def test_PRV001_starts_with_magic_bytes(self, binary_manifest):
        assert binary_manifest[:8] == MAGIC

    def test_PRV001_format_version_is_4(self, binary_manifest):
        assert binary_manifest[8] == FORMAT_VERSION
        assert binary_manifest[8] == 4

    def test_PRV001_code_hash_is_at_correct_offset(self, sample_bundle, binary_manifest):
        """code_hash starts at byte 9 and is 32 bytes."""
        expected = binascii.unhexlify(sample_bundle["manifest"]["code_checksum"])
        stored = binary_manifest[9:41]
        assert stored == expected

    def test_PRV001_data_hash_is_at_correct_offset(self, sample_bundle, binary_manifest):
        """data_hash starts at byte 41 and is 32 bytes."""
        expected = binascii.unhexlify(sample_bundle["manifest"]["data_checksum"])
        stored = binary_manifest[41:73]
        assert stored == expected

    def test_PRV001_signature_is_256_bytes(self, binary_manifest):
        """RSA-2048 signature at offset 73, always exactly 256 bytes."""
        sig_bytes = binary_manifest[73:73 + SIG_MAX_LEN]
        assert len(sig_bytes) == 256
        # sig_len field (uint16 at offset 329) should be 256
        sig_len = struct.unpack_from("<H", binary_manifest, 73 + SIG_MAX_LEN)[0]
        assert sig_len == 256

    def test_PRV001_board_id_is_stored_correctly(self, sample_bundle, keypair):
        """board_id stored as little-endian uint16 at offset 331."""
        bundle = dict(sample_bundle)
        bundle["manifest"] = dict(sample_bundle["manifest"])
        bundle["manifest"]["board_id"] = 50
        binary = export_binary_manifest(bundle, private_key_path=keypair["private"])
        # board_id offset: 8 + 1 + 32 + 32 + 256 + 2 = 331
        board_id_bytes = binary[331:333]
        assert struct.unpack("<H", board_id_bytes)[0] == 50

    def test_PRV001_version_string_is_null_terminated(self, binary_manifest):
        """Version field must be null-terminated within the 32-byte buffer."""
        # version offset: 331 + 2 = 333
        version_field = binary_manifest[333:333 + VERSION_LEN]
        assert b"\x00" in version_field

    def test_PRV001_struct_format_size_matches_total(self):
        """Struct pack format must match expected total size."""
        assert struct.calcsize(STRUCT_FORMAT) == TOTAL_SIZE


# ---------------------------------------------------------------------------
# PRV001 — CRC tests
# ---------------------------------------------------------------------------

class TestPRV001_CRC:

    def test_PRV001_crc32_is_at_last_4_bytes(self, binary_manifest):
        """CRC32 field is the last 4 bytes of the struct."""
        stored_crc   = struct.unpack_from("<I", binary_manifest, TOTAL_SIZE - 4)[0]
        computed_crc = _compute_crc32(binary_manifest[:TOTAL_SIZE - 4])
        assert stored_crc == computed_crc

    def test_PRV001_single_byte_flip_changes_crc(self, binary_manifest):
        """Any single byte change in the manifest should change the CRC."""
        tampered = bytearray(binary_manifest)
        tampered[10] ^= 0xFF  # flip a byte in code_hash area
        stored_crc   = struct.unpack_from("<I", bytes(tampered), TOTAL_SIZE - 4)[0]
        computed_crc = _compute_crc32(bytes(tampered)[:TOTAL_SIZE - 4])
        assert stored_crc != computed_crc

    def test_PRV001_crc_covers_all_fields_except_itself(self, binary_manifest):
        """CRC must be over bytes 0 to TOTAL_SIZE-5, not including last 4 bytes."""
        expected_crc = zlib.crc32(binary_manifest[:TOTAL_SIZE - 4]) & 0xFFFFFFFF
        stored_crc   = struct.unpack_from("<I", binary_manifest, TOTAL_SIZE - 4)[0]
        assert stored_crc == expected_crc


# ---------------------------------------------------------------------------
# PRV001 — Signature tests
# ---------------------------------------------------------------------------

class TestPRV001_Signature:

    def test_PRV001_valid_manifest_verifies_successfully(self, binary_manifest, keypair):
        result = verify_binary_manifest(binary_manifest, keypair["public"])
        assert result is True

    def test_PRV001_wrong_public_key_fails_verification(self, binary_manifest, tmp_path):
        _, other_public_pem = generate_keypair()
        other_key = tmp_path / "other.pem"
        other_key.write_bytes(other_public_pem)
        result = verify_binary_manifest(binary_manifest, other_key)
        assert result is False

    def test_PRV001_tampered_code_hash_fails_verification(self, binary_manifest, keypair):
        """Flipping a byte in code_hash must fail signature verification."""
        tampered = bytearray(binary_manifest)
        tampered[9] ^= 0xFF  # flip first byte of code_hash

        # Fix the CRC so only signature fails (not CRC)
        new_crc = _compute_crc32(bytes(tampered)[:TOTAL_SIZE - 4])
        struct.pack_into("<I", tampered, TOTAL_SIZE - 4, new_crc)

        result = verify_binary_manifest(bytes(tampered), keypair["public"])
        assert result is False

    def test_PRV001_tampered_data_hash_fails_verification(self, binary_manifest, keypair):
        """Flipping a byte in data_hash must fail signature verification."""
        tampered = bytearray(binary_manifest)
        tampered[41] ^= 0xFF  # flip first byte of data_hash

        new_crc = _compute_crc32(bytes(tampered)[:TOTAL_SIZE - 4])
        struct.pack_into("<I", tampered, TOTAL_SIZE - 4, new_crc)

        result = verify_binary_manifest(bytes(tampered), keypair["public"])
        assert result is False

    def test_PRV001_tampered_created_at_fails_verification(self, binary_manifest, keypair):
        """THE v4 gap-closure test: forward-dating created_at (CRC fixed up,
        as an attacker replaying an old signed manifest would) must now break
        the RSA signature. Under v3 this exact tamper VERIFIED SUCCESSFULLY,
        making the A-5 apply / A-6 promotion anti-rollback checks forgeable."""
        tampered = bytearray(binary_manifest)
        # created_at is the uint32 at offset 365 — bump it far into the future
        old_ts = struct.unpack_from("<I", tampered, 365)[0]
        struct.pack_into("<I", tampered, 365, old_ts + 10 * 365 * 24 * 3600)

        # Attacker can always recompute the CRC — it's not a security boundary
        new_crc = _compute_crc32(bytes(tampered)[:TOTAL_SIZE - 4])
        struct.pack_into("<I", tampered, TOTAL_SIZE - 4, new_crc)

        result = verify_binary_manifest(bytes(tampered), keypair["public"])
        assert result is False

    def test_PRV001_corrupted_crc_fails_before_signature_check(self, binary_manifest, keypair):
        """Bad CRC should fail immediately — no need to check signature."""
        tampered = bytearray(binary_manifest)
        tampered[TOTAL_SIZE - 3] ^= 0xFF  # flip a byte in CRC field
        result = verify_binary_manifest(bytes(tampered), keypair["public"])
        assert result is False

    def test_PRV001_wrong_size_fails_verification(self, keypair):
        result = verify_binary_manifest(b"\x00" * 100, keypair["public"])
        assert result is False

    def test_PRV001_wrong_magic_fails_verification(self, binary_manifest, keypair):
        """Wrong magic bytes mean this is not our manifest format."""
        tampered = bytearray(binary_manifest)
        tampered[:8] = b"WRONGMAG"
        new_crc = _compute_crc32(bytes(tampered)[:TOTAL_SIZE - 4])
        struct.pack_into("<I", tampered, TOTAL_SIZE - 4, new_crc)
        result = verify_binary_manifest(bytes(tampered), keypair["public"])
        assert result is False


# ---------------------------------------------------------------------------
# PRV001 — Signable payload tests
# ---------------------------------------------------------------------------

class TestPRV001_SignablePayload:

    def test_PRV001_signable_payload_is_102_bytes(self):
        """v4 payload: 98 v3 bytes + created_at_le[4]."""
        payload = _build_signable_payload(b"\xaa" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        assert len(payload) == 102

    def test_PRV001_signable_payload_is_deterministic(self):
        p1 = _build_signable_payload(b"\xaa" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        p2 = _build_signable_payload(b"\xaa" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        assert p1 == p2

    def test_PRV001_different_code_hash_changes_payload(self):
        p1 = _build_signable_payload(b"\x00" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        p2 = _build_signable_payload(b"\xff" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        assert p1 != p2

    def test_PRV001_different_created_at_changes_payload(self):
        """v4: the timestamp is part of what gets signed."""
        p1 = _build_signable_payload(b"\xaa" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225600)
        p2 = _build_signable_payload(b"\xaa" * 32, b"\xbb" * 32, 50, "1.14.0", 1767225601)
        assert p1 != p2

    def test_PRV001_long_version_is_truncated_safely(self, keypair):
        """A version string longer than 31 chars must not crash or overflow."""
        bundle = {
            "manifest": {
                "firmware_version": "v" * 100,  # way too long
                "board_id": 50,
                "code_checksum": "a" * 64,
                "data_checksum": "b" * 64,
                "generated_at": "2026-01-01T00:00:00+00:00",
            },
            "signature": "fake",
            "signed_at": "2026-01-01T00:00:00+00:00",
        }
        binary = export_binary_manifest(bundle, private_key_path=keypair["private"])
        assert len(binary) == TOTAL_SIZE


# ---------------------------------------------------------------------------
# PRV001 — Save tests
# ---------------------------------------------------------------------------

class TestPRV001_Save:

    def test_PRV001_save_writes_correct_bytes(self, binary_manifest, tmp_path):
        output = tmp_path / "manifest.bin"
        save_binary_manifest(binary_manifest, output)
        assert output.read_bytes() == binary_manifest

    def test_PRV001_save_creates_parent_dirs(self, binary_manifest, tmp_path):
        output = tmp_path / "deep" / "nested" / "manifest.bin"
        save_binary_manifest(binary_manifest, output)
        assert output.exists()
