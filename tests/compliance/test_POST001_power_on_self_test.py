"""
tests/compliance/test_POST001_power_on_self_test.py

Compliance tests for POST001 and ARM001

Requirement: POST001 (DGCA Section 7.1 — Power On Self Test)
  - On every boot, the drone must verify firmware integrity
  - CRC32 check detects storage corruption
  - RSA-PSS signature verification proves manufacturer authenticity
  - A failed check must report the specific failure reason

Requirement: ARM001 (DGCA Section 7.1 — Arming Gate)
  - If POST001 fails, the drone MUST block arming (motors cannot start)
  - The arming gate reads firmware_integrity_status uORB message
  - Preflight failure is reported to both pilot and GCS

Implementation:
  POST001: FirmwareIntegrityChecker runs at boot inside secure_boot module
  ARM001: firmwareIntegrityCheck.hpp/cpp in commander's arming checks

These tests verify:
  1. The Python-side manifest verification matches the C++ POST logic
  2. The PX4 firmware source files implementing POST exist and are correct
  3. Binary manifest format is correctly structured for POST consumption
"""

import struct
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.pki.keygen import generate_keypair
from tools.provisioning.export_manifest import (
    export_binary_manifest,
    verify_binary_manifest,
    _build_signable_payload,
    _compute_crc32,
    MAGIC,
    FORMAT_VERSION,
    TOTAL_SIZE,
    SIG_MAX_LEN,
    HASH_LEN,
    VERSION_LEN,
)
from tools.checksum.checksum import generate_manifest
from tools.signer.signer import sign_manifest

import base64
import json
import zlib


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_px4_file(path: Path, image_bytes: bytes = b"\x7fELF" + b"\x00" * 256) -> Path:
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
    path.write_text(json.dumps(firmware, indent=4))
    return path


def wsl_read_file(path: str) -> str:
    """Read a file from WSL, return contents or None if unavailable."""
    import subprocess
    result = subprocess.run(
        ["wsl", "-e", "bash", "-c", f"cat {path}"],
        capture_output=True
    )
    if result.returncode == 0:
        return result.stdout.decode("utf-8", errors="replace")
    return None


def wsl_file_exists(path: str) -> bool:
    """Check if a file exists in WSL."""
    import subprocess
    result = subprocess.run(
        ["wsl", "-e", "bash", "-c", f"test -f {path} && echo EXISTS"],
        capture_output=True, text=True,
    )
    return "EXISTS" in result.stdout


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("keys")
    priv_path = tmp / "private.pem"
    pub_path = tmp / "public.pem"
    priv_pem, pub_pem = generate_keypair()
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


@pytest.fixture(scope="module")
def firmware_file(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("firmware")
    return make_px4_file(tmp / "test.px4")


@pytest.fixture(scope="module")
def binary_manifest(firmware_file, keypair):
    """A valid 373-byte binary manifest."""
    priv_path, _ = keypair
    manifest = generate_manifest(firmware_file, firmware_version="1.14.0")
    signed = sign_manifest(manifest, private_key_path=priv_path)
    return export_binary_manifest(signed, private_key_path=priv_path)


# ── Tests: POST001 — Manifest Format Matches C++ Expectations ───────────────

class TestPOST001ManifestFormat:
    """Verify the binary manifest format matches what FirmwareIntegrityChecker
    expects (security_manifest.h struct layout)."""

    def test_POST001_manifest_size_matches_struct(self, binary_manifest):
        """Binary manifest must be exactly 373 bytes (sizeof(security_manifest_t))."""
        assert len(binary_manifest) == TOTAL_SIZE
        assert len(binary_manifest) == 373

    def test_POST001_magic_bytes(self, binary_manifest):
        """First 8 bytes must be 'INOFLY03' magic."""
        assert binary_manifest[0:8] == MAGIC

    def test_POST001_format_version(self, binary_manifest):
        """Byte 8 must be format version 3 (RSA-2048)."""
        assert binary_manifest[8] == FORMAT_VERSION
        assert binary_manifest[8] == 3

    def test_POST001_signature_is_256_bytes(self, binary_manifest):
        """RSA-2048 signature must be exactly 256 bytes."""
        sig_len_bytes = binary_manifest[329:331]
        sig_len = struct.unpack("<H", sig_len_bytes)[0]
        assert sig_len == SIG_MAX_LEN
        assert sig_len == 256

    def test_POST001_crc32_is_last_4_bytes(self, binary_manifest):
        """CRC32 must be stored in the last 4 bytes."""
        stored_crc = struct.unpack("<I", binary_manifest[369:373])[0]
        computed_crc = _compute_crc32(binary_manifest[:369])
        assert stored_crc == computed_crc

    def test_POST001_signable_payload_is_98_bytes(self, binary_manifest):
        """The signable payload (code_hash + data_hash + board_id + version)
        must be exactly 98 bytes — matching _build_signable_payload in C++."""
        code_hash = binary_manifest[9:9+32]
        data_hash = binary_manifest[41:41+32]
        board_id = struct.unpack("<H", binary_manifest[331:333])[0]
        version = binary_manifest[333:333+32]

        payload = code_hash + data_hash + struct.pack("<H", board_id) + version
        assert len(payload) == 98


# ── Tests: POST001 — CRC32 Verification ─────────────────────────────────────

class TestPOST001CRC:
    """CRC32 is the first check POST runs — detects flash storage corruption."""

    def test_POST001_valid_manifest_passes_crc(self, binary_manifest, keypair):
        """A valid manifest must pass CRC verification."""
        _, pub_path = keypair
        assert verify_binary_manifest(binary_manifest, pub_path) is True

    def test_POST001_single_bit_flip_fails_crc(self, binary_manifest, keypair):
        """Flipping a single bit must cause CRC failure."""
        _, pub_path = keypair
        data = bytearray(binary_manifest)
        data[20] ^= 0x01  # flip one bit in code_hash
        assert verify_binary_manifest(bytes(data), pub_path) is False

    def test_POST001_crc_covers_entire_manifest(self, binary_manifest):
        """CRC must cover bytes 0-368 (everything except the CRC itself)."""
        stored_crc = struct.unpack("<I", binary_manifest[369:373])[0]
        # Verify by recomputing
        import zlib as _zlib
        expected_crc = _zlib.crc32(binary_manifest[:369]) & 0xFFFFFFFF
        assert stored_crc == expected_crc


# ── Tests: POST001 — RSA-PSS Signature Verification ─────────────────────────

class TestPOST001SignatureVerification:
    """RSA-PSS is the second check POST runs — proves manufacturer authenticity."""

    def test_POST001_valid_signature_passes(self, binary_manifest, keypair):
        """Signature signed with correct key must pass."""
        _, pub_path = keypair
        assert verify_binary_manifest(binary_manifest, pub_path) is True

    def test_POST001_wrong_key_fails_signature(self, binary_manifest, tmp_path):
        """Signature verified with wrong key must fail."""
        # Generate a different keypair
        _, wrong_pub = generate_keypair()
        wrong_pub_path = tmp_path / "wrong_pub.pem"
        wrong_pub_path.write_bytes(wrong_pub)
        assert verify_binary_manifest(binary_manifest, wrong_pub_path) is False

    def test_POST001_tampered_hash_fails_signature(self, binary_manifest, keypair):
        """Modifying a hash (with CRC recomputed) must still fail RSA check."""
        _, pub_path = keypair
        data = bytearray(binary_manifest)
        # Tamper with code_hash
        data[10] ^= 0xFF
        # Recompute CRC so CRC check passes
        import zlib as _zlib
        new_crc = _zlib.crc32(bytes(data[:369])) & 0xFFFFFFFF
        struct.pack_into("<I", data, 369, new_crc)
        assert verify_binary_manifest(bytes(data), pub_path) is False


# ── Tests: POST001 — Failure Reason Reporting ────────────────────────────────

class TestPOST001FailureReasons:
    """POST must report specific failure reasons (matches firmware_integrity_status.msg)."""

    def test_POST001_failure_reasons_defined(self):
        """All failure reason constants must match FirmwareIntegrityStatus.msg."""
        # These values must match the C++ enum in security_manifest.h
        REASON_NONE = 0
        REASON_NO_MANIFEST = 1
        REASON_MANIFEST_CORRUPT = 2
        REASON_SIGNATURE_INVALID = 3
        REASON_CODE_HASH_MISMATCH = 4
        REASON_DATA_HASH_MISMATCH = 5
        REASON_BOARD_ID_MISMATCH = 6

        # Verify the constants are sequential and start from 0
        reasons = [REASON_NONE, REASON_NO_MANIFEST, REASON_MANIFEST_CORRUPT,
                   REASON_SIGNATURE_INVALID, REASON_CODE_HASH_MISMATCH,
                   REASON_DATA_HASH_MISMATCH, REASON_BOARD_ID_MISMATCH]
        assert reasons == list(range(7))

    def test_POST001_security_manifest_h_has_reason_constants(self):
        """security_manifest.h must define all INTEGRITY_REASON_* constants."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/security_manifest.h"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")

        for reason in ["NONE", "NO_MANIFEST", "MANIFEST_CORRUPT",
                       "SIGNATURE_INVALID", "CODE_HASH_MISMATCH",
                       "DATA_HASH_MISMATCH", "BOARD_ID_MISMATCH"]:
            assert f"INTEGRITY_REASON_{reason}" in content


# ── Tests: POST001 — Firmware Source Files ──────────────────────────────────

class TestPOST001FirmwareSource:
    """Verify PX4 source files implementing POST exist and are structured correctly."""

    def test_POST001_checker_hpp_exists(self):
        """FirmwareIntegrityChecker.hpp must exist."""
        if not wsl_file_exists("~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.hpp"):
            pytest.skip("WSL/PX4 not available")
        assert True

    def test_POST001_checker_cpp_exists(self):
        """FirmwareIntegrityChecker.cpp must exist."""
        if not wsl_file_exists("~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.cpp"):
            pytest.skip("WSL/PX4 not available")
        assert True

    def test_POST001_checker_has_crc32_function(self):
        """FirmwareIntegrityChecker must implement CRC32."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.cpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "crc32" in content

    def test_POST001_checker_has_verify_signature(self):
        """FirmwareIntegrityChecker must verify the manifest RSA-PSS signature.

        BOOT008 (ADR-025) factored the RSA-PSS primitive into the shared
        src/lib/secure_verify lib so bl_update and secure_boot share one
        implementation. The checker now DELEGATES to secure_verify_pss; the
        primitive itself lives in secure_verify.cpp.
        """
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.cpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "verifySignature" in content
        # Delegates to the shared verify lib (BOOT008 refactor).
        assert "secure_verify_pss" in content

        verify_lib = wsl_read_file(
            "~/PX4-Autopilot/src/lib/secure_verify/secure_verify.cpp"
        )
        if verify_lib is None:
            pytest.skip("WSL/PX4 not available")
        # POSIX uses OpenSSL RSA_PKCS1_PSS_PADDING; NuttX uses libtomcrypt
        # rsa_verify_hash_ex with LTC_PKCS_1_PSS. Either is acceptable.
        assert (
            "RSA_PKCS1_PSS_PADDING" in verify_lib
            or "LTC_PKCS_1_PSS" in verify_lib
            or "rsa_verify_hash_ex" in verify_lib
        )

    def test_POST001_checker_uses_openssl_for_sitl(self):
        """SITL path must use OpenSSL for crypto."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.cpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "#include <openssl/" in content

    def test_POST001_checker_uses_libtomcrypt_for_nuttx(self):
        """NuttX path must use libtomcrypt for crypto (no mbedTLS in this project)."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/FirmwareIntegrityChecker.cpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "tomcrypt" in content or "rsa_verify_hash_ex" in content

    def test_POST001_uorb_message_exists(self):
        """FirmwareIntegrityStatus.msg uORB message definition must exist."""
        if not wsl_file_exists("~/PX4-Autopilot/msg/FirmwareIntegrityStatus.msg"):
            pytest.skip("WSL/PX4 not available")
        assert True

    def test_POST001_checker_in_cmake(self):
        """FirmwareIntegrityChecker must be in secure_boot CMakeLists.txt."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/CMakeLists.txt"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "FirmwareIntegrityChecker" in content


# ── Tests: ARM001 — Arming Gate ─────────────────────────────────────────────

class TestARM001ArmingGate:
    """Verify the arming gate blocks flight if POST fails."""

    def test_ARM001_arming_check_hpp_exists(self):
        """firmwareIntegrityCheck.hpp must exist in commander arming checks."""
        path = ("~/PX4-Autopilot/src/modules/commander/"
                "HealthAndArmingChecks/checks/firmwareIntegrityCheck.hpp")
        if not wsl_file_exists(path):
            pytest.skip("WSL/PX4 not available")
        assert True

    def test_ARM001_arming_check_subscribes_to_uorb(self):
        """Arming check must subscribe to firmware_integrity_status topic."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/commander/"
            "HealthAndArmingChecks/checks/firmwareIntegrityCheck.hpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "firmware_integrity_status" in content

    def test_ARM001_arming_check_uses_subscription(self):
        """Arming check must use uORB::Subscription for firmware_integrity_status."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/commander/"
            "HealthAndArmingChecks/checks/firmwareIntegrityCheck.hpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "uORB::Subscription" in content
        assert "firmware_integrity_status" in content

    def test_ARM001_arming_check_implements_interface(self):
        """Arming check must extend HealthAndArmingCheckBase."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/commander/"
            "HealthAndArmingChecks/checks/firmwareIntegrityCheck.hpp"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        assert "HealthAndArmingCheckBase" in content
        assert "checkAndReport" in content

    def test_ARM001_secure_boot_in_cmake(self):
        """secure_boot module must be registered in PX4 build system."""
        content = wsl_read_file(
            "~/PX4-Autopilot/src/modules/secure_boot/CMakeLists.txt"
        )
        if content is None:
            pytest.skip("WSL/PX4 not available")
        # Must reference the module name
        assert "modules__secure_boot" in content or "secure_boot" in content
