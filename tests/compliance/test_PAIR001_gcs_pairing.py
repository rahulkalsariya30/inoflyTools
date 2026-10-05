"""
tests/compliance/test_PAIR001_gcs_pairing.py

Compliance tests for PAIR001 — GCS-FC pairing via MAVLink signing

Requirement: PAIR001 (Annexure E - communication requirement)
  - Each drone must have a unique MAVLink signing key
  - Signing key file must be exactly 40 bytes (32-byte key + 8-byte timestamp)
  - MAV_SIGN_CFG parameter must be locked to 1 (non-USB signing required)
  - Unauthorized GCS (without the matching key) cannot send commands
  - The signing mode cannot be disabled at runtime (protected by PAR001)

Implementation approach:
  Leverages PX4's built-in MAVLink v2 message signing and QGC's native
  signing support. Key derivation is SHA256(passphrase) on both sides
  so QGC's "Add Key" dialog (which only accepts a passphrase) interops
  with the drone-side provisioning.
"""

import struct
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.provisioning.provision_signing_key import (
    derive_signing_key,
    generate_initial_timestamp,
    build_key_file,
    save_key_file,
    SIGNING_KEY_SIZE,
    TIMESTAMP_SIZE,
    KEY_FILE_SIZE,
    MAVLINK_EPOCH,
    MIN_PASSPHRASE_LEN,
)


# ── PX4 source path (WSL) ────────────────────────────────────────────────────

PX4_ROOT = Path.home() / "PX4-Autopilot"
COMPLIANCE_PARAMS_H = PX4_ROOT / "src" / "modules" / "secure_boot" / "compliance_params.h"


# ── Test passphrases ────────────────────────────────────────────────────────
# Fixed passphrases let us assert deterministic key derivation.
# These are TEST values only — real deployments use unique per-drone secrets.
TEST_PASSPHRASE_1 = "test_passphrase_alpha_001"
TEST_PASSPHRASE_2 = "test_passphrase_bravo_002"


# ── Tests: Key derivation ────────────────────────────────────────────────────

class TestPAIR001KeyDerivation:
    """Test passphrase-based MAVLink signing key derivation."""

    def test_PAIR001_derived_key_is_32_bytes(self):
        """Derived key must be exactly 32 bytes (SHA256 output)."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        assert len(key) == SIGNING_KEY_SIZE

    def test_PAIR001_derived_key_is_bytes(self):
        """Derived key must be a bytes object."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        assert isinstance(key, bytes)

    def test_PAIR001_same_passphrase_same_key(self):
        """Identical passphrase MUST produce identical key — required for QGC interop."""
        k1 = derive_signing_key(TEST_PASSPHRASE_1)
        k2 = derive_signing_key(TEST_PASSPHRASE_1)
        assert k1 == k2

    def test_PAIR001_different_passphrases_different_keys(self):
        """Different passphrases MUST produce different keys (1:1 pairing property)."""
        k1 = derive_signing_key(TEST_PASSPHRASE_1)
        k2 = derive_signing_key(TEST_PASSPHRASE_2)
        assert k1 != k2

    def test_PAIR001_empty_passphrase_rejected(self):
        """Empty passphrase MUST be rejected — would yield a known-public hash."""
        with pytest.raises(ValueError):
            derive_signing_key("")

    def test_PAIR001_derived_key_matches_qgc_formula(self):
        """Derivation MUST be exactly SHA256(passphrase.utf8) — QGC does the same."""
        import hashlib
        expected = hashlib.sha256(TEST_PASSPHRASE_1.encode("utf-8")).digest()
        assert derive_signing_key(TEST_PASSPHRASE_1) == expected

    def test_PAIR001_key_not_all_zeros(self):
        """Derived key must not be all zeros for a non-degenerate passphrase."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        assert key != b'\x00' * SIGNING_KEY_SIZE

    def test_PAIR001_key_not_all_ones(self):
        """Derived key must not be all 0xFF for a non-degenerate passphrase."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        assert key != b'\xFF' * SIGNING_KEY_SIZE

    def test_PAIR001_min_passphrase_constant_sane(self):
        """Minimum passphrase length must be enforced and >= 8 chars."""
        assert MIN_PASSPHRASE_LEN >= 8


# ── Tests: Timestamp generation ──────────────────────────────────────────────

class TestPAIR001Timestamp:
    """Test MAVLink signing timestamp generation."""

    def test_PAIR001_timestamp_is_8_bytes(self):
        """Timestamp must be exactly 8 bytes."""
        ts = generate_initial_timestamp()
        assert len(ts) == TIMESTAMP_SIZE

    def test_PAIR001_timestamp_is_valid_uint64(self):
        """Timestamp must be a valid little-endian uint64."""
        ts = generate_initial_timestamp()
        value = struct.unpack("<Q", ts)[0]
        assert value > 0

    def test_PAIR001_timestamp_is_after_mavlink_epoch(self):
        """Timestamp must represent a time after 2015-01-01."""
        ts = generate_initial_timestamp()
        value = struct.unpack("<Q", ts)[0]
        assert value > 0

    def test_PAIR001_timestamp_is_reasonable(self):
        """Timestamp must represent a time between 2020 and 2030."""
        ts = generate_initial_timestamp()
        value = struct.unpack("<Q", ts)[0]
        unix_secs = (value * 10) / 1e6 + MAVLINK_EPOCH
        assert unix_secs > 1577836800  # 2020-01-01
        assert unix_secs < 1893456000  # 2030-01-01


# ── Tests: Key file format ───────────────────────────────────────────────────

class TestPAIR001KeyFile:
    """Test key file format matches PX4 MavlinkSignControl expectations."""

    def test_PAIR001_key_file_size(self):
        """Key file must be exactly 40 bytes (32 key + 8 timestamp)."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        key_file = build_key_file(key)
        assert len(key_file) == KEY_FILE_SIZE

    def test_PAIR001_key_file_contains_key(self):
        """First 32 bytes must be the derived key."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        key_file = build_key_file(key)
        assert key_file[:SIGNING_KEY_SIZE] == key

    def test_PAIR001_key_file_contains_timestamp(self):
        """Last 8 bytes must be the timestamp."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        ts = generate_initial_timestamp()
        key_file = build_key_file(key, ts)
        assert key_file[SIGNING_KEY_SIZE:] == ts

    def test_PAIR001_key_file_save_and_read(self, tmp_path):
        """Key file must be readable after saving."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        key_file = build_key_file(key)

        path = tmp_path / "mavlink" / "mavlink-signing-key.bin"
        save_key_file(key_file, path)

        assert path.exists()
        assert path.read_bytes() == key_file

    def test_PAIR001_key_file_creates_parent_dirs(self, tmp_path):
        """save_key_file must create parent directories if they don't exist."""
        key_file = build_key_file(derive_signing_key(TEST_PASSPHRASE_1))
        path = tmp_path / "deep" / "nested" / "mavlink" / "key.bin"
        save_key_file(key_file, path)
        assert path.exists()

    def test_PAIR001_different_drones_different_files(self, tmp_path):
        """Two drones with different passphrases must get different key files."""
        kf1 = build_key_file(derive_signing_key(TEST_PASSPHRASE_1))
        kf2 = build_key_file(derive_signing_key(TEST_PASSPHRASE_2))
        # Compare key portions only — timestamps may coincide if called in same us tick
        assert kf1[:SIGNING_KEY_SIZE] != kf2[:SIGNING_KEY_SIZE]


# ── Tests: Compliance parameter protection ───────────────────────────────────

class TestPAIR001ComplianceParam:
    """Test that MAV_SIGN_CFG is protected by PAR001."""

    @pytest.fixture
    def compliance_header(self):
        """Read compliance_params.cpp from PX4 source (WSL path).

        ADR-018 moved the COMPLIANCE_PARAMS[] table from the header into
        compliance_params.cpp so a single definition can be tagged into the
        .compliance_params flash section. The fixture name is kept as
        `compliance_header` for compatibility — it now returns the .cpp.
        """
        import subprocess
        result = subprocess.run(
            ["wsl", "-e", "bash", "-c",
             "cat ~/PX4-Autopilot/src/modules/secure_boot/compliance_params.cpp"],
            capture_output=True
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace")
        pytest.skip("Cannot read compliance_params.cpp from WSL")

    def test_PAIR001_compliance_param_exists(self, compliance_header):
        """MAV_SIGN_CFG must be listed in the compliance parameter table."""
        assert "MAV_SIGN_CFG" in compliance_header

    def test_PAIR001_compliance_param_value(self, compliance_header):
        """MAV_SIGN_CFG must be locked to value 1 (non-USB signing required)."""
        assert ".i = 1" in compliance_header or ".i=1" in compliance_header

    def test_PAIR001_compliance_param_is_int32(self, compliance_header):
        """MAV_SIGN_CFG must be declared as INT32 type."""
        lines = compliance_header.split("\n")
        found_param = False
        for i, line in enumerate(lines):
            if "MAV_SIGN_CFG" in line:
                found_param = True
                context = "\n".join(lines[max(0, i-1):i+3])
                assert "COMPLIANCE_TYPE_INT32" in context
                break
        assert found_param, "MAV_SIGN_CFG not found in compliance_params.cpp"

    def test_PAIR001_compliance_param_description(self, compliance_header):
        """MAV_SIGN_CFG entry must have a description."""
        lines = compliance_header.split("\n")
        for i, line in enumerate(lines):
            if "MAV_SIGN_CFG" in line:
                context = "\n".join(lines[max(0, i-1):i+3])
                assert "Signing" in context or "signing" in context
                return
        pytest.fail("MAV_SIGN_CFG not found")


# ── Tests: Security properties ───────────────────────────────────────────────

class TestPAIR001SecurityProperties:
    """Test security properties of the pairing mechanism."""

    def test_PAIR001_key_entropy(self):
        """Key derived from a non-trivial passphrase must have reasonable entropy."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        unique_bytes = len(set(key))
        assert unique_bytes >= 8, f"Only {unique_bytes} unique bytes — insufficient entropy"

    def test_PAIR001_key_file_not_truncated(self):
        """Build must produce exactly 40 bytes, not truncated."""
        key = derive_signing_key(TEST_PASSPHRASE_1)
        ts = generate_initial_timestamp()
        key_file = build_key_file(key, ts)
        assert len(key_file) == 40

    def test_PAIR001_constants_match_px4(self):
        """Our constants must match PX4's MavlinkSignControl expectations."""
        assert SIGNING_KEY_SIZE == 32
        assert TIMESTAMP_SIZE == 8
        assert KEY_FILE_SIZE == 40
        assert MAVLINK_EPOCH == 1420070400  # 2015-01-01T00:00:00Z
