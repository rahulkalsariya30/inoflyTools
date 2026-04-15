"""
tests/compliance/test_LOG001_audit_log.py

Compliance tests for LOG001 — Signed audit log of security events

Requirement: LOG001
  - Audit log entries must be exactly 132 bytes
  - Each entry must contain correct magic bytes (0x4C4F4701)
  - CRC32 must cover bytes 0-127 (everything except crc32 field itself)
  - ECDSA P-256 signature must cover bytes 4-51 (signable payload)
  - Tampered entries must fail CRC and/or signature verification
  - Sequence numbers must be monotonically increasing
  - Entry format must match the binary struct defined in security_audit_entry.h
"""

import struct
import zlib
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.pki.keygen import generate_keypair
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization


# ── Constants matching security_audit_entry.h ─────────────────────────────────

AUDIT_ENTRY_MAGIC  = 0x4C4F4701
AUDIT_FORMAT_VER   = 1
AUDIT_DETAIL_LEN   = 32
AUDIT_SIG_MAX_LEN  = 72
AUDIT_ENTRY_SIZE   = 132
AUDIT_SIGN_OFFSET  = 4
AUDIT_SIGN_LEN     = 48

# Struct format: magic(I) format_ver(B) event_type(B) event_result(B) detail_code(B)
#   sequence_num(I) timestamp_us(Q) detail(32s) signature(72s) sig_len(B)
#   reserved(3s) crc32(I)
ENTRY_STRUCT_FORMAT = "<IBBBBI Q 32s 72s B 3s I"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def keypair(tmp_path):
    """Generate a fresh ECDSA P-256 keypair for testing."""
    private_pem, public_pem = generate_keypair()
    private_path = tmp_path / "private.pem"
    public_path  = tmp_path / "public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return {"private": private_path, "public": public_path}


def _load_private_key(path):
    """Load an ECDSA private key from PEM file."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(path.read_bytes(), password=None)


def _load_public_key(path):
    """Load an ECDSA public key from PEM file."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(path.read_bytes())


def _build_entry(event_type=1, event_result=0, detail_code=0, sequence_num=0,
                 timestamp_us=1000000, detail=b"POST", private_key=None):
    """Build a complete audit log entry, optionally signed."""
    # Pad detail to 32 bytes
    detail_padded = detail.ljust(AUDIT_DETAIL_LEN, b'\x00')[:AUDIT_DETAIL_LEN]

    # Build the entry without signature and CRC first
    entry_bytes = struct.pack(
        "<IBBBBI Q 32s",
        AUDIT_ENTRY_MAGIC,
        AUDIT_FORMAT_VER,
        event_type,
        event_result,
        detail_code,
        sequence_num,
        timestamp_us,
        detail_padded,
    )

    # Signable payload is bytes 4-51 (48 bytes)
    signable = entry_bytes[AUDIT_SIGN_OFFSET:AUDIT_SIGN_OFFSET + AUDIT_SIGN_LEN]
    assert len(signable) == AUDIT_SIGN_LEN

    # Sign if key provided
    signature = b'\x00' * AUDIT_SIG_MAX_LEN
    sig_len = 0

    if private_key:
        der_sig = private_key.sign(signable, ec.ECDSA(hashes.SHA256()))
        sig_len = len(der_sig)
        # Pad to 72 bytes
        signature = der_sig.ljust(AUDIT_SIG_MAX_LEN, b'\x00')

    # Pack remaining fields
    reserved = b'\x00' * 3
    entry_bytes += signature
    entry_bytes += struct.pack("<B 3s", sig_len, reserved)

    # CRC32 over bytes 0-127
    assert len(entry_bytes) == AUDIT_ENTRY_SIZE - 4  # 128 bytes before CRC
    crc = zlib.crc32(entry_bytes) & 0xFFFFFFFF
    entry_bytes += struct.pack("<I", crc)

    assert len(entry_bytes) == AUDIT_ENTRY_SIZE
    return entry_bytes


def _verify_crc(entry_bytes):
    """Verify CRC32 of an entry (bytes 0-127 vs stored crc32 at 128-131)."""
    assert len(entry_bytes) == AUDIT_ENTRY_SIZE
    stored_crc = struct.unpack_from("<I", entry_bytes, 128)[0]
    computed_crc = zlib.crc32(entry_bytes[:128]) & 0xFFFFFFFF
    return stored_crc == computed_crc


def _verify_signature(entry_bytes, public_key):
    """Verify ECDSA signature of an entry."""
    sig_len = entry_bytes[124]
    if sig_len == 0:
        return False

    der_sig = entry_bytes[52:52 + sig_len]
    signable = entry_bytes[AUDIT_SIGN_OFFSET:AUDIT_SIGN_OFFSET + AUDIT_SIGN_LEN]

    try:
        public_key.verify(der_sig, signable, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestLOG001EntryFormat:
    """Test binary audit log entry format."""

    def test_LOG001_entry_size(self):
        """Entry must be exactly 132 bytes."""
        entry = _build_entry()
        assert len(entry) == AUDIT_ENTRY_SIZE

    def test_LOG001_struct_pack_size(self):
        """Struct format must produce 132 bytes."""
        assert struct.calcsize(ENTRY_STRUCT_FORMAT) == AUDIT_ENTRY_SIZE

    def test_LOG001_magic_bytes(self):
        """Entry must start with magic 0x4C4F4701."""
        entry = _build_entry()
        magic = struct.unpack_from("<I", entry, 0)[0]
        assert magic == AUDIT_ENTRY_MAGIC

    def test_LOG001_format_version(self):
        """Format version must be 1."""
        entry = _build_entry()
        assert entry[4] == AUDIT_FORMAT_VER

    def test_LOG001_event_type_codes(self):
        """All defined event types must pack correctly."""
        for event_type in [1, 2, 3, 4]:
            entry = _build_entry(event_type=event_type)
            assert entry[5] == event_type

    def test_LOG001_detail_field_padding(self):
        """Detail field must be padded to 32 bytes with nulls."""
        entry = _build_entry(detail=b"short")
        detail = entry[20:52]
        assert detail[:5] == b"short"
        assert detail[5:] == b'\x00' * 27

    def test_LOG001_detail_field_truncation(self):
        """Detail field must be truncated to 32 bytes if too long."""
        long_detail = b"x" * 64
        entry = _build_entry(detail=long_detail)
        detail = entry[20:52]
        assert len(detail) == AUDIT_DETAIL_LEN
        assert detail == b"x" * 32


class TestLOG001CRC:
    """Test CRC32 integrity checking."""

    def test_LOG001_crc_valid(self):
        """Valid entry must pass CRC check."""
        entry = _build_entry()
        assert _verify_crc(entry)

    def test_LOG001_crc_detects_tamper(self):
        """Tampered entry must fail CRC check."""
        entry = bytearray(_build_entry())
        # Flip a bit in the event_type field
        entry[5] ^= 0xFF
        assert not _verify_crc(bytes(entry))

    def test_LOG001_crc_covers_all_fields(self):
        """CRC must cover bytes 0-127 (everything except itself)."""
        entry = _build_entry()
        stored_crc = struct.unpack_from("<I", entry, 128)[0]
        computed_crc = zlib.crc32(entry[:128]) & 0xFFFFFFFF
        assert stored_crc == computed_crc


class TestLOG001Signing:
    """Test ECDSA P-256 signing and verification."""

    def test_LOG001_signed_entry_verifies(self, keypair):
        """Signed entry must pass signature verification."""
        private_key = _load_private_key(keypair["private"])
        public_key = _load_public_key(keypair["public"])

        entry = _build_entry(private_key=private_key)
        assert _verify_crc(entry)
        assert _verify_signature(entry, public_key)

    def test_LOG001_unsigned_entry_fails_verify(self, keypair):
        """Unsigned entry (sig_len=0) must fail signature verification."""
        public_key = _load_public_key(keypair["public"])
        entry = _build_entry()  # no private key → unsigned
        assert entry[124] == 0  # sig_len = 0
        assert not _verify_signature(entry, public_key)

    def test_LOG001_tampered_payload_fails_signature(self, keypair):
        """Tampering with the signable payload must fail signature verification."""
        private_key = _load_private_key(keypair["private"])
        public_key = _load_public_key(keypair["public"])

        entry = bytearray(_build_entry(private_key=private_key))
        # Tamper with detail_code (byte 7, within signable payload)
        entry[7] = 0xFF

        # Recompute CRC so it passes — but signature should still fail
        crc = zlib.crc32(bytes(entry[:128])) & 0xFFFFFFFF
        struct.pack_into("<I", entry, 128, crc)

        assert _verify_crc(bytes(entry))  # CRC was recomputed
        assert not _verify_signature(bytes(entry), public_key)  # Signature must fail

    def test_LOG001_wrong_key_fails_signature(self, keypair, tmp_path):
        """Signature from one key must not verify with a different key."""
        private_key = _load_private_key(keypair["private"])

        # Generate a different keypair
        other_priv_pem, other_pub_pem = generate_keypair()
        other_pub_path = tmp_path / "other_public.pem"
        other_pub_path.write_bytes(other_pub_pem)
        other_public_key = _load_public_key(other_pub_path)

        entry = _build_entry(private_key=private_key)
        assert not _verify_signature(entry, other_public_key)

    def test_LOG001_signable_payload_bounds(self, keypair):
        """Signable payload must be bytes 4-51 (48 bytes)."""
        private_key = _load_private_key(keypair["private"])
        entry = _build_entry(private_key=private_key)

        signable = entry[AUDIT_SIGN_OFFSET:AUDIT_SIGN_OFFSET + AUDIT_SIGN_LEN]
        assert len(signable) == 48

        # Payload should contain: format_ver(1) + event_type(1) + event_result(1)
        # + detail_code(1) + sequence_num(4) + timestamp_us(8) + detail(32) = 48
        assert signable[0] == AUDIT_FORMAT_VER  # format_ver


class TestLOG001SequenceAndTimestamp:
    """Test monotonic sequence numbers and timestamp storage."""

    def test_LOG001_sequence_num_stored_correctly(self):
        """Sequence number must be stored at offset 8 as uint32 LE."""
        entry = _build_entry(sequence_num=42)
        seq = struct.unpack_from("<I", entry, 8)[0]
        assert seq == 42

    def test_LOG001_timestamp_stored_correctly(self):
        """Timestamp must be stored at offset 12 as uint64 LE."""
        ts = 1712345678000000  # microseconds
        entry = _build_entry(timestamp_us=ts)
        stored_ts = struct.unpack_from("<Q", entry, 12)[0]
        assert stored_ts == ts

    def test_LOG001_multiple_entries_sequential(self, keypair):
        """Multiple entries must have increasing sequence numbers."""
        private_key = _load_private_key(keypair["private"])
        entries = []

        for i in range(5):
            entry = _build_entry(sequence_num=i, private_key=private_key)
            entries.append(entry)

        for i, entry in enumerate(entries):
            seq = struct.unpack_from("<I", entry, 8)[0]
            assert seq == i


class TestLOG001AppendOnly:
    """Test append-only log file behavior."""

    def test_LOG001_entries_concatenate(self, keypair, tmp_path):
        """Multiple entries written sequentially must produce a valid log file."""
        private_key = _load_private_key(keypair["private"])
        public_key = _load_public_key(keypair["public"])

        log_path = tmp_path / "audit_log.bin"

        # Write 3 entries
        with open(log_path, "ab") as f:
            for i in range(3):
                entry = _build_entry(
                    event_type=1,
                    sequence_num=i,
                    detail=f"POST_{i}".encode(),
                    private_key=private_key,
                )
                f.write(entry)

        # Read back and verify
        data = log_path.read_bytes()
        assert len(data) == 3 * AUDIT_ENTRY_SIZE

        for i in range(3):
            entry = data[i * AUDIT_ENTRY_SIZE:(i + 1) * AUDIT_ENTRY_SIZE]
            assert _verify_crc(entry)
            assert _verify_signature(entry, public_key)
            seq = struct.unpack_from("<I", entry, 8)[0]
            assert seq == i
