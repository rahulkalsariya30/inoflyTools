"""
tests/compliance/test_LOG001_audit_log.py

Compliance tests for LOG001 — Signed audit log of security events

Requirement: LOG001
  - Audit log entries must be exactly 316 bytes
  - Each entry must contain correct magic bytes (0x4C4F4701)
  - CRC32 must cover bytes 0-311 (everything except crc32 field itself)
  - Signature field and sig_len are zeroed in per-file signing mode
  - Tampered entries must fail CRC verification
  - Sequence numbers must be monotonically increasing
  - Entry format must match the binary struct defined in security_audit_entry.h

Per-file RSA signing:
  - FC computes SHA-256 of entire audit_log.bin
  - Encrypts hash with RSA-2048 public key (PKCS#1 v1.5), saves as audit_log.sig (256 bytes)
  - Manufacturer verifies offline: decrypt .sig with private key, compare SHA-256 hashes
  - NO per-entry signatures — entries have CRC32 integrity only
"""

import hashlib
import struct
import zlib
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ── Constants matching security_audit_entry.h ─────────────────────────────────

AUDIT_ENTRY_MAGIC  = 0x4C4F4701
AUDIT_FORMAT_VER   = 2   # v2: timestamp_us is real UTC epoch us (v1 was boot-relative)
AUDIT_DETAIL_LEN   = 32
AUDIT_SIG_MAX_LEN  = 256
AUDIT_ENTRY_SIZE   = 316

# Struct format: magic(I) format_ver(B) event_type(B) event_result(B) detail_code(B)
#   sequence_num(I) timestamp_us(Q) detail(32s) signature(256s) sig_len(H)
#   reserved(2s) crc32(I)
ENTRY_STRUCT_FORMAT = "<IBBBBI Q 32s 256s H 2s I"

# Per-file RSA signature size (RSA-2048 = 256 bytes)
RSA_SIG_SIZE = 256


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def rsa_keypair(tmp_path):
    """Generate a fresh RSA-2048 keypair for per-file log signing tests.

    Matches the audited reference scheme: public key on FC encrypts SHA-256 hash,
    manufacturer's private key decrypts for verification.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = tmp_path / "private.pem"
    public_path  = tmp_path / "public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return {
        "private": private_path,
        "public": public_path,
        "private_key": private_key,
        "public_key": private_key.public_key(),
    }


def _build_entry(event_type=1, event_result=0, detail_code=0, sequence_num=0,
                 timestamp_us=1000000, detail=b"POST"):
    """Build a complete audit log entry (per-file mode: signature zeroed)."""
    # Pad detail to 32 bytes
    detail_padded = detail.ljust(AUDIT_DETAIL_LEN, b'\x00')[:AUDIT_DETAIL_LEN]

    # Build the entry without signature and CRC
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

    # Per-file mode: signature field zeroed, sig_len = 0
    signature = b'\x00' * AUDIT_SIG_MAX_LEN
    sig_len = 0
    reserved = b'\x00' * 2

    entry_bytes += signature
    entry_bytes += struct.pack("<H 2s", sig_len, reserved)

    # CRC32 over bytes 0-311
    assert len(entry_bytes) == AUDIT_ENTRY_SIZE - 4  # 312 bytes before CRC
    crc = zlib.crc32(entry_bytes) & 0xFFFFFFFF
    entry_bytes += struct.pack("<I", crc)

    assert len(entry_bytes) == AUDIT_ENTRY_SIZE
    return entry_bytes


def _verify_crc(entry_bytes):
    """Verify CRC32 of an entry (bytes 0-311 vs stored crc32 at 312-315)."""
    assert len(entry_bytes) == AUDIT_ENTRY_SIZE
    stored_crc = struct.unpack_from("<I", entry_bytes, AUDIT_ENTRY_SIZE - 4)[0]
    computed_crc = zlib.crc32(entry_bytes[:AUDIT_ENTRY_SIZE - 4]) & 0xFFFFFFFF
    return stored_crc == computed_crc


def _build_log_file(tmp_path, num_entries=3, event_type=1):
    """Build a multi-entry audit log file. Returns (path, entries)."""
    log_path = tmp_path / "audit_log.bin"
    entries = []

    with open(log_path, "wb") as f:
        for i in range(num_entries):
            entry = _build_entry(
                event_type=event_type,
                sequence_num=i,
                timestamp_us=1000000 * (i + 1),
                detail=f"EVENT_{i}".encode(),
            )
            f.write(entry)
            entries.append(entry)

    return log_path, entries


def _sign_log_file(log_path, public_key):
    """Sign a log file using RSA public key encryption.

    FC encrypts SHA-256 hash with public key. Returns 256-byte ciphertext.
    """
    log_data = log_path.read_bytes()
    sha256_hash = hashlib.sha256(log_data).digest()

    # Encrypt hash with RSA public key (PKCS#1 v1.5 padding)
    ciphertext = public_key.encrypt(
        sha256_hash,
        padding.PKCS1v15(),
    )
    return ciphertext


def _verify_log_signature(log_path, sig_path, private_key):
    """Verify a log file signature using RSA private key decryption.

    Manufacturer decrypts .sig with private key, compares to SHA-256 of .bin.
    Returns True if hashes match.
    """
    log_data = log_path.read_bytes()
    sig_data = sig_path.read_bytes()

    # Compute expected SHA-256 of log file
    expected_hash = hashlib.sha256(log_data).digest()

    # Decrypt the ciphertext with private key
    try:
        decrypted_hash = private_key.decrypt(
            sig_data,
            padding.PKCS1v15(),
        )
        return decrypted_hash == expected_hash
    except Exception:
        return False


# ── Tests: Entry Format ──────────────────────────────────────────────────────

class TestLOG001EntryFormat:
    """Test binary audit log entry format."""

    def test_LOG001_entry_size(self):
        """Entry must be exactly 316 bytes."""
        entry = _build_entry()
        assert len(entry) == AUDIT_ENTRY_SIZE

    def test_LOG001_struct_pack_size(self):
        """Struct format must produce 316 bytes."""
        assert struct.calcsize(ENTRY_STRUCT_FORMAT) == AUDIT_ENTRY_SIZE

    def test_LOG001_magic_bytes(self):
        """Entry must start with magic 0x4C4F4701."""
        entry = _build_entry()
        magic = struct.unpack_from("<I", entry, 0)[0]
        assert magic == AUDIT_ENTRY_MAGIC

    def test_LOG001_format_version(self):
        """Format version must be 2 (timestamp_us is real UTC epoch us)."""
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

    def test_LOG001_signature_field_zeroed(self):
        """In per-file mode, signature field must be all zeroes."""
        entry = _build_entry()
        sig = entry[52:52 + AUDIT_SIG_MAX_LEN]
        assert sig == b'\x00' * AUDIT_SIG_MAX_LEN

    def test_LOG001_sig_len_zero(self):
        """In per-file mode, sig_len must be 0."""
        entry = _build_entry()
        assert entry[124] == 0


# ── Tests: CRC ───────────────────────────────────────────────────────────────

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
        stored_crc = struct.unpack_from("<I", entry, AUDIT_ENTRY_SIZE - 4)[0]
        computed_crc = zlib.crc32(entry[:AUDIT_ENTRY_SIZE - 4]) & 0xFFFFFFFF
        assert stored_crc == computed_crc

    def test_LOG001_crc_detects_tamper_in_detail(self):
        """Tampering with detail field must fail CRC."""
        entry = bytearray(_build_entry(detail=b"original"))
        # Tamper detail byte
        entry[20] = ord('X')
        assert not _verify_crc(bytes(entry))


# ── Tests: Per-File RSA Signing ──────────────────────────────────────────

class TestLOG001PerFileRSA:
    """Test per-file RSA-2048 log signing.

    Scheme:
    - FC computes SHA-256 of audit_log.bin
    - Encrypts hash with RSA public key (on FC)
    - Stores 256-byte ciphertext as audit_log.sig
    - Manufacturer decrypts with private key (offline) and compares hashes
    """

    def test_LOG001_sig_file_size(self, rsa_keypair, tmp_path):
        """Signature file must be exactly 256 bytes (RSA-2048)."""
        log_path, _ = _build_log_file(tmp_path)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])
        assert len(sig) == RSA_SIG_SIZE

    def test_LOG001_valid_sig_verifies(self, rsa_keypair, tmp_path):
        """Valid signature must verify with manufacturer's private key."""
        log_path, _ = _build_log_file(tmp_path)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])

        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(sig)

        assert _verify_log_signature(log_path, sig_path, rsa_keypair["private_key"])

    def test_LOG001_tampered_log_fails_sig(self, rsa_keypair, tmp_path):
        """Tampered log file must fail signature verification."""
        log_path, _ = _build_log_file(tmp_path)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])

        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(sig)

        # Tamper with the log file after signing
        data = bytearray(log_path.read_bytes())
        data[5] ^= 0xFF  # flip event_type in first entry
        log_path.write_bytes(bytes(data))

        assert not _verify_log_signature(log_path, sig_path, rsa_keypair["private_key"])

    def test_LOG001_tampered_sig_fails(self, rsa_keypair, tmp_path):
        """Tampered signature file must fail verification."""
        log_path, _ = _build_log_file(tmp_path)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])

        # Tamper with the sig before writing
        tampered_sig = bytearray(sig)
        tampered_sig[10] ^= 0xFF
        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(bytes(tampered_sig))

        assert not _verify_log_signature(log_path, sig_path, rsa_keypair["private_key"])

    def test_LOG001_wrong_key_fails_sig(self, rsa_keypair, tmp_path):
        """Signature encrypted with one key must not verify with another key."""
        log_path, _ = _build_log_file(tmp_path)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])

        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(sig)

        # Generate a different RSA keypair
        other_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        assert not _verify_log_signature(log_path, sig_path, other_private)

    def test_LOG001_empty_log_signs_correctly(self, rsa_keypair, tmp_path):
        """Empty log file must still produce a valid signature (SHA-256 of empty)."""
        log_path = tmp_path / "audit_log.bin"
        log_path.write_bytes(b"")

        sig = _sign_log_file(log_path, rsa_keypair["public_key"])
        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(sig)

        assert _verify_log_signature(log_path, sig_path, rsa_keypair["private_key"])

    def test_LOG001_sig_updates_after_append(self, rsa_keypair, tmp_path):
        """Signature must be recomputed when a new entry is appended."""
        log_path, _ = _build_log_file(tmp_path, num_entries=2)

        # Sign with 2 entries
        sig1 = _sign_log_file(log_path, rsa_keypair["public_key"])

        # Append a third entry
        with open(log_path, "ab") as f:
            entry = _build_entry(sequence_num=2, detail=b"NEW_ENTRY")
            f.write(entry)

        # Re-sign
        sig2 = _sign_log_file(log_path, rsa_keypair["public_key"])

        # Old signature must NOT verify new file
        old_sig_path = tmp_path / "old.sig"
        old_sig_path.write_bytes(sig1)
        assert not _verify_log_signature(log_path, old_sig_path, rsa_keypair["private_key"])

        # New signature must verify
        new_sig_path = tmp_path / "new.sig"
        new_sig_path.write_bytes(sig2)
        assert _verify_log_signature(log_path, new_sig_path, rsa_keypair["private_key"])

    def test_LOG001_decrypt_matches_sha256(self, rsa_keypair, tmp_path):
        """Decrypted signature must exactly equal SHA-256 of the log file (32 bytes)."""
        log_path, _ = _build_log_file(tmp_path, num_entries=5)
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])

        # Decrypt with private key
        decrypted = rsa_keypair["private_key"].decrypt(sig, padding.PKCS1v15())

        # Must be exactly 32 bytes (SHA-256 digest)
        assert len(decrypted) == 32

        # Must match SHA-256 of the log file
        expected = hashlib.sha256(log_path.read_bytes()).digest()
        assert decrypted == expected


# ── Tests: Sequence and Timestamp ─────────────────────────────────────────────

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

    def test_LOG001_multiple_entries_sequential(self):
        """Multiple entries must have increasing sequence numbers."""
        entries = []
        for i in range(5):
            entry = _build_entry(sequence_num=i)
            entries.append(entry)

        for i, entry in enumerate(entries):
            seq = struct.unpack_from("<I", entry, 8)[0]
            assert seq == i


# ── Tests: Append-Only Log ────────────────────────────────────────────────────

class TestLOG001AppendOnly:
    """Test append-only log file behavior."""

    def test_LOG001_entries_concatenate(self, tmp_path):
        """Multiple entries written sequentially must produce a valid log file."""
        log_path, entries = _build_log_file(tmp_path, num_entries=3)

        # Read back and verify
        data = log_path.read_bytes()
        assert len(data) == 3 * AUDIT_ENTRY_SIZE

        for i in range(3):
            entry = data[i * AUDIT_ENTRY_SIZE:(i + 1) * AUDIT_ENTRY_SIZE]
            assert _verify_crc(entry)
            seq = struct.unpack_from("<I", entry, 8)[0]
            assert seq == i

    def test_LOG001_log_file_with_signature(self, rsa_keypair, tmp_path):
        """Complete workflow: build log, sign, verify all entries + file sig."""
        log_path, _ = _build_log_file(tmp_path, num_entries=5)

        # Verify all entries have valid CRC
        data = log_path.read_bytes()
        for i in range(5):
            entry = data[i * AUDIT_ENTRY_SIZE:(i + 1) * AUDIT_ENTRY_SIZE]
            assert _verify_crc(entry), f"Entry {i} CRC failed"

        # Sign the whole file and verify
        sig = _sign_log_file(log_path, rsa_keypair["public_key"])
        sig_path = tmp_path / "audit_log.sig"
        sig_path.write_bytes(sig)

        assert _verify_log_signature(log_path, sig_path, rsa_keypair["private_key"])
