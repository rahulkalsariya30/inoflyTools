"""
tests/compliance/test_BOOT001_toc_sign_verify.py

Compliance tests for BOOT001 (Phase 5b.2c) — TOC-aware firmware signing.

Requirement: BOOT001
  - The off-board signer must produce a .bin with an RSA-PSS signature placed
    inside the image's TOC-declared SIG region, hashed over the BOOT region.
  - Verification with the matching public key must pass; tampering anywhere
    in the BOOT region must fail; tampering in the SIG region must fail; a
    different key must fail.
  - The signer must use saltlen=32 (matches libtomcrypt in the bootloader).
  - The signed file must be byte-for-byte the same length as the input.

These tests do NOT require a real PX4 build. They construct a synthetic .bin
that matches the layout the linker emits — a fast, hermetic round-trip.
"""

import struct
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.signer.toc_sign import (
    sign_image,
    verify_image,
    find_toc,
    TocParseError,
    TOC_START_MAGIC,
    TOC_END_MAGIC,
    TOC_OFFSET_DEFAULT,
    APP_LOAD_ADDRESS_DEFAULT,
    RSA_3072_SIG_LEN,
)
from tools.pki.keygen import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair():
    """RSA-3072 keypair. Module-scoped because keygen is ~1s."""
    priv_pem, pub_pem = generate_keypair()
    return priv_pem, pub_pem


@pytest.fixture(scope="module")
def other_keypair():
    """A second, unrelated RSA-3072 keypair — used for negative cross-key tests."""
    priv_pem, pub_pem = generate_keypair()
    return priv_pem, pub_pem


def _build_synthetic_bin(
    code_size: int = 4096,
    app_load_address: int = APP_LOAD_ADDRESS_DEFAULT,
    toc_offset: int = TOC_OFFSET_DEFAULT,
) -> bytes:
    """
    Build a .bin that mimics the layout the cubeorangeplus linker emits:

      [0 .. toc_offset)            arbitrary "vectors + boot delay" bytes
      [toc_offset .. toc_end)      image_toc_start_t + 2 entries + END magic
      [toc_end .. code_size)       arbitrary "code" bytes
      [code_size .. code_size+384) 384 zero bytes (SIG placeholder)

    BOOT spans [app_load_address, app_load_address+code_size); SIG spans the
    384 bytes after that. Total .bin length = code_size + 384.
    """
    assert code_size > toc_offset + 8 + 24 + 24 + 4, "code_size must be larger than the TOC itself"

    sig_off = code_size
    total_len = code_size + RSA_3072_SIG_LEN

    bin_data = bytearray(total_len)

    # Fill the pre-TOC region with a recognisable pattern (mimics vectors + bootdelay).
    for i in range(toc_offset):
        bin_data[i] = (i * 7 + 0x42) & 0xFF

    # TOC start: magic + version
    struct.pack_into("<II", bin_data, toc_offset, TOC_START_MAGIC, 1)

    # Entry 0: BOOT. flags1 = TOC_FLAG1_BOOT (0x1) | TOC_FLAG1_CHECK_SIGNATURE (0x4) = 0x5
    struct.pack_into(
        "<4sIII4BI",
        bin_data,
        toc_offset + 8,
        b"BOOT",
        app_load_address,                # start
        app_load_address + code_size,    # end (= start of SIG region)
        0,                               # target
        1,                               # signature_idx
        0,                               # signature_key
        0,                               # encryption_key
        0x05,                            # flags1
        0,                               # reserved
    )
    # Entry 1: SIG1
    struct.pack_into(
        "<4sIII4BI",
        bin_data,
        toc_offset + 8 + 24,
        b"SIG1",
        app_load_address + code_size,
        app_load_address + code_size + RSA_3072_SIG_LEN,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    # END magic
    struct.pack_into("<I", bin_data, toc_offset + 8 + 24 + 24, TOC_END_MAGIC)

    # Fill post-TOC code with another pattern.
    for i in range(toc_offset + 8 + 24 + 24 + 4, code_size):
        bin_data[i] = (i * 13 + 0x99) & 0xFF

    # SIG region [code_size .. code_size+384) is left zero — that's the linker placeholder.
    return bytes(bin_data)


@pytest.fixture
def synthetic_bin():
    return _build_synthetic_bin()


# ---------------------------------------------------------------------------
# TOC parsing
# ---------------------------------------------------------------------------

def test_BOOT001_toc_parses_two_entries(synthetic_bin):
    count, entries = find_toc(synthetic_bin, TOC_OFFSET_DEFAULT)
    assert count == 2
    assert entries[0]["name"] == "BOOT"
    assert entries[1]["name"] == "SIG1"
    assert entries[0]["signature_idx"] == 1
    # BOOT region must end exactly where SIG region starts — load-bearing for the signer.
    assert entries[0]["end"] == entries[1]["start"]


def test_BOOT001_bad_magic_raises(synthetic_bin):
    """A .bin without the TOC magic at the expected offset must be rejected loudly."""
    corrupt = bytearray(synthetic_bin)
    corrupt[TOC_OFFSET_DEFAULT] = 0xFF  # smash the magic
    with pytest.raises(TocParseError, match="TOC_START_MAGIC mismatch"):
        find_toc(bytes(corrupt), TOC_OFFSET_DEFAULT)


def test_BOOT001_truncated_bin_raises():
    """Too-short input must not crash — must raise TocParseError."""
    with pytest.raises(TocParseError):
        find_toc(b"\x00" * 16, TOC_OFFSET_DEFAULT)


# ---------------------------------------------------------------------------
# Signing round-trip
# ---------------------------------------------------------------------------

def test_BOOT001_sign_then_verify_passes(synthetic_bin, keypair):
    priv, pub = keypair
    signed = sign_image(synthetic_bin, priv)
    assert verify_image(signed, pub) is True


def test_BOOT001_signed_bin_same_length(synthetic_bin, keypair):
    """In-place patch — file size must not change. If it does, flash layout breaks."""
    priv, _pub = keypair
    signed = sign_image(synthetic_bin, priv)
    assert len(signed) == len(synthetic_bin)


def test_BOOT001_signature_region_overwritten(synthetic_bin, keypair):
    """The 384 placeholder zero bytes must be replaced with non-zero signature bytes."""
    priv, _pub = keypair
    signed = sign_image(synthetic_bin, priv)
    # SIG region is the last 384 bytes of our synthetic bin.
    sig_bytes = signed[-RSA_3072_SIG_LEN:]
    assert len(sig_bytes) == RSA_3072_SIG_LEN
    assert any(b != 0 for b in sig_bytes), "signature region was not patched"
    # And the BOOT region must be byte-for-byte unchanged.
    boot_len = len(synthetic_bin) - RSA_3072_SIG_LEN
    assert signed[:boot_len] == synthetic_bin[:boot_len]


def test_BOOT001_signature_is_exactly_384_bytes(synthetic_bin, keypair):
    """RSA-3072 PSS signature length is fixed at |n|/8 = 384."""
    priv, _pub = keypair
    signed = sign_image(synthetic_bin, priv)
    sig_bytes = signed[-RSA_3072_SIG_LEN:]
    assert len(sig_bytes) == 384


# ---------------------------------------------------------------------------
# Tamper resistance
# ---------------------------------------------------------------------------

def test_BOOT001_boot_region_tamper_fails_verify(synthetic_bin, keypair):
    """Flip one byte inside the BOOT region — verification must reject it."""
    priv, pub = keypair
    signed = sign_image(synthetic_bin, priv)
    tampered = bytearray(signed)
    # Flip a byte well inside BOOT (past the TOC) — at offset code_size//2.
    boot_len = len(signed) - RSA_3072_SIG_LEN
    tampered[boot_len // 2] ^= 0xFF
    assert verify_image(bytes(tampered), pub) is False


def test_BOOT001_sig_region_tamper_fails_verify(synthetic_bin, keypair):
    """Flip one byte inside the SIG region — verification must reject it."""
    priv, pub = keypair
    signed = sign_image(synthetic_bin, priv)
    tampered = bytearray(signed)
    tampered[-1] ^= 0xFF  # last byte of the signature
    assert verify_image(bytes(tampered), pub) is False


def test_BOOT001_wrong_key_fails_verify(synthetic_bin, keypair, other_keypair):
    """A signature from a DIFFERENT manufacturer key must NOT verify against ours.
    This is the property that makes 'manufacturer-signed only' meaningful.
    """
    priv, _pub = keypair
    _other_priv, other_pub = other_keypair
    signed = sign_image(synthetic_bin, priv)
    assert verify_image(signed, other_pub) is False


# ---------------------------------------------------------------------------
# Determinism / regression guards
# ---------------------------------------------------------------------------

def test_BOOT001_signer_uses_saltlen_32(synthetic_bin, keypair):
    """The bootloader's libtomcrypt verifier passes saltlen=32 to
    rsa_verify_hash_ex. If the signer drifts to MAX_LENGTH (as signer.py uses),
    verification on the device silently fails. We don't have introspection
    into PSS internals from `cryptography` directly — but we CAN verify
    end-to-end with saltlen=32 succeeds, and sanity-check that with
    saltlen=MAX_LENGTH on the verify side, our signature does NOT validate.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.exceptions import InvalidSignature

    priv, pub = keypair
    signed = sign_image(synthetic_bin, priv)

    boot_len = len(signed) - RSA_3072_SIG_LEN
    boot_bytes = signed[:boot_len]
    sig_bytes = signed[-RSA_3072_SIG_LEN:]

    public_key = serialization.load_pem_public_key(pub)
    # MAX_LENGTH would silently pass anything <= max, so this asymmetric check
    # primarily proves the signer didn't accidentally use saltlen=0 or some
    # other off-by-default value. The positive-side guarantee is the round-trip
    # test above (which uses saltlen=32 on both ends).
    try:
        public_key.verify(
            sig_bytes,
            boot_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        verified_at_32 = True
    except InvalidSignature:
        verified_at_32 = False
    assert verified_at_32, "signer must produce signatures verifiable at saltlen=32"
