"""
tests/compliance/test_BOOT008_sign_bootloader.py

Compliance tests for BOOT008 (T11-H) — signed bootloader updates, host side.

Requirement: BOOT008 (ADR-025)
  - The secure bootloader is a manufacturer-signed embedded-TOC artifact, the
    same *kind* of signed image as the app (BOOT001) but loaded at flash sector
    0 (0x08000000) instead of the app load address (0x08020000).
  - `pipeline.sign_bootloader_image` must RSA-PSS-sign the BOOT region and patch
    the SIG region in place; the result must verify with the matching pubkey.
  - A bootloader .bin with NO image TOC (i.e. a pre-BOOT008 artifact) must be
    REFUSED loudly, not silently shipped unsigned — otherwise the on-device
    `bl_update` gate would reject it on the bench and look like a brick.
  - Tampering the BOOT region, or signing with a different key, must fail verify.

These tests are hermetic: they build a synthetic bootloader .bin matching the
linker layout and never touch the real PX4 build. The device-side gate
(bl_update verify-before-erase) is validated separately on hardware
(BOOTLOADER_BRINGUP B8).
"""

import struct
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.pipeline import sign_bootloader_image, BOOTLOADER_LOAD_ADDRESS
from tools.signer.toc_sign import (
    verify_image,
    TOC_START_MAGIC,
    TOC_END_MAGIC,
    TOC_OFFSET_DEFAULT,
    RSA_2048_SIG_LEN,
)
from tools.pki.keygen import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keyfiles(tmp_path_factory):
    """RSA-2048 keypair written to PEM files (sign_bootloader_image takes paths)."""
    priv_pem, pub_pem = generate_keypair()
    d = tmp_path_factory.mktemp("bl_keys")
    priv = d / "priv.pem"
    pub = d / "pub.pem"
    priv.write_bytes(priv_pem)
    pub.write_bytes(pub_pem)
    return priv, pub, pub_pem


@pytest.fixture(scope="module")
def other_pub(tmp_path_factory):
    """An unrelated public key for the cross-key negative test."""
    _priv_pem, pub_pem = generate_keypair()
    return pub_pem


def _build_bootloader_bin(code_size: int = 8192) -> bytes:
    """
    Synthetic bootloader .bin at load address 0x08000000, TOC at 0x2a8, mirroring
    what bl_toc.c + bootloader_script.ld emit:

      [0 .. 0x2a8)                 vectors + bootdelay slot
      [0x2a8 .. toc_end)           TOC start + BOOT + SIG1 + END
      [toc_end .. code_size)       "code"
      [code_size .. code_size+256) 256 zero bytes (SIG placeholder)
    """
    base = BOOTLOADER_LOAD_ADDRESS
    toc_offset = TOC_OFFSET_DEFAULT
    assert code_size > toc_offset + 8 + 24 + 24 + 4

    total_len = code_size + RSA_2048_SIG_LEN
    b = bytearray(total_len)

    for i in range(toc_offset):
        b[i] = (i * 7 + 0x42) & 0xFF

    struct.pack_into("<II", b, toc_offset, TOC_START_MAGIC, 1)
    # BOOT: [base, base+code_size), flags BOOT|CHECK_SIGNATURE = 0x05, sig_idx 1
    struct.pack_into("<4sIII4BI", b, toc_offset + 8,
                     b"BOOT", base, base + code_size, 0, 1, 0, 0, 0x05, 0)
    # SIG1: the 256 bytes after BOOT
    struct.pack_into("<4sIII4BI", b, toc_offset + 8 + 24,
                     b"SIG1", base + code_size, base + code_size + RSA_2048_SIG_LEN,
                     0, 0, 0, 0, 0, 0)
    struct.pack_into("<I", b, toc_offset + 8 + 24 + 24, TOC_END_MAGIC)

    for i in range(toc_offset + 8 + 24 + 24 + 4, code_size):
        b[i] = (i * 13 + 0x99) & 0xFF
    return bytes(b)


@pytest.fixture
def bl_bin(tmp_path):
    p = tmp_path / "bootloader.bin"
    p.write_bytes(_build_bootloader_bin())
    return p


# ---------------------------------------------------------------------------
# Signing round-trip (load address 0x08000000)
# ---------------------------------------------------------------------------

def test_BOOT008_sign_then_verify_passes(bl_bin, keyfiles, tmp_path):
    priv, pub, pub_pem = keyfiles
    out = tmp_path / "signed.bin"
    sign_bootloader_image(bl_bin, priv, pub, out)
    signed = out.read_bytes()
    # Must verify at the bootloader load address, NOT the app one.
    assert verify_image(signed, pub_pem, app_load_address=BOOTLOADER_LOAD_ADDRESS) is True


def test_BOOT008_signed_same_length_and_sig_patched(bl_bin, keyfiles, tmp_path):
    priv, pub, _pub_pem = keyfiles
    out = tmp_path / "signed.bin"
    sign_bootloader_image(bl_bin, priv, pub, out)
    original = bl_bin.read_bytes()
    signed = out.read_bytes()
    assert len(signed) == len(original)                       # in-place patch
    assert any(b != 0 for b in signed[-RSA_2048_SIG_LEN:])    # SIG region patched
    boot_len = len(original) - RSA_2048_SIG_LEN
    assert signed[:boot_len] == original[:boot_len]           # BOOT region untouched


def test_BOOT008_sign_in_place_default_output(bl_bin, keyfiles):
    """output_path defaults are exercised via the CLI; here confirm signing the
    same path as input works when caller passes output == input."""
    priv, pub, pub_pem = keyfiles
    sign_bootloader_image(bl_bin, priv, pub, bl_bin)
    assert verify_image(bl_bin.read_bytes(), pub_pem,
                        app_load_address=BOOTLOADER_LOAD_ADDRESS) is True


# ---------------------------------------------------------------------------
# Refuses a pre-BOOT008 (no-TOC) artifact — the "don't sign the stale bin" guard
# ---------------------------------------------------------------------------

def test_BOOT008_no_toc_bin_is_refused(keyfiles, tmp_path):
    priv, pub, _pub_pem = keyfiles
    # A plausible bootloader-sized blob with NO TOC magic at 0x2a8.
    junk = tmp_path / "old_bootloader.bin"
    junk.write_bytes(bytes((i * 3 + 1) & 0xFF for i in range(4096)))
    out = tmp_path / "should_not_exist.bin"
    with pytest.raises(RuntimeError, match="no image TOC"):
        sign_bootloader_image(junk, priv, pub, out)
    assert not out.exists(), "must not emit an output when it refuses to sign"


# ---------------------------------------------------------------------------
# Tamper / wrong-key negatives
# ---------------------------------------------------------------------------

def test_BOOT008_boot_region_tamper_fails_verify(bl_bin, keyfiles, tmp_path):
    priv, pub, pub_pem = keyfiles
    out = tmp_path / "signed.bin"
    sign_bootloader_image(bl_bin, priv, pub, out)
    signed = bytearray(out.read_bytes())
    boot_len = len(signed) - RSA_2048_SIG_LEN
    signed[boot_len // 2] ^= 0xFF  # flip a byte inside BOOT
    assert verify_image(bytes(signed), pub_pem,
                        app_load_address=BOOTLOADER_LOAD_ADDRESS) is False


def test_BOOT008_wrong_key_fails_verify(bl_bin, keyfiles, other_pub, tmp_path):
    priv, pub, _pub_pem = keyfiles
    out = tmp_path / "signed.bin"
    sign_bootloader_image(bl_bin, priv, pub, out)
    signed = out.read_bytes()
    # A different manufacturer key must NOT validate our bootloader signature.
    assert verify_image(signed, other_pub,
                        app_load_address=BOOTLOADER_LOAD_ADDRESS) is False


def test_BOOT008_app_load_address_is_flash_base():
    """Guard: the bootloader load address is flash sector 0, not the app's."""
    assert BOOTLOADER_LOAD_ADDRESS == 0x08000000
