"""
tests/compliance/test_ROT002_embed_pubkey.py

Compliance tests for ROT002 — Manufacturer public key embedded in firmware

Requirement: ROT002
  - Public key must be exported in DER SubjectPublicKeyInfo format
  - DER output for RSA-3072 must be the correct size (~422 bytes)
  - Generated C header must contain a valid byte array
  - Generated C header must include the array length constant
  - Wrong key type (not RSA-3072) must be rejected
  - Missing key file must raise a clear error
"""

import re
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from tools.pki.embed_pubkey import pem_to_der, der_to_c_header, generate_header
from tools.pki.keygen import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rsa3072_public_pem():
    """A fresh RSA-3072 public key in PEM format."""
    _, public_pem = generate_keypair()
    return public_pem


@pytest.fixture
def rsa3072_der(rsa3072_public_pem):
    """DER bytes for the RSA-3072 public key."""
    return pem_to_der(rsa3072_public_pem)


# ---------------------------------------------------------------------------
# ROT002 — PEM to DER conversion tests
# ---------------------------------------------------------------------------

class TestROT002_PemToDer:

    def test_ROT002_pem_to_der_returns_bytes(self, rsa3072_public_pem):
        result = pem_to_der(rsa3072_public_pem)
        assert isinstance(result, bytes)

    def test_ROT002_rsa3072_der_is_correct_size(self, rsa3072_public_pem):
        """
        SubjectPublicKeyInfo DER encoding of RSA-3072 is approximately 422 bytes.
        The exact size depends on the modulus encoding but is always in this range.
        """
        result = pem_to_der(rsa3072_public_pem)
        assert 400 < len(result) < 450, \
            f"RSA-3072 DER key should be ~422 bytes, got {len(result)}"

    def test_ROT002_der_starts_with_sequence_tag(self, rsa3072_public_pem):
        """
        DER SubjectPublicKeyInfo starts with 0x30 (ASN.1 SEQUENCE tag).
        This confirms the output is valid DER encoding.
        """
        result = pem_to_der(rsa3072_public_pem)
        assert result[0] == 0x30

    def test_ROT002_der_contains_rsa_oid(self, rsa3072_public_pem):
        """
        The DER bytes must contain the RSA OID: 2a 86 48 86 f7 0d 01 01 01
        This identifies the key as RSA (id-rsaEncryption).
        """
        rsa_oid = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
        result = pem_to_der(rsa3072_public_pem)
        assert rsa_oid in result

    def test_ROT002_different_keys_produce_different_der(self):
        """Two different RSA-3072 keys must produce different DER bytes."""
        _, pem1 = generate_keypair()
        _, pem2 = generate_keypair()
        assert pem_to_der(pem1) != pem_to_der(pem2)

    def test_ROT002_rejects_ec_key(self):
        """Must reject EC keys — only RSA-3072 is supported."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_public_pem = ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(TypeError, match="not an RSA public key"):
            pem_to_der(ec_public_pem)

    def test_ROT002_rejects_rsa2048(self):
        """Must reject RSA-2048 — only RSA-3072 is supported."""
        rsa2048_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2048_public_pem = rsa2048_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(TypeError, match="RSA-3072"):
            pem_to_der(rsa2048_public_pem)


# ---------------------------------------------------------------------------
# ROT002 — C header generation tests
# ---------------------------------------------------------------------------

class TestROT002_CHeaderGeneration:

    def test_ROT002_header_contains_array_declaration(self, rsa3072_der):
        header = der_to_c_header(rsa3072_der)
        assert "MANUFACTURER_PUBLIC_KEY_DER[]" in header

    def test_ROT002_header_contains_length_constant(self, rsa3072_der):
        header = der_to_c_header(rsa3072_der)
        assert "MANUFACTURER_PUBLIC_KEY_DER_LEN" in header
        assert str(len(rsa3072_der)) in header

    def test_ROT002_header_has_pragma_once(self, rsa3072_der):
        """#pragma once prevents double-inclusion in C/C++ builds."""
        header = der_to_c_header(rsa3072_der)
        assert "#pragma once" in header

    def test_ROT002_header_includes_stdint(self, rsa3072_der):
        """Must include stdint.h so uint8_t is defined on all platforms."""
        header = der_to_c_header(rsa3072_der)
        assert "#include <stdint.h>" in header

    def test_ROT002_header_all_bytes_present(self, rsa3072_der):
        """Every byte of the key must appear in the header as a hex value."""
        header = der_to_c_header(rsa3072_der)
        for byte in rsa3072_der:
            assert f"0x{byte:02x}" in header

    def test_ROT002_header_byte_count_matches_key(self, rsa3072_der):
        """Count of 0xNN values in header must equal key length."""
        header = der_to_c_header(rsa3072_der)
        hex_values = re.findall(r"0x[0-9a-f]{2}", header)
        assert len(hex_values) == len(rsa3072_der)

    def test_ROT002_header_contains_auto_generated_warning(self, rsa3072_der):
        """Header must warn developers not to edit it manually."""
        header = der_to_c_header(rsa3072_der)
        assert "DO NOT EDIT MANUALLY" in header

    def test_ROT002_header_mentions_rsa3072(self, rsa3072_der):
        """Header must document that the key is RSA-3072."""
        header = der_to_c_header(rsa3072_der)
        assert "RSA-3072" in header

    def test_ROT002_custom_array_name_is_used(self, rsa3072_der):
        header = der_to_c_header(rsa3072_der, array_name="MY_CUSTOM_KEY")
        assert "MY_CUSTOM_KEY[]" in header
        assert "MY_CUSTOM_KEY_LEN" in header


# ---------------------------------------------------------------------------
# ROT002 — Full pipeline (generate_header) tests
# ---------------------------------------------------------------------------

class TestROT002_GenerateHeader:

    def test_ROT002_generate_header_creates_file(self, tmp_path):
        _, public_pem = generate_keypair()
        key_path = tmp_path / "public.pem"
        key_path.write_bytes(public_pem)
        output_path = tmp_path / "include" / "pubkey.h"

        generate_header(public_key_path=key_path, output_path=output_path)
        assert output_path.exists()

    def test_ROT002_generate_header_creates_parent_dirs(self, tmp_path):
        _, public_pem = generate_keypair()
        key_path = tmp_path / "public.pem"
        key_path.write_bytes(public_pem)
        output_path = tmp_path / "deep" / "nested" / "pubkey.h"

        generate_header(public_key_path=key_path, output_path=output_path)
        assert output_path.exists()

    def test_ROT002_generated_file_content_is_valid_header(self, tmp_path):
        _, public_pem = generate_keypair()
        key_path = tmp_path / "public.pem"
        key_path.write_bytes(public_pem)
        output_path = tmp_path / "pubkey.h"

        content = generate_header(public_key_path=key_path, output_path=output_path)
        assert "#pragma once" in content
        assert "MANUFACTURER_PUBLIC_KEY_DER[]" in content
        assert "MANUFACTURER_PUBLIC_KEY_DER_LEN" in content

    def test_ROT002_missing_key_file_raises_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            generate_header(
                public_key_path=tmp_path / "nonexistent.pem",
                output_path=tmp_path / "out.h",
            )
