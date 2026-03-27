"""
tests/compliance/test_ROT002_embed_pubkey.py

Compliance tests for ROT002 — Manufacturer public key embedded in firmware

Requirement: ROT002
  - Public key must be exported in DER SubjectPublicKeyInfo format
  - DER output for P-256 must be exactly 91 bytes
  - Generated C header must contain a valid byte array
  - Generated C header must include the array length constant
  - Wrong key type (not P-256) must be rejected
  - Missing key file must raise a clear error
"""

import re
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from tools.pki.embed_pubkey import pem_to_der, der_to_c_header, generate_header
from tools.pki.keygen import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def p256_public_pem():
    """A fresh P-256 public key in PEM format."""
    _, public_pem = generate_keypair()
    return public_pem


@pytest.fixture
def p256_der(p256_public_pem):
    """DER bytes for the P-256 public key."""
    return pem_to_der(p256_public_pem)


# ---------------------------------------------------------------------------
# ROT002 — PEM to DER conversion tests
# ---------------------------------------------------------------------------

class TestROT002_PemToDer:

    def test_ROT002_pem_to_der_returns_bytes(self, p256_public_pem):
        result = pem_to_der(p256_public_pem)
        assert isinstance(result, bytes)

    def test_ROT002_p256_der_is_exactly_91_bytes(self, p256_public_pem):
        """
        SubjectPublicKeyInfo DER encoding of P-256 is always exactly 91 bytes.
        This is fixed by the curve: 32-byte X + 32-byte Y + ASN.1 overhead.
        If this fails, the key is not P-256.
        """
        result = pem_to_der(p256_public_pem)
        assert len(result) == 91

    def test_ROT002_der_starts_with_sequence_tag(self, p256_public_pem):
        """
        DER SubjectPublicKeyInfo starts with 0x30 (ASN.1 SEQUENCE tag).
        This confirms the output is valid DER encoding.
        """
        result = pem_to_der(p256_public_pem)
        assert result[0] == 0x30

    def test_ROT002_der_contains_secp256r1_oid(self, p256_public_pem):
        """
        The DER bytes must contain the secp256r1 OID: 2a 86 48 ce 3d 03 01 07
        This is how libtomcrypt knows which curve to use when importing.
        """
        secp256r1_oid = bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
        result = pem_to_der(p256_public_pem)
        assert secp256r1_oid in result

    def test_ROT002_different_keys_produce_different_der(self):
        """Two different P-256 keys must produce different DER bytes."""
        _, pem1 = generate_keypair()
        _, pem2 = generate_keypair()
        assert pem_to_der(pem1) != pem_to_der(pem2)

    def test_ROT002_rejects_non_ec_key(self, tmp_path):
        """Must reject RSA keys — only P-256 EC keys are supported."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        rsa_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        rsa_public_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(TypeError, match="not an EC public key"):
            pem_to_der(rsa_public_pem)

    def test_ROT002_rejects_p384_curve(self):
        """Must reject curves other than P-256 — firmware only supports P-256."""
        p384_key = ec.generate_private_key(ec.SECP384R1())
        p384_public_pem = p384_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(TypeError, match="P-256"):
            pem_to_der(p384_public_pem)


# ---------------------------------------------------------------------------
# ROT002 — C header generation tests
# ---------------------------------------------------------------------------

class TestROT002_CHeaderGeneration:

    def test_ROT002_header_contains_array_declaration(self, p256_der):
        header = der_to_c_header(p256_der)
        assert "MANUFACTURER_PUBLIC_KEY_DER[]" in header

    def test_ROT002_header_contains_length_constant(self, p256_der):
        header = der_to_c_header(p256_der)
        assert "MANUFACTURER_PUBLIC_KEY_DER_LEN" in header
        assert "91" in header  # correct length for P-256

    def test_ROT002_header_has_pragma_once(self, p256_der):
        """#pragma once prevents double-inclusion in C/C++ builds."""
        header = der_to_c_header(p256_der)
        assert "#pragma once" in header

    def test_ROT002_header_includes_stdint(self, p256_der):
        """Must include stdint.h so uint8_t is defined on all platforms."""
        header = der_to_c_header(p256_der)
        assert "#include <stdint.h>" in header

    def test_ROT002_header_all_bytes_present(self, p256_der):
        """Every byte of the key must appear in the header as a hex value."""
        header = der_to_c_header(p256_der)
        for byte in p256_der:
            assert f"0x{byte:02x}" in header

    def test_ROT002_header_byte_count_matches_key(self, p256_der):
        """Count of 0xNN values in header must equal key length (91)."""
        header = der_to_c_header(p256_der)
        hex_values = re.findall(r"0x[0-9a-f]{2}", header)
        assert len(hex_values) == len(p256_der)

    def test_ROT002_header_contains_auto_generated_warning(self, p256_der):
        """Header must warn developers not to edit it manually."""
        header = der_to_c_header(p256_der)
        assert "DO NOT EDIT MANUALLY" in header

    def test_ROT002_custom_array_name_is_used(self, p256_der):
        header = der_to_c_header(p256_der, array_name="MY_CUSTOM_KEY")
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
