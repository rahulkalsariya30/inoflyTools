"""
tests/compliance/test_ROT001_keygen.py

Tests for Requirement ROT001:
  "The flight module shall have a root of trust mechanism implemented
   using TPM or TEE. The manufacturer keypair is the software RoT
   used to sign all manufacturer-generated data."

Each test name starts with the requirement ID it covers.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Add project root to path so we can import our tools
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.pki.keygen import generate_keypair, RSA_KEY_SIZE


class TestROT001_KeypairGeneration:
    """Tests that the manufacturer keypair is generated correctly."""

    def test_ROT001_keypair_returns_two_values(self):
        """generate_keypair() must return both a private and public key."""
        result = generate_keypair()
        assert len(result) == 2, "Expected (private_key_pem, public_key_pem) tuple"

    def test_ROT001_private_key_is_bytes(self):
        """Private key must be returned as bytes (PEM format)."""
        private_key_pem, _ = generate_keypair()
        assert isinstance(private_key_pem, bytes)

    def test_ROT001_public_key_is_bytes(self):
        """Public key must be returned as bytes (PEM format)."""
        _, public_key_pem = generate_keypair()
        assert isinstance(public_key_pem, bytes)

    def test_ROT001_private_key_is_valid_pem(self):
        """Private key must be a valid PEM-encoded RSA private key."""
        private_key_pem, _ = generate_keypair()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)

    def test_ROT001_public_key_is_valid_pem(self):
        """Public key must be a valid PEM-encoded RSA public key."""
        _, public_key_pem = generate_keypair()
        public_key = serialization.load_pem_public_key(public_key_pem)
        assert isinstance(public_key, rsa.RSAPublicKey)

    def test_ROT001_uses_RSA_3072(self):
        """
        Keypair must use RSA-3072 (128-bit security).
        WHY: RSA-3072 is NIST-recommended for use beyond 2030 (SP 800-57).
             Supports both signing (firmware) and encryption (log hashes).
        """
        private_key_pem, public_key_pem = generate_keypair()

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        public_key  = serialization.load_pem_public_key(public_key_pem)

        assert private_key.key_size == RSA_KEY_SIZE, \
            f"Private key must be RSA-{RSA_KEY_SIZE}, got RSA-{private_key.key_size}"
        assert public_key.key_size == RSA_KEY_SIZE, \
            f"Public key must be RSA-{RSA_KEY_SIZE}, got RSA-{public_key.key_size}"

    def test_ROT001_keypair_is_mathematically_linked(self):
        """
        Private key must be able to sign data that the public key can verify.
        WHY: Proves the two keys are a matching pair, not random bytes.
        """
        private_key_pem, public_key_pem = generate_keypair()

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        public_key  = serialization.load_pem_public_key(public_key_pem)

        # Sign some test data with private key (RSA-PSS + SHA-256)
        test_data = b"inofly-manufacturer-test"
        signature = private_key.sign(
            test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Verify with public key — will raise exception if keys don't match
        public_key.verify(
            signature,
            test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def test_ROT001_each_call_generates_unique_keypair(self):
        """
        Every call to generate_keypair() must produce a different keypair.
        WHY: Ensures the generator uses proper randomness, not a fixed seed.
        """
        private_key_pem_1, public_key_pem_1 = generate_keypair()
        private_key_pem_2, public_key_pem_2 = generate_keypair()

        assert private_key_pem_1 != private_key_pem_2, \
            "Two calls produced identical private keys — not random!"
        assert public_key_pem_1 != public_key_pem_2, \
            "Two calls produced identical public keys — not random!"

    def test_ROT001_wrong_key_cannot_verify_signature(self):
        """
        A signature made with one private key must NOT verify with a different public key.
        WHY: Proves the verification actually checks the key, not just the format.
        """
        from cryptography.exceptions import InvalidSignature

        private_key_pem_1, _ = generate_keypair()
        _, public_key_pem_2  = generate_keypair()  # different keypair

        private_key_1 = serialization.load_pem_private_key(private_key_pem_1, password=None)
        public_key_2  = serialization.load_pem_public_key(public_key_pem_2)

        test_data = b"inofly-manufacturer-test"
        signature = private_key_1.sign(
            test_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # This MUST raise InvalidSignature
        with pytest.raises(InvalidSignature):
            public_key_2.verify(
                signature,
                test_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

    def test_ROT001_rsa_signature_is_384_bytes(self):
        """RSA-3072 signature must be exactly 384 bytes (3072/8)."""
        private_key_pem, _ = generate_keypair()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        signature = private_key.sign(
            b"test",
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        assert len(signature) == RSA_KEY_SIZE // 8  # 3072/8 = 384
