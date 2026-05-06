"""
tests/compliance/test_SIG001_signer.py

Compliance tests for SIG001 — Firmware manifest signing and verification

Requirement: SIG001
  - Manufacturer private key must be able to sign the checksum manifest
  - Signature must be verifiable with the corresponding public key
  - A tampered manifest must fail verification
  - A signature from a different key must fail verification
  - Signed bundle must contain the manifest and signature fields
  - Signature must use RSA-2048 with PSS padding and SHA-256
"""

import base64
import json
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.signer.signer import (
    sign_manifest,
    verify_bundle,
    save_signed_bundle,
    load_signed_bundle,
    _canonical_bytes,
)
from tools.pki.keygen import generate_keypair, RSA_KEY_SIZE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair(tmp_path):
    """Generate a fresh keypair and save to temp directory."""
    private_pem, public_pem = generate_keypair()

    private_path = tmp_path / "private" / "manufacturer_private.pem"
    public_path  = tmp_path / "public"  / "manufacturer_public.pem"
    private_path.parent.mkdir(parents=True)
    public_path.parent.mkdir(parents=True)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    return {"private": private_path, "public": public_path}


@pytest.fixture
def sample_manifest():
    """A realistic checksum manifest as produced by checksum.generate_manifest()."""
    return {
        "algorithm": "SHA-256",
        "firmware_version": "1.14.0-test",
        "source_file": "px4_fmu-v5_default.px4",
        "board_id": 50,
        "git_hash": "abc123def456",
        "code_checksum": "a" * 64,
        "data_checksum": "b" * 64,
        "generated_at": "2026-01-01T00:00:00+00:00",
    }


@pytest.fixture
def signed_bundle(sample_manifest, keypair):
    """A signed bundle produced from the sample manifest."""
    return sign_manifest(sample_manifest, private_key_path=keypair["private"])


# ---------------------------------------------------------------------------
# SIG001 — Signing tests
# ---------------------------------------------------------------------------

class TestSIG001_Signing:

    def test_SIG001_sign_returns_dict(self, sample_manifest, keypair):
        result = sign_manifest(sample_manifest, private_key_path=keypair["private"])
        assert isinstance(result, dict)

    def test_SIG001_signed_bundle_has_manifest_field(self, signed_bundle, sample_manifest):
        assert "manifest" in signed_bundle
        assert signed_bundle["manifest"] == sample_manifest

    def test_SIG001_signed_bundle_has_signature_field(self, signed_bundle):
        assert "signature" in signed_bundle
        assert isinstance(signed_bundle["signature"], str)
        assert len(signed_bundle["signature"]) > 0

    def test_SIG001_signed_bundle_has_signed_at_field(self, signed_bundle):
        assert "signed_at" in signed_bundle

    def test_SIG001_signature_is_valid_base64(self, signed_bundle):
        """Signature must be storable in JSON — base64 encoded."""
        try:
            decoded = base64.b64decode(signed_bundle["signature"])
            assert len(decoded) > 0
        except Exception:
            pytest.fail("Signature is not valid base64")

    def test_SIG001_signature_is_256_bytes(self, signed_bundle):
        """RSA-2048 signature must be exactly 256 bytes (2048 / 8)."""
        sig_bytes = base64.b64decode(signed_bundle["signature"])
        assert len(sig_bytes) == RSA_KEY_SIZE // 8, \
            f"Expected {RSA_KEY_SIZE // 8} bytes, got {len(sig_bytes)}"

    def test_SIG001_missing_private_key_raises_error(self, sample_manifest, tmp_path):
        """Must fail clearly if private key file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            sign_manifest(sample_manifest, private_key_path=tmp_path / "nonexistent.pem")

    def test_SIG001_two_signatures_of_same_manifest_are_different(self, sample_manifest, keypair):
        """
        RSA-PSS uses a random salt per signature — the same data signed twice
        produces different signatures. Both must verify correctly.
        """
        bundle1 = sign_manifest(sample_manifest, private_key_path=keypair["private"])
        bundle2 = sign_manifest(sample_manifest, private_key_path=keypair["private"])
        assert bundle1["signature"] != bundle2["signature"]


# ---------------------------------------------------------------------------
# SIG001 — Verification tests
# ---------------------------------------------------------------------------

class TestSIG001_Verification:

    def test_SIG001_valid_bundle_verifies_successfully(self, signed_bundle, keypair):
        result = verify_bundle(signed_bundle, public_key_path=keypair["public"])
        assert result is True

    def test_SIG001_tampered_code_checksum_fails_verification(self, signed_bundle, keypair):
        """
        If someone changes the code_checksum after signing, verification must fail.
        This is the core tamper-detection requirement.
        """
        tampered = json.loads(json.dumps(signed_bundle))  # deep copy
        tampered["manifest"]["code_checksum"] = "f" * 64  # flip all chars
        result = verify_bundle(tampered, public_key_path=keypair["public"])
        assert result is False

    def test_SIG001_tampered_data_checksum_fails_verification(self, signed_bundle, keypair):
        """Tampering with the data checksum must also be caught."""
        tampered = json.loads(json.dumps(signed_bundle))
        tampered["manifest"]["data_checksum"] = "0" * 64
        result = verify_bundle(tampered, public_key_path=keypair["public"])
        assert result is False

    def test_SIG001_tampered_version_fails_verification(self, signed_bundle, keypair):
        """Even changing the version string must fail verification."""
        tampered = json.loads(json.dumps(signed_bundle))
        tampered["manifest"]["firmware_version"] = "9.9.9-malicious"
        result = verify_bundle(tampered, public_key_path=keypair["public"])
        assert result is False

    def test_SIG001_wrong_public_key_fails_verification(self, signed_bundle, tmp_path):
        """
        A different manufacturer's public key must not verify our signature.
        This proves the bundle is tied specifically to our private key.
        """
        # Generate a completely separate keypair
        _, different_public_pem = generate_keypair()
        different_public_path = tmp_path / "different_public.pem"
        different_public_path.write_bytes(different_public_pem)

        result = verify_bundle(signed_bundle, public_key_path=different_public_path)
        assert result is False

    def test_SIG001_corrupted_signature_fails_verification(self, signed_bundle, keypair):
        """A randomly corrupted signature must not verify."""
        corrupted = json.loads(json.dumps(signed_bundle))
        corrupted["signature"] = base64.b64encode(b"\x00" * 256).decode("utf-8")
        result = verify_bundle(corrupted, public_key_path=keypair["public"])
        assert result is False

    def test_SIG001_missing_public_key_raises_error(self, signed_bundle, tmp_path):
        """Must fail clearly if public key file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            verify_bundle(signed_bundle, public_key_path=tmp_path / "nonexistent.pem")


# ---------------------------------------------------------------------------
# SIG001 — Canonical serialization tests
# ---------------------------------------------------------------------------

class TestSIG001_Canonical:

    def test_SIG001_canonical_bytes_are_deterministic(self, sample_manifest):
        """Same manifest must always serialize to identical bytes."""
        b1 = _canonical_bytes(sample_manifest)
        b2 = _canonical_bytes(sample_manifest)
        assert b1 == b2

    def test_SIG001_key_order_does_not_affect_canonical_bytes(self, sample_manifest):
        """
        JSON key order must not matter for signing.
        Whether keys come out as abc or cba, the canonical form is the same.
        """
        import copy
        # Build a reversed-key version of the manifest
        reversed_manifest = dict(reversed(list(sample_manifest.items())))
        assert _canonical_bytes(sample_manifest) == _canonical_bytes(reversed_manifest)

    def test_SIG001_bundle_signed_with_reordered_manifest_still_verifies(self, keypair):
        """
        A bundle signed from one key order must verify even if keys are reordered.
        Proves canonical serialization works end-to-end.
        """
        manifest_v1 = {"algorithm": "SHA-256", "code_checksum": "a" * 64, "data_checksum": "b" * 64}
        manifest_v2 = {"data_checksum": "b" * 64, "code_checksum": "a" * 64, "algorithm": "SHA-256"}

        bundle = sign_manifest(manifest_v1, private_key_path=keypair["private"])
        bundle["manifest"] = manifest_v2  # replace with reordered version

        result = verify_bundle(bundle, public_key_path=keypair["public"])
        assert result is True


# ---------------------------------------------------------------------------
# SIG001 — Save / load round-trip tests
# ---------------------------------------------------------------------------

class TestSIG001_SaveLoad:

    def test_SIG001_save_and_load_preserves_bundle(self, signed_bundle, tmp_path):
        output_path = tmp_path / "signed_bundle.json"
        save_signed_bundle(signed_bundle, output_path)
        loaded = load_signed_bundle(output_path)
        assert loaded["signature"] == signed_bundle["signature"]
        assert loaded["manifest"] == signed_bundle["manifest"]

    def test_SIG001_loaded_bundle_verifies_successfully(self, signed_bundle, keypair, tmp_path):
        """A bundle saved to disk and reloaded must still verify correctly."""
        output_path = tmp_path / "signed_bundle.json"
        save_signed_bundle(signed_bundle, output_path)
        loaded = load_signed_bundle(output_path)
        result = verify_bundle(loaded, public_key_path=keypair["public"])
        assert result is True

    def test_SIG001_save_creates_parent_directories(self, signed_bundle, tmp_path):
        output_path = tmp_path / "deep" / "nested" / "signed_bundle.json"
        save_signed_bundle(signed_bundle, output_path)
        assert output_path.exists()
