"""
tools/signer/signer.py

Firmware Signing Tool
Requirement: SIG001 - Sign firmware checksum manifest with manufacturer private key

WHY we sign the manifest (not the firmware directly)?
  - The manifest contains both checksums (code + data) from Phase 1.2
  - Signing the manifest proves: "these checksums were produced by the
    legitimate manufacturer and have not been altered"
  - The drone stores this signed bundle and verifies the signature on
    every boot before trusting the checksums
  - If someone tampers with a checksum in the manifest, the signature
    check fails — arming is blocked

WHAT gets signed?
  - The manifest is serialized to canonical JSON (sorted keys, no extra
    whitespace) before signing. This ensures the signature is the same
    regardless of how the JSON was originally formatted.
  - ECDSA P-256 with SHA-256 (same key pair from Phase 1.1 / ROT001)

SIGNED BUNDLE FORMAT (what gets stored on the drone):
  {
      "manifest":   { ...checksum manifest from Phase 1.2... },
      "signature":  "<base64-encoded DER signature bytes>",
      "signed_at":  "<ISO 8601 UTC timestamp>"
  }
  The public key is NOT included in the bundle — it is embedded in the
  drone firmware at build time (from pki/manufacturer/public/).
"""

import base64
import json
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# Default paths — can be overridden by callers
PKI_DIR = Path(__file__).resolve().parent.parent.parent / "pki" / "manufacturer"
PRIVATE_KEY_PATH = PKI_DIR / "private" / "manufacturer_private.pem"
PUBLIC_KEY_PATH  = PKI_DIR / "public"  / "manufacturer_public.pem"


def _canonical_bytes(manifest: dict) -> bytes:
    """
    Serialize manifest to canonical JSON bytes for signing.

    WHY canonical form?
      JSON can be formatted many ways (whitespace, key order) but all
      represent the same data. If we signed formatted JSON, a re-serialization
      with different spacing would break the signature — even though the data
      is identical. Canonical form (sorted keys, no extra whitespace) ensures
      the same manifest always produces the same bytes to sign.
    """
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: dict, private_key_path: Path = PRIVATE_KEY_PATH) -> dict:
    """
    Sign a checksum manifest with the manufacturer private key.

    Args:
        manifest: The checksum manifest dict from checksum.generate_manifest()
        private_key_path: Path to the PEM-encoded ECDSA private key

    Returns:
        A signed bundle dict containing the manifest and its signature.
        This bundle is what gets stored on the flight module.
    """
    if not Path(private_key_path).exists():
        raise FileNotFoundError(
            f"Private key not found at {private_key_path}. "
            "Run tools/pki/keygen.py first to generate the keypair."
        )

    # Load the private key
    private_key_pem = Path(private_key_path).read_bytes()
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Serialize manifest to canonical bytes — this is what we sign
    manifest_bytes = _canonical_bytes(manifest)

    # Sign with ECDSA P-256 + SHA-256
    # The signature is in DER format (the standard binary encoding for ECDSA)
    der_signature = private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))

    # Base64-encode the DER signature so it's safe to store in JSON
    signature_b64 = base64.b64encode(der_signature).decode("utf-8")

    signed_bundle = {
        "manifest": manifest,
        "signature": signature_b64,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    return signed_bundle


def verify_bundle(signed_bundle: dict, public_key_path: Path = PUBLIC_KEY_PATH) -> bool:
    """
    Verify a signed bundle using the manufacturer public key.

    This is what the drone runs on every boot (POST).
    Returns True if signature is valid, False if verification fails.

    Args:
        signed_bundle: The dict produced by sign_manifest()
        public_key_path: Path to the PEM-encoded ECDSA public key

    Returns:
        True if the manifest was signed by the manufacturer's private key
        and has not been altered since signing.
    """
    if not Path(public_key_path).exists():
        raise FileNotFoundError(
            f"Public key not found at {public_key_path}."
        )

    # Load the public key
    public_key_pem = Path(public_key_path).read_bytes()
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Re-derive the canonical bytes from the manifest — same process as signing
    manifest_bytes = _canonical_bytes(signed_bundle["manifest"])

    # Decode the base64 signature back to DER bytes
    der_signature = base64.b64decode(signed_bundle["signature"])

    try:
        public_key.verify(der_signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def save_signed_bundle(signed_bundle: dict, output_path: Path) -> None:
    """
    Save a signed bundle to a JSON file.

    This file is what gets provisioned onto the flight module.
    It contains the manifest (checksums) + the manufacturer's signature.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(signed_bundle, f, indent=4)
    print(f"[OK] Signed bundle saved to: {output_path}")


def load_signed_bundle(bundle_path: Path) -> dict:
    """
    Load a signed bundle from a JSON file.
    """
    with open(bundle_path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    import argparse
    import sys

    # Add project root to path for importing checksum tool
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.checksum.checksum import generate_manifest

    parser = argparse.ArgumentParser(
        description="Sign a PX4 firmware checksum manifest with the manufacturer private key."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--version", default="", help="Firmware version string (optional)")
    parser.add_argument("--output", default="", help="Output path for signed bundle JSON")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        sys.exit(1)

    print(f"Generating checksums for: {px4_path.name}")
    manifest = generate_manifest(px4_path, firmware_version=args.version)
    print(f"  Code checksum: {manifest['code_checksum']}")
    print(f"  Data checksum: {manifest['data_checksum']}")

    print("Signing manifest with manufacturer private key...")
    signed_bundle = sign_manifest(manifest)
    print(f"  Signature:     {signed_bundle['signature'][:32]}...")

    if args.output:
        save_signed_bundle(signed_bundle, Path(args.output))
    else:
        print("\nSigned bundle:")
        print(json.dumps(signed_bundle, indent=4))

    # Verify immediately after signing as a sanity check
    valid = verify_bundle(signed_bundle)
    print(f"\n[{'OK' if valid else 'FAIL'}] Signature verification: {'passed' if valid else 'FAILED'}")
    if not valid:
        sys.exit(1)
