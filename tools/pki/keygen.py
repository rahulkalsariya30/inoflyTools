"""
tools/pki/keygen.py

Manufacturer Key Generation Tool
Requirement: ROT001 - Root of Trust keypair for firmware manufacturer

Generates an ECDSA P-256 keypair:
  - Private key: used by manufacturer to SIGN firmware and parameter updates
  - Public key:  stored on flight module to VERIFY manufacturer signatures

WHY ECDSA P-256?
  - Approved by NIST, accepted by aviation regulators
  - Smaller and faster than RSA while providing equivalent security
  - Supported by PX4's built-in crypto library (libtomcrypt)
  - SHA-256 based — meets the SHA-2 requirement in DGCA Level 1

NEVER share or commit the private key.
The public key is safe to distribute — it goes into the firmware.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# Output paths relative to project root
PKI_DIR = Path(__file__).resolve().parent.parent.parent / "pki" / "manufacturer"
PRIVATE_KEY_PATH = PKI_DIR / "private" / "manufacturer_private.pem"
PUBLIC_KEY_PATH  = PKI_DIR / "public"  / "manufacturer_public.pem"


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ECDSA P-256 keypair.

    Returns:
        (private_key_pem, public_key_pem) as bytes

    The private key is encrypted with a passphrase if provided,
    otherwise stored unencrypted (only do this in a secure environment).
    """
    # Generate the private key using NIST P-256 curve (also called secp256r1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize private key to PEM format — unencrypted for now
    # In production: use BestAvailableEncryption(passphrase) instead of NoEncryption()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract and serialize the public key — safe to share
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


def save_keypair(private_key_pem: bytes, public_key_pem: bytes) -> None:
    """
    Save the keypair to the pki/ directory.

    Private key goes to pki/manufacturer/private/ (never committed to git)
    Public key goes to pki/manufacturer/public/  (safe to commit)
    """
    # Ensure directories exist
    PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write private key — restrict permissions so only owner can read
    PRIVATE_KEY_PATH.write_bytes(private_key_pem)
    os.chmod(PRIVATE_KEY_PATH, 0o600)  # owner read/write only

    # Write public key — no permission restriction needed
    PUBLIC_KEY_PATH.write_bytes(public_key_pem)

    print(f"[OK] Private key saved to: {PRIVATE_KEY_PATH}")
    print(f"[OK] Public key saved to:  {PUBLIC_KEY_PATH}")
    print()
    print("[IMPORTANT] Never commit the private key to git.")
    print("[IMPORTANT] Back up the private key securely offline.")


def load_public_key_pem() -> bytes:
    """
    Load the manufacturer public key PEM bytes.
    Used by other tools (signer, checksum) to embed the key in firmware.
    """
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Public key not found at {PUBLIC_KEY_PATH}. "
            "Run keygen.py first to generate the keypair."
        )
    return PUBLIC_KEY_PATH.read_bytes()


if __name__ == "__main__":
    # Warn if keys already exist — don't overwrite silently
    if PRIVATE_KEY_PATH.exists():
        print("[WARNING] Private key already exists!")
        answer = input("Overwrite? This will invalidate all previously signed firmware. [y/N]: ")
        if answer.strip().lower() != "y":
            print("Aborted.")
            exit(0)

    print("Generating ECDSA P-256 manufacturer keypair...")
    private_key_pem, public_key_pem = generate_keypair()
    save_keypair(private_key_pem, public_key_pem)
    print("Done.")
