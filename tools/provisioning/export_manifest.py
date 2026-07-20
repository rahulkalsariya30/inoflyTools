"""
tools/provisioning/export_manifest.py

Binary Manifest Export Tool
Requirement: PRV001 - Convert JSON signed bundle to binary manifest for drone storage

WHY this tool exists:
  Phase 1.3 (signer.py) produces a JSON signed bundle — great for tooling,
  auditing, and storage on developer machines. But the drone runs NuttX RTOS
  which cannot parse JSON efficiently at boot time.

  This tool converts the JSON bundle into a compact binary struct that the
  C++ secure_boot module can read directly using a simple struct cast.

WHY re-sign in binary format?
  The JSON signer (Phase 1.3) signed the canonical JSON representation.
  The embedded verifier cannot reproduce canonical JSON. So this tool
  creates a separate signature over a deterministic binary payload:

    signable_payload = code_hash[32] + data_hash[32] + board_id[2]
                     + version[32] + created_at[4]
                     = 102 bytes, always in this exact order

  The embedded side reconstructs this same 102-byte payload from the struct
  fields and verifies the RSA-PSS signature.

WHY created_at is inside the signature (v4):
  The FC's apply (A-5) and promotion (A-6) anti-rollback checks compare the
  staged manifest's created_at against the active one. In v3 created_at was
  covered only by CRC32 — an attacker replaying an old signed manifest could
  forward-date it (recompute CRC, signature still valid) and beat the
  rollback check. v4 folds created_at into the signed payload, so any
  timestamp edit invalidates the manufacturer signature.

BINARY MANIFEST FORMAT (security_manifest_t — 373 bytes):
  Offset  Size  Field
  ------  ----  -----
       0     8  magic        "INOFLY04" — format identifier (v4: signed created_at)
       8     1  format_ver   struct layout version (currently 4)
       9    32  code_hash    SHA-256 of firmware binary
      41    32  data_hash    SHA-256 of default parameter set
      73   256  signature    RSA-2048 PSS signature (always exactly 256 bytes)
     329     2  sig_len      actual signature byte count (256 for RSA-2048)
     331     2  board_id     target hardware ID (little-endian uint16)
     333    32  version      firmware version string, null-terminated
     365     4  created_at   unix timestamp (little-endian uint32)
     369     4  crc32        CRC32 of bytes 0–368 (little-endian uint32)
    ----
     373     TOTAL

The CRC32 covers the entire struct except the last 4 bytes (the CRC itself).
It detects storage corruption — a failed CRC means the flash was corrupted,
not necessarily that someone tampered with the firmware.
"""

import binascii
import json
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Paths
PROJECT_ROOT     = Path(__file__).resolve().parent.parent.parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"

# Binary format constants
MAGIC           = b"INOFLY04"   # 8 bytes — v4: created_at inside signed payload
FORMAT_VERSION  = 4             # v4: signed created_at (anti-rollback hardening)
HASH_LEN        = 32            # SHA-256 output size
SIG_MAX_LEN     = 256           # RSA-2048 signature size (2048/8 = 256 bytes, always exact)
VERSION_LEN     = 32            # firmware version string buffer size
TOTAL_SIZE      = 373           # total struct size in bytes

# Struct pack format (little-endian, packed):
# 8s = magic[8], B = format_ver, 32s = code_hash, 32s = data_hash,
# 256s = signature, H = sig_len, H = board_id, 32s = version,
# I = created_at, I = crc32
STRUCT_FORMAT   = "<8sB32s32s256sHH32sII"

assert struct.calcsize(STRUCT_FORMAT) == TOTAL_SIZE, \
    f"Struct size mismatch: {struct.calcsize(STRUCT_FORMAT)} != {TOTAL_SIZE}"


def _build_signable_payload(code_hash: bytes, data_hash: bytes,
                             board_id: int, version: str,
                             created_at: int) -> bytes:
    """
    Build the 102-byte payload that gets signed and later verified on the drone.

    WHY this specific layout?
      Fixed-length fields, fixed order — the embedded C code reconstructs
      this exact sequence from the struct and passes it to the RSA-PSS
      verifier. Any change here must be mirrored in
      FirmwareIntegrityChecker.cpp _build_signable_payload().

    WHY created_at is included (v4):
      The FC compares staged vs active created_at for anti-rollback (A-5/A-6).
      Signing it makes the timestamp unforgeable.

    Returns:
        102 bytes: code_hash[32] + data_hash[32] + board_id_le[2]
                 + version_padded[32] + created_at_le[4]
    """
    board_id_bytes   = struct.pack("<H", board_id)          # 2 bytes, little-endian
    version_bytes    = version.encode("utf-8")[:VERSION_LEN-1]  # max 31 chars + null
    version_padded   = version_bytes.ljust(VERSION_LEN, b"\x00")  # pad to 32 bytes
    created_at_bytes = struct.pack("<I", created_at)        # 4 bytes, little-endian

    payload = code_hash + data_hash + board_id_bytes + version_padded + created_at_bytes
    assert len(payload) == 102, f"Payload size wrong: {len(payload)}"
    return payload


def _sign_binary_payload(payload: bytes, private_key_path: Path) -> bytes:
    """
    Sign the binary signable_payload with the manufacturer private key.
    Returns RSA-PSS signature bytes (256 bytes for RSA-2048).
    """
    private_pem = Path(private_key_path).read_bytes()
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,  # SHA-256 length; matches device-side verifier
        ),
        hashes.SHA256(),
    )
    return signature


def _compute_crc32(data: bytes) -> int:
    """Compute CRC32 of data. Used to detect flash storage corruption."""
    return zlib.crc32(data) & 0xFFFFFFFF


def export_binary_manifest(
    signed_bundle: dict,
    private_key_path: Path = PRIVATE_KEY_PATH,
) -> bytes:
    """
    Convert a JSON signed bundle to a binary security_manifest_t struct.

    This is the main function. It:
      1. Extracts code_hash and data_hash from the bundle (hex → bytes)
      2. Builds the 102-byte signable payload (created_at included, v4)
      3. Signs the payload with the private key (RSA-PSS signature)
      4. Packs everything into the binary struct
      5. Appends CRC32 over the entire struct (excluding CRC field)

    Args:
        signed_bundle:    JSON signed bundle from signer.sign_manifest()
        private_key_path: Path to manufacturer private key PEM

    Returns:
        373-byte binary manifest ready to write to the drone's flash storage
    """
    manifest = signed_bundle["manifest"]

    # Extract and validate fields
    code_hash_hex = manifest["code_hash"] if "code_hash" in manifest else manifest["code_checksum"]
    data_hash_hex = manifest["data_hash"] if "data_hash" in manifest else manifest["data_checksum"]

    code_hash = binascii.unhexlify(code_hash_hex)
    data_hash = binascii.unhexlify(data_hash_hex)

    if len(code_hash) != HASH_LEN or len(data_hash) != HASH_LEN:
        raise ValueError(f"Hash must be {HASH_LEN} bytes (SHA-256)")

    board_id = int(manifest.get("board_id", 0))
    version  = manifest.get("firmware_version", "unknown")

    # Parse created_at timestamp
    created_at_str = manifest.get("generated_at", "")
    try:
        dt = datetime.fromisoformat(created_at_str)
        created_at = int(dt.timestamp())
    except (ValueError, OSError):
        created_at = 0

    # Build signable payload and sign it (v4: created_at is inside the signature)
    payload = _build_signable_payload(code_hash, data_hash, board_id, version, created_at)
    sig = _sign_binary_payload(payload, private_key_path)

    if len(sig) != SIG_MAX_LEN:
        raise ValueError(
            f"RSA-2048 signature must be exactly {SIG_MAX_LEN} bytes, got {len(sig)}."
        )

    sig_len = len(sig)

    # Encode version string
    version_bytes = version.encode("utf-8")[:VERSION_LEN-1]
    version_padded = version_bytes.ljust(VERSION_LEN, b"\x00")

    # Pack struct (all fields except crc32 — use 0 as placeholder)
    packed_without_crc = struct.pack(
        STRUCT_FORMAT,
        MAGIC,
        FORMAT_VERSION,
        code_hash,
        data_hash,
        sig,
        sig_len,
        board_id,
        version_padded,
        created_at,
        0,  # crc32 placeholder
    )

    assert len(packed_without_crc) == TOTAL_SIZE

    # Compute CRC32 over everything except the last 4 bytes (the CRC field)
    crc = _compute_crc32(packed_without_crc[:-4])

    # Replace placeholder with real CRC
    binary_manifest = packed_without_crc[:-4] + struct.pack("<I", crc)

    assert len(binary_manifest) == TOTAL_SIZE
    return binary_manifest


def verify_binary_manifest(binary_manifest: bytes, public_key_path: Path) -> bool:
    """
    Verify a binary manifest's CRC and RSA-PSS signature.

    This mirrors exactly what FirmwareIntegrityChecker.cpp does on the drone.
    Use this to verify a manifest before provisioning it onto a drone.

    Returns:
        True if CRC and signature are both valid
    """
    from cryptography.exceptions import InvalidSignature

    if len(binary_manifest) != TOTAL_SIZE:
        return False

    # Step 1: Verify CRC32 (storage integrity)
    stored_crc   = struct.unpack_from("<I", binary_manifest, TOTAL_SIZE - 4)[0]
    computed_crc = _compute_crc32(binary_manifest[:-4])
    if stored_crc != computed_crc:
        return False

    # Step 2: Unpack fields
    (magic, fmt_ver, code_hash, data_hash, sig_bytes, sig_len,
     board_id, version_padded, created_at, _) = struct.unpack(STRUCT_FORMAT, binary_manifest)

    if magic != MAGIC:
        return False

    # Step 3: Reconstruct signable payload (v4 includes created_at)
    version_str = version_padded.rstrip(b"\x00").decode("utf-8", errors="replace")
    payload = _build_signable_payload(code_hash, data_hash, board_id, version_str, created_at)

    # Step 4: Verify RSA-PSS signature
    sig = bytes(sig_bytes[:sig_len])
    public_pem = Path(public_key_path).read_bytes()
    public_key = serialization.load_pem_public_key(public_pem)

    try:
        public_key.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,  # SHA-256 length; matches device-side verifier
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def decode_binary_manifest(binary_manifest: bytes) -> dict:
    """
    Decode a 373-byte binary manifest back into a signed-bundle-shaped dict.

    The returned dict has the same shape export_binary_manifest() expects, so
    the caller can mutate one field (a hash or board_id) and feed it straight
    back into export_binary_manifest() to produce a *re-signed* variant. This
    is what the H14/H15 fixture helpers do
    (make_hash_mismatch_manifest.py, make_wrong_boardid_manifest.py).

    The input signature is intentionally NOT carried over — export re-signs the
    (possibly mutated) payload. created_at round-trips through the UTC unix
    timestamp so an unmutated decode→export reproduces the same created_at
    (the signature/CRC differ only because RSA-PSS uses a random salt).
    """
    if len(binary_manifest) != TOTAL_SIZE:
        raise ValueError(f"manifest must be {TOTAL_SIZE} bytes, got {len(binary_manifest)}")

    (magic, _fmt_ver, code_hash, data_hash, _sig, _sig_len,
     board_id, version_padded, created_at, _crc) = struct.unpack(STRUCT_FORMAT, binary_manifest)

    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}; not an {MAGIC.decode()} manifest")

    version_str  = version_padded.rstrip(b"\x00").decode("utf-8", errors="replace")
    generated_at = datetime.fromtimestamp(created_at, tz=timezone.utc).isoformat()

    return {
        "manifest": {
            "code_checksum":    binascii.hexlify(code_hash).decode("ascii"),
            "data_checksum":    binascii.hexlify(data_hash).decode("ascii"),
            "board_id":         int(board_id),
            "firmware_version": version_str,
            "generated_at":     generated_at,
        }
    }


def save_binary_manifest(binary_manifest: bytes, output_path: Path) -> None:
    """Write binary manifest to file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(binary_manifest)
    print(f"[OK] Binary manifest saved to: {output_path}")
    print(f"     Size: {len(binary_manifest)} bytes")


if __name__ == "__main__":
    import argparse
    import sys

    sys.path.insert(0, str(PROJECT_ROOT))
    from tools.signer.signer import load_signed_bundle

    parser = argparse.ArgumentParser(
        description="Convert a JSON signed bundle to a binary manifest for drone provisioning."
    )
    parser.add_argument("bundle", help="Path to signed_bundle.json (from signer.py)")
    parser.add_argument("--output", required=True, help="Output path for .bin manifest")
    parser.add_argument("--verify", action="store_true", help="Verify after export")
    args = parser.parse_args()

    bundle = load_signed_bundle(Path(args.bundle))
    binary = export_binary_manifest(bundle)
    save_binary_manifest(binary, Path(args.output))

    if args.verify:
        pubkey = PROJECT_ROOT / "pki" / "manufacturer" / "public" / "manufacturer_public.pem"
        valid = verify_binary_manifest(binary, pubkey)
        print(f"[{'OK' if valid else 'FAIL'}] Verification: {'passed' if valid else 'FAILED'}")
        if not valid:
            sys.exit(1)
