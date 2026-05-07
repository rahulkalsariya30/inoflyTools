"""
tools/signer/toc_sign.py

TOC-aware firmware signer for the BOOT001 verifying bootloader (Phase 5b.2c).

WHY this exists, separate from signer.py
----------------------------------------
signer.py produces a JSON bundle (manifest + base64 RSA-PSS signature) for the
app-firmware POST flow (LOG001 / CHK001). That bundle is what the running app
verifies against its in-memory checksums.

The verifying bootloader is a different consumer with different needs:
  - It cannot parse JSON (no allocator, no parser, 128 KB code budget).
  - It needs the signature to live AT a fixed flash offset declared by the
    image's Table of Contents, so it can locate it via find_toc().
  - It uses a saltlen=32 RSA-PSS verifier (matches what libtomcrypt does in
    the bootloader, and matches the project-wide saltlen=32 convention used
    by signer.py, export_manifest.py, and the QGC verifier).

So this tool is a separate post-build pass: take the linker-produced .bin,
locate the TOC, hash the BOOT region, RSA-PSS sign with saltlen=32, and
patch the signature into the SIG region in place.

WHAT IT EXPECTS
---------------
A raw flash image (.bin produced by `arm-none-eabi-objcopy -O binary`) of the
CubeOrange+ app firmware, where:
  - Byte 0 of the .bin == address APP_LOAD_ADDRESS in flash (0x08020000).
  - Offset BOOT_DELAY_ADDRESS+8 (0x2a8) holds image_toc_start_t followed by
    image_toc_entry_t records and a TOC_END_MAGIC sentinel.
  - The TOC's entry[0] is the BOOT region (signed range), entry[1] is the
    SIG region (a 256-byte zero-filled placeholder reserved by script.ld).

Layout constants and struct field offsets are defined to match
src/include/image_toc.h in the PX4 fork. Keep these in sync if the C struct
ever changes.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# --- Constants matching ~/PX4-Autopilot/src/include/image_toc.h ---
# Magic values are little-endian; the C side declares them as uint32_t.
TOC_START_MAGIC = 0x00434F54  # "TOC\0"
TOC_END_MAGIC = 0x00444E45    # "END\0"

# Layout: sizeof(image_toc_start_t) = 8 bytes (magic + version, both u32).
TOC_START_SIZE = 8

# Layout: image_toc_entry_t is __packed__:
#   char name[4] + 3*void* + 4*u8 + u32 = 4 + 12 + 4 + 4 = 24 bytes on ARM32.
TOC_ENTRY_SIZE = 24
TOC_ENTRY_FMT = "<4sIII4BI"  # name, start, end, target, sigidx, sigkey, enckey, flags1, reserved

# Per CubeOrange+ hw_config.h. If you ever port to another STM32H7 board with a
# different APP_LOAD_ADDRESS, pass --app-load-address on the CLI.
APP_LOAD_ADDRESS_DEFAULT = 0x08020000
# BOOT_DELAY_ADDRESS is 0x2A0 (not the documented 0x1A0) on STM32H7: the M7's
# vector table is 16 system + ~150 IRQ entries × 4 = ~0x298 bytes, so the
# bootdelay slot lands at 0x2A0 after ALIGN(32) and the TOC sits 8 bytes
# later. Matches BOOT_DELAY_ADDRESS in the cubeorangeplus hw_config.h.
BOOT_DELAY_ADDRESS_DEFAULT = 0x000002A0
TOC_OFFSET_DEFAULT = BOOT_DELAY_ADDRESS_DEFAULT + 8  # 0x2A8

# RSA-2048 PSS produces a 256-byte signature. Salt length = 32 bytes (SHA-256
# digest length) — the project-wide convention shared by every signer and
# verifier in the system: signer.py (JSON bundle), export_manifest.py
# (provisioning), the device-side FirmwareIntegrityChecker (OpenSSL on SITL
# and libtomcrypt on hardware — see crypto.c in the PX4 fork), and the QGC
# BCrypt verifier. A saltlen mismatch silently fails verification on the
# device, so do NOT change this without changing every consumer.
RSA_PSS_SALT_LEN = 32
RSA_2048_SIG_LEN = 256


class TocParseError(RuntimeError):
    """Raised when the .bin's TOC layout doesn't match what we expect."""


def find_toc(bin_data: bytes, toc_offset: int) -> tuple[int, list[dict]]:
    """
    Locate and parse the TOC at the expected offset within the .bin.

    Returns (entry_count, entries) where entries is a list of dicts with the
    parsed fields. We don't preserve the raw bytes for entries — the signer
    only mutates the SIG region of the .bin, never the TOC itself.
    """
    if len(bin_data) < toc_offset + TOC_START_SIZE:
        raise TocParseError(
            f".bin is only {len(bin_data)} bytes — too small to hold a TOC at offset {toc_offset:#x}"
        )

    magic, version = struct.unpack_from("<II", bin_data, toc_offset)
    if magic != TOC_START_MAGIC:
        raise TocParseError(
            f"TOC_START_MAGIC mismatch at offset {toc_offset:#x}: got {magic:#010x}, expected {TOC_START_MAGIC:#010x}. "
            f"Is this the right .bin? Did the linker emit *(.main_toc) at the right place?"
        )

    entries: list[dict] = []
    cursor = toc_offset + TOC_START_SIZE
    # Walk entries until we hit TOC_END_MAGIC. The bootloader caps at 32; we
    # use a smaller sanity bound to avoid runaway parsing on a corrupt image.
    for _ in range(64):
        if cursor + 4 > len(bin_data):
            raise TocParseError("ran off end of .bin while scanning TOC entries")
        # The end sentinel is just a u32 — *not* a full 24-byte entry. We peek
        # the first 4 bytes; if they match TOC_END_MAGIC we stop.
        peek = struct.unpack_from("<I", bin_data, cursor)[0]
        if peek == TOC_END_MAGIC:
            return len(entries), entries
        if cursor + TOC_ENTRY_SIZE > len(bin_data):
            raise TocParseError("TOC entry would extend past end of .bin")
        name, start, end, target, sigidx, sigkey, enckey, flags1, reserved = struct.unpack_from(
            TOC_ENTRY_FMT, bin_data, cursor
        )
        entries.append({
            "name": name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "start": start,
            "end": end,
            "target": target,
            "signature_idx": sigidx,
            "signature_key": sigkey,
            "encryption_key": enckey,
            "flags1": flags1,
            "reserved": reserved,
        })
        cursor += TOC_ENTRY_SIZE
    raise TocParseError("TOC has too many entries — likely corrupt or wrong file")


def sign_image(
    bin_data: bytes,
    private_key_pem: bytes,
    app_load_address: int = APP_LOAD_ADDRESS_DEFAULT,
    toc_offset: int = TOC_OFFSET_DEFAULT,
) -> bytes:
    """
    Produce a signed copy of bin_data.

    Steps:
      1. Parse the TOC; pick entry[0] as the BOOT region and entry[entry[0].signature_idx] as SIG.
      2. SHA-256 the BOOT region. (libtomcrypt on the device hashes the same range.)
      3. RSA-PSS sign with saltlen=32. (Must match the verifier.)
      4. Patch the signature into the SIG region's offset in the .bin.

    The signature region in the unsigned build is 256 zero bytes reserved by
    the linker — patching does not change file size.
    """
    _entry_count, entries = find_toc(bin_data, toc_offset)
    if not entries:
        raise TocParseError("TOC is empty — no entries to sign")

    boot = entries[0]
    sig_idx = boot["signature_idx"]
    if sig_idx == 0 or sig_idx >= len(entries):
        raise TocParseError(
            f"BOOT entry's signature_idx={sig_idx} is out of range for {len(entries)} TOC entries"
        )
    sig = entries[sig_idx]

    # Convert flash addresses to .bin offsets. The .bin is APP_LOAD_ADDRESS-relative.
    boot_off_lo = boot["start"] - app_load_address
    boot_off_hi = boot["end"] - app_load_address
    sig_off_lo = sig["start"] - app_load_address
    sig_off_hi = sig["end"] - app_load_address

    if not (0 <= boot_off_lo < boot_off_hi <= len(bin_data)):
        raise TocParseError(
            f"BOOT region [{boot_off_lo:#x}..{boot_off_hi:#x}] is outside the .bin (len {len(bin_data):#x})"
        )
    if not (boot_off_hi <= sig_off_lo < sig_off_hi <= len(bin_data)):
        raise TocParseError(
            f"SIG region [{sig_off_lo:#x}..{sig_off_hi:#x}] does not follow BOOT region or extends past .bin"
        )
    sig_region_len = sig_off_hi - sig_off_lo
    if sig_region_len != RSA_2048_SIG_LEN:
        raise TocParseError(
            f"SIG region is {sig_region_len} bytes but RSA-2048 PSS signature is exactly {RSA_2048_SIG_LEN}"
        )

    # The signer must NOT include the placeholder bytes in the hashed range, or
    # signing changes the hash and the bootloader will fail. By construction,
    # the BOOT region ends at &_app_signature[0] (sig.start), so it never
    # includes the SIG region. Enforce it loudly.
    assert boot_off_hi == sig_off_lo, "BOOT region must end exactly where SIG region starts"

    boot_bytes = bin_data[boot_off_lo:boot_off_hi]
    digest = hashlib.sha256(boot_bytes).digest()
    print(f"  BOOT region: bin[{boot_off_lo:#x} .. {boot_off_hi:#x}] = {len(boot_bytes)} bytes")
    print(f"  SHA-256:     {digest.hex()}")

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        boot_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=RSA_PSS_SALT_LEN,
        ),
        hashes.SHA256(),
    )
    if len(signature) != RSA_2048_SIG_LEN:
        raise RuntimeError(
            f"Expected {RSA_2048_SIG_LEN}-byte signature, got {len(signature)} — wrong key size?"
        )

    signed = bytearray(bin_data)
    signed[sig_off_lo:sig_off_hi] = signature
    print(f"  Patched {len(signature)} signature bytes at bin[{sig_off_lo:#x}]")
    return bytes(signed)


def verify_image(
    bin_data: bytes,
    public_key_pem: bytes,
    app_load_address: int = APP_LOAD_ADDRESS_DEFAULT,
    toc_offset: int = TOC_OFFSET_DEFAULT,
) -> bool:
    """
    Verify a signed .bin offline (sanity check before flashing). Returns True
    only if the signature in the SIG region validates over the BOOT region
    under the provided public key. This does the same RSA-PSS-saltlen=32 dance
    the bootloader does, so a True here ≈ "device will accept this firmware".
    """
    from cryptography.exceptions import InvalidSignature

    _entry_count, entries = find_toc(bin_data, toc_offset)
    boot = entries[0]
    sig = entries[boot["signature_idx"]]

    boot_off_lo = boot["start"] - app_load_address
    boot_off_hi = boot["end"] - app_load_address
    sig_off_lo = sig["start"] - app_load_address
    sig_off_hi = sig["end"] - app_load_address

    boot_bytes = bin_data[boot_off_lo:boot_off_hi]
    sig_bytes = bin_data[sig_off_lo:sig_off_hi]

    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            sig_bytes,
            boot_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=RSA_PSS_SALT_LEN,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign a CubeOrange+ app firmware .bin with RSA-PSS via the image TOC."
    )
    parser.add_argument("input_bin", type=Path, help="unsigned firmware .bin (from objcopy)")
    parser.add_argument("output_bin", type=Path, help="signed firmware .bin to emit")
    parser.add_argument(
        "--key",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "pki" / "manufacturer" / "private" / "manufacturer_private.pem",
        help="RSA-2048 manufacturer private key (PEM)",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "pki" / "manufacturer" / "public" / "manufacturer_public.pem",
        help="manufacturer public key (PEM) — used for the post-sign sanity verify",
    )
    parser.add_argument("--app-load-address", type=lambda s: int(s, 0), default=APP_LOAD_ADDRESS_DEFAULT)
    parser.add_argument("--toc-offset", type=lambda s: int(s, 0), default=TOC_OFFSET_DEFAULT)
    parser.add_argument("--no-verify", action="store_true", help="skip the post-sign sanity verification")
    args = parser.parse_args(argv)

    if not args.input_bin.exists():
        print(f"[ERROR] input not found: {args.input_bin}", file=sys.stderr)
        return 1
    if not args.key.exists():
        print(f"[ERROR] private key not found: {args.key}", file=sys.stderr)
        return 1

    bin_data = args.input_bin.read_bytes()
    private_key_pem = args.key.read_bytes()

    print(f"Signing {args.input_bin.name} ({len(bin_data)} bytes)")
    signed = sign_image(
        bin_data,
        private_key_pem,
        app_load_address=args.app_load_address,
        toc_offset=args.toc_offset,
    )
    args.output_bin.parent.mkdir(parents=True, exist_ok=True)
    args.output_bin.write_bytes(signed)
    print(f"[OK] wrote {args.output_bin}")

    if not args.no_verify:
        if not args.public_key.exists():
            print(f"[WARN] public key not found at {args.public_key} — skipping verify", file=sys.stderr)
            return 0
        public_key_pem = args.public_key.read_bytes()
        ok = verify_image(
            signed,
            public_key_pem,
            app_load_address=args.app_load_address,
            toc_offset=args.toc_offset,
        )
        print(f"[{'OK' if ok else 'FAIL'}] post-sign verify: {'passed' if ok else 'FAILED'}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
