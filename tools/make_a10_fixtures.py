"""
tools/make_a10_fixtures.py

ADR-023 staged-update fixture generator (Workstream A, step A-10).

Generates the SD-staging fixture set for SITL matrices and bench runs
(B9/B10/H16/H17) from a release-signed firmware: one GOOD staged update plus
the negative fixtures for every refusal path in the chain
(app-side FirmwareUpdateGatekeeper::applyUpdate → bootloader sd_update.c).

WHY a committed tool (vs the gitignored release/b9/ helpers):
  The B9-era helpers (extract_update.py / validate_update.py /
  make_a5_sitl_fixtures.py) proved the flow on the bench but live outside
  git. This tool is the durable, tested replacement: tests/compliance/
  test_ADR023_sd_update.py imports its reference implementations, so the
  host-side mirror of the device checks can never silently rot.

FIXTURE SET (out_dir):
  UPDATE.BIN            good staged image (raw signed .bin, TOC at 0x2a8)
  UPDATE.MTA            good meta sidecar (device contract, see bundler)
  UPDATE_TAMPERED.BIN   one byte flipped in the code region
                        -> app: IMAGE_HASH_MISMATCH (6); BL: sig REFUSED
  UPDATE_BADSIG.BIN     signature region zeroed
                        -> app: IMAGE_SIG_INVALID (7); BL: sig REFUSED
  UPDATE_ATTACKER.BIN   re-signed with a NON-manufacturer key
                        -> app: IMAGE_SIG_INVALID (7); BL: sig REFUSED
  UPDATE_TRUNC.BIN      truncated image (last 4 KB missing)
                        -> app: meta/file inconsistency (5/6); BL: TOC bounds
  UPDATE_BADMETA.MTA    meta with code_len/data_len shifted one word each way;
                        the contract invariants still hold, so ONLY the hash
                        binding vs the RSA-signed manifest catches it
                        -> app: IMAGE_HASH_MISMATCH (6). Proves the sidecar is
                        self-validating (the property ADR-023 relies on).
  attacker_public.pem   pubkey matching UPDATE_ATTACKER.BIN's signature, so a
                        bench log can prove the fixture is a REAL signature
                        that the device still refuses (key pinning, not luck).

Every fixture is validated on the host before being blessed: the good image
must pass the reference parse + RSA-PSS verify, each negative must fail in
exactly the intended way. Generation aborts otherwise.

USAGE:
  py -3 tools/make_a10_fixtures.py release/cubepilot_cubeorangeplus_default.px4 \
      release/cubepilot_cubeorangeplus_default.elf --out release/a10_fixtures/

The .px4 must be the pipeline-signed artifact (step 0 patches the BOOT001
image signature); an unsigned image is refused up front.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.bundler.bundler import build_update_artifacts
from tools.pki.keygen import generate_keypair
from tools.signer.toc_sign import (
    sign_image,
    verify_image,
    APP_LOAD_ADDRESS_DEFAULT,
    TOC_OFFSET_DEFAULT,
    TOC_START_MAGIC,
    TOC_END_MAGIC,
    TOC_ENTRY_SIZE,
    RSA_2048_SIG_LEN,
)

# Same budget the bootloader enforces (cubeorangeplus app flash: sectors 1-15).
FW_SIZE_MAX = 1920 * 1024

_ENTRIES_OFFSET = TOC_OFFSET_DEFAULT + 8  # first image_toc_entry_t after the TOC header


class StagedImageReject(ValueError):
    """The staged image would be REFUSED by the bootloader's parser."""


def parse_staged_image(raw: bytes) -> tuple[int, int]:
    """
    Reference implementation of the bootloader's staged-image TOC checks
    (sd_update.c pass-1). Returns (signed_len, image_size) on acceptance or
    raises StagedImageReject with the reason — the same rejects, in the same
    spirit, as the device. Kept byte-math-identical so host fixtures prove
    what the bench will do. Bench-validated by B9 (2026-07-09).
    """
    def fail(msg: str):
        raise StagedImageReject(msg)

    if len(raw) < _ENTRIES_OFFSET + 2 * TOC_ENTRY_SIZE + 4:
        fail("file too small for a TOC")
    # A blank/erased first word means there is no app stack pointer — the
    # bootloader refuses before doing any crypto.
    if struct.unpack_from("<I", raw, 0)[0] == 0xFFFFFFFF:
        fail("initial SP is 0xffffffff")
    magic, version = struct.unpack_from("<II", raw, TOC_OFFSET_DEFAULT)
    if magic != TOC_START_MAGIC or version > 1:
        fail(f"bad TOC magic/version ({magic:#010x}, v{version})")

    n = 0
    while struct.unpack_from("<I", raw, _ENTRIES_OFFSET + n * TOC_ENTRY_SIZE)[0] != TOC_END_MAGIC:
        n += 1
        if n > 32:
            fail("no TOC END magic within 32 entries")
        if _ENTRIES_OFFSET + (n + 1) * TOC_ENTRY_SIZE > len(raw):
            fail("TOC runs past end of file")
    if n < 2:
        fail("fewer than 2 TOC entries")
    toc_end_off = _ENTRIES_OFFSET + n * TOC_ENTRY_SIZE + 4

    def entry(i: int):
        off = _ENTRIES_OFFSET + i * TOC_ENTRY_SIZE
        start, end = struct.unpack_from("<II", raw, off + 4)
        sig_idx, sig_key, _enc_key, flags1 = struct.unpack_from("<BBBB", raw, off + 16)
        return start, end, sig_idx, sig_key, flags1

    b_start, b_end, sig_idx, sig_key, flags1 = entry(0)
    if not flags1 & 0x4:
        fail("entry 0 lacks CHECK_SIGNATURE flag")
    if b_start != APP_LOAD_ADDRESS_DEFAULT:
        fail(f"entry 0 start {b_start:#x} != APP_LOAD_ADDRESS")
    if sig_key != 0:
        # The TOC is attacker-controlled bytes; the key slot is PINNED to the
        # manufacturer slot on the device — honoring the field would let an
        # image pick its own trust anchor.
        fail(f"signature_key {sig_key} != 0 (manufacturer slot)")
    if sig_idx == 0 or sig_idx >= n:
        fail(f"signature_idx {sig_idx} out of range")
    s_start, s_end, _, _, _ = entry(sig_idx)
    if s_start != b_end or s_end - s_start != RSA_2048_SIG_LEN:
        fail("SIG region must directly follow BOOT and be 256 B")
    signed_len, image_size = b_end - b_start, s_end - b_start
    if signed_len <= toc_end_off:
        fail("TOC not inside the signed range")
    if image_size > FW_SIZE_MAX or image_size > len(raw):
        fail("image exceeds fw budget / file size")
    if signed_len % 4 or image_size % 4:
        fail("lengths not word-aligned")
    return signed_len, image_size


def verify_staged_signature(raw: bytes, public_key_pem: bytes) -> bool:
    """RSA-PSS check the bootloader performs before ANY erase (gate 2 of 3).
    Parse must have been done first; raises StagedImageReject on a bad TOC."""
    signed_len, _image_size = parse_staged_image(raw)

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    pub = serialization.load_pem_public_key(public_key_pem)
    try:
        pub.verify(
            raw[signed_len:signed_len + RSA_2048_SIG_LEN],
            raw[:signed_len],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def region_digests(raw: bytes, code_len: int, data_len: int,
                   chunk_size: int = 4096) -> tuple[str, str, str]:
    """
    Reference implementation of the app-side single streamed pass
    (FirmwareUpdateGatekeeper::applyUpdate, A-5): one sequential read, three
    SHA-256 contexts — code [0, code_len), data [code_len, code_len+data_len),
    signed range [0, code_len+data_len). Returns the three hex digests.

    Streaming (vs slicing) is the point: the device never holds the 1.8 MB
    image in RAM, so the offset math here is what the tests must prove
    equivalent to whole-buffer hashing.
    """
    signed_len = code_len + data_len
    regions = [
        (0, code_len, hashlib.sha256()),
        (code_len, signed_len, hashlib.sha256()),
        (0, signed_len, hashlib.sha256()),
    ]
    offset = 0
    while offset < len(raw):
        chunk = raw[offset:offset + chunk_size]
        for start, end, ctx in regions:
            lo = max(start, offset)
            hi = min(end, offset + len(chunk))
            if lo < hi:
                ctx.update(chunk[lo - offset:hi - offset])
        offset += len(chunk)
    return tuple(r[2].hexdigest() for r in regions)


def _write_meta(path: Path, meta: dict) -> None:
    # Trailing newline matches the bench-validated A-5 fixtures; the device's
    # key-scan parser accepts either.
    path.write_text(json.dumps(meta) + "\n")


def make_fixtures(
    px4_path: Path,
    elf_path: Path,
    out_dir: Path,
    public_key_path: Path,
    attacker_private_pem: bytes = None,
    log=print,
) -> dict:
    """
    Generate and host-validate the full fixture set. Returns {name: Path}.

    attacker_private_pem: PEM of a non-manufacturer RSA-2048 key for the
    wrong-key fixture. Generated ephemerally when omitted (its PUBLIC half is
    saved alongside the fixtures; the private half is deliberately dropped).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pub_pem = Path(public_key_path).read_bytes()

    image, meta = build_update_artifacts(px4_path, elf_path)
    code_len, data_len = meta["code_len"], meta["data_len"]
    signed_len = code_len + data_len

    written: dict = {}

    def bless(name: str, data: bytes, expect_parse_ok: bool, expect_sig_ok: bool = None):
        """Write a fixture only after proving it behaves as intended."""
        try:
            parse_staged_image(data)
            parse_ok = True
        except StagedImageReject as e:
            parse_ok = False
            reject_reason = e
        if parse_ok != expect_parse_ok:
            raise RuntimeError(f"{name}: parse_ok={parse_ok}, expected {expect_parse_ok}")
        if parse_ok and expect_sig_ok is not None:
            sig_ok = verify_staged_signature(data, pub_pem)
            if sig_ok != expect_sig_ok:
                raise RuntimeError(f"{name}: sig_ok={sig_ok}, expected {expect_sig_ok}")
        path = out_dir / name
        path.write_bytes(data)
        outcome = ("ACCEPT" if expect_sig_ok else "sig REFUSED") if parse_ok \
            else f"parse REFUSED ({reject_reason})"
        log(f"[OK] {name}: {len(data)} bytes -> {outcome}")
        written[name] = path

    # --- good staged update ---
    bless("UPDATE.BIN", image, expect_parse_ok=True, expect_sig_ok=True)
    _write_meta(out_dir / "UPDATE.MTA", meta)
    written["UPDATE.MTA"] = out_dir / "UPDATE.MTA"
    log(f"[OK] UPDATE.MTA: {meta}")

    # --- tampered code byte (signature untouched) ---
    tamper_off = code_len - 8
    assert tamper_off > _ENTRIES_OFFSET + 3 * TOC_ENTRY_SIZE, \
        "tamper offset must land in code, past the TOC"
    tampered = bytearray(image)
    tampered[tamper_off] ^= 0x01
    bless("UPDATE_TAMPERED.BIN", bytes(tampered),
          expect_parse_ok=True, expect_sig_ok=False)

    # --- zeroed signature (the pre-signing placeholder state) ---
    badsig = bytearray(image)
    badsig[signed_len:signed_len + RSA_2048_SIG_LEN] = b"\x00" * RSA_2048_SIG_LEN
    bless("UPDATE_BADSIG.BIN", bytes(badsig),
          expect_parse_ok=True, expect_sig_ok=False)

    # --- signed by a NON-manufacturer key ---
    if attacker_private_pem is None:
        attacker_private_pem, attacker_public_pem = generate_keypair()
    else:
        from cryptography.hazmat.primitives import serialization
        attacker_key = serialization.load_pem_private_key(attacker_private_pem, password=None)
        attacker_public_pem = attacker_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    attacker_signed = sign_image(image, attacker_private_pem)
    # Prove it's a REAL signature (valid under the attacker key) that the
    # manufacturer key still refuses — key pinning, not a malformed file.
    assert verify_image(attacker_signed, attacker_public_pem), \
        "attacker fixture must carry a valid signature under the attacker key"
    bless("UPDATE_ATTACKER.BIN", attacker_signed,
          expect_parse_ok=True, expect_sig_ok=False)
    (out_dir / "attacker_public.pem").write_bytes(attacker_public_pem)
    written["attacker_public.pem"] = out_dir / "attacker_public.pem"
    log(f"[OK] attacker_public.pem (private half discarded)")

    # --- truncated image (e.g. interrupted upload) ---
    bless("UPDATE_TRUNC.BIN", image[:-4096], expect_parse_ok=False)

    # --- self-validating meta: invariants hold, binding must catch it ---
    bad_meta = dict(meta)
    bad_meta["code_len"] = code_len + 4
    bad_meta["data_len"] = data_len - 4
    assert bad_meta["code_len"] + bad_meta["data_len"] == signed_len
    shifted_code, shifted_data, _ = region_digests(
        image, bad_meta["code_len"], bad_meta["data_len"])
    true_code, true_data, _ = region_digests(image, code_len, data_len)
    assert shifted_code != true_code and shifted_data != true_data, \
        "shifted split must change the region digests, or the fixture is useless"
    _write_meta(out_dir / "UPDATE_BADMETA.MTA", bad_meta)
    written["UPDATE_BADMETA.MTA"] = out_dir / "UPDATE_BADMETA.MTA"
    log(f"[OK] UPDATE_BADMETA.MTA: split shifted +4/-4 (invariants hold, binding fails)")

    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate ADR-023 staged-update fixtures (good + negatives) "
                    "from a pipeline-signed firmware."
    )
    parser.add_argument("px4_file", type=Path,
                        help="pipeline-signed .px4 (BOOT001 image signature patched)")
    parser.add_argument("elf_file", type=Path, help="matching firmware ELF")
    parser.add_argument("--out", type=Path, default=Path("release") / "a10_fixtures",
                        help="output directory (default: release/a10_fixtures/)")
    parser.add_argument(
        "--public-key", type=Path,
        default=PROJECT_ROOT / "pki" / "manufacturer" / "public" / "manufacturer_public.pem",
        help="manufacturer public key used to host-validate the fixtures",
    )
    parser.add_argument("--attacker-key", type=Path, default=None,
                        help="private PEM for the wrong-key fixture "
                             "(default: ephemeral keypair)")
    args = parser.parse_args(argv)

    for p in (args.px4_file, args.elf_file, args.public_key):
        if not p.exists():
            print(f"[ERROR] not found: {p}", file=sys.stderr)
            return 1

    attacker_pem = args.attacker_key.read_bytes() if args.attacker_key else None
    try:
        written = make_fixtures(
            args.px4_file, args.elf_file, args.out, args.public_key,
            attacker_private_pem=attacker_pem,
        )
    except (ValueError, RuntimeError) as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        return 1
    print(f"\n[DONE] {len(written)} fixtures in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
