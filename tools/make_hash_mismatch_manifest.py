"""
tools/make_hash_mismatch_manifest.py

Fixture helper for HARDWARE_ACCEPTANCE H14 (organic code_hash / data_hash
mismatch — the Tier 1 "prize" that SITL structurally cannot run).

Takes a REAL, validly-signed binary manifest (the one provisioned to the
board in H2), swaps the code_hash OR the data_hash to a deliberately-wrong
value, then re-signs the mutated payload with the MANUFACTURER private key.
The output has a valid CRC and a valid RSA-PSS signature, so on-device POST
passes the CRC check (reason=2) and the signature check (reason=3) and
reaches the hash comparison:

    --mutate code  ->  code_hash wrong               ->  POST FAILED reason=4
    --mutate data  ->  code_hash kept correct,
                       data_hash wrong               ->  POST FAILED reason=5

Reason=5 isolation matters: POST checks code_hash *before* data_hash, so to
land on reason=5 the manifest must carry the CORRECT code_hash and only a
wrong data_hash — which also re-confirms the code->data ordering on real
silicon.

WHY re-sign instead of hex-editing the hash field:
    code_hash and data_hash are inside the signed payload. A raw hex edit
    would fail at the *signature* check (reason=3) and never reach the hash
    comparison. To land on reason=4/5 the manifest must be VALIDLY SIGNED but
    carry a wrong hash. Only the manufacturer key can do that — exactly the
    property POST proves.

The wrong hash is the real hash with its first byte flipped (XOR 0xFF). That
guarantees it differs from the live-flash hash, so the fixture cannot
false-pass by accidentally matching the running firmware (the cross-hash
sanity guard HARDWARE_ACCEPTANCE asks for).

Output goes to .fixture_workdir/ (gitignored). Never commit fixtures.

Usage:
    py -3 tools/make_hash_mismatch_manifest.py \
        release/cubepilot_cubeorangeplus_default_manifest.bin \
        --mutate code \
        --output .fixture_workdir/wrong_code_manifest.bin

    py -3 tools/make_hash_mismatch_manifest.py \
        release/cubepilot_cubeorangeplus_default_manifest.bin \
        --mutate data \
        --output .fixture_workdir/wrong_data_manifest.bin
"""

from __future__ import annotations

import argparse
import binascii
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.provisioning.export_manifest import (
    PRIVATE_KEY_PATH,
    decode_binary_manifest,
    export_binary_manifest,
    save_binary_manifest,
    verify_binary_manifest,
)

MFR_PUBLIC_KEY_PATH = REPO_ROOT / "pki" / "manufacturer" / "public" / "manufacturer_public.pem"


def _flip_first_byte(hex_hash: str) -> str:
    """Flip the first byte of a hex SHA-256 (XOR 0xFF) — deterministic, and
    guaranteed to differ from the original (and thus from the live flash)."""
    raw = bytearray(binascii.unhexlify(hex_hash))
    raw[0] ^= 0xFF
    return binascii.hexlify(bytes(raw)).decode("ascii")


def make_hash_mismatch_manifest(input_manifest: bytes, mutate: str,
                                private_key_path: Path = PRIVATE_KEY_PATH,
                                public_key_path: Path = MFR_PUBLIC_KEY_PATH) -> bytes:
    """Produce a validly-signed manifest with a wrong code_hash or data_hash.

    `mutate` is "code" (-> POST reason=4) or "data" (-> POST reason=5).
    `public_key_path` is the key the input is verified against and the output
    is sanity-checked against (defaults to the manufacturer key; overridable
    for unit tests that use a throwaway keypair).
    Returns the 373-byte re-signed binary manifest.
    """
    if mutate not in ("code", "data"):
        raise ValueError(f"mutate must be 'code' or 'data', got {mutate!r}")

    # Input must be a real, currently-valid manufacturer-signed manifest —
    # otherwise we'd be mutating garbage and the bench result would be
    # meaningless. Fail loud if the operator points us at a stale/wrong file.
    if not verify_binary_manifest(input_manifest, public_key_path):
        raise ValueError(
            "input manifest does not verify under the manufacturer public key — "
            "point this tool at the real provisioned manifest.bin (H2 output)")

    bundle = decode_binary_manifest(input_manifest)
    m = bundle["manifest"]

    orig_code = m["code_checksum"]
    orig_data = m["data_checksum"]

    if mutate == "code":
        m["code_checksum"] = _flip_first_byte(orig_code)
    else:  # data: keep code correct so POST reaches the data check (reason=5)
        m["data_checksum"] = _flip_first_byte(orig_data)

    out = export_binary_manifest(bundle, private_key_path=private_key_path)

    # Sanity guards — a buggy fixture must never false-pass on the bench.
    out_bundle = decode_binary_manifest(out)["manifest"]
    if not verify_binary_manifest(out, public_key_path):
        raise RuntimeError("re-signed manifest does not verify — fixture broken")
    if mutate == "code":
        if out_bundle["code_checksum"] == orig_code:
            raise RuntimeError("code_hash unchanged — fixture would not trip reason=4")
    else:
        if out_bundle["data_checksum"] == orig_data:
            raise RuntimeError("data_hash unchanged — fixture would not trip reason=5")
        if out_bundle["code_checksum"] != orig_code:
            raise RuntimeError("code_hash drifted — reason=5 would collapse to reason=4")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", help="path to the real, validly-signed manifest.bin")
    ap.add_argument("--mutate", required=True, choices=("code", "data"),
                    help="code -> POST reason=4; data -> POST reason=5")
    ap.add_argument("--output", required=True, help="output path for the fixture .bin")
    ap.add_argument("--key", default=str(PRIVATE_KEY_PATH),
                    help="manufacturer private key (default: pki/manufacturer/private)")
    args = ap.parse_args()

    input_manifest = Path(args.manifest).read_bytes()
    out = make_hash_mismatch_manifest(input_manifest, args.mutate, Path(args.key))
    save_binary_manifest(out, Path(args.output))

    expect = "reason=4 (code hash mismatch)" if args.mutate == "code" \
        else "reason=5 (data hash mismatch)"
    print(f"     mutated: {args.mutate}_hash  ->  POST should FAIL with {expect}")
    print(f"     CRC + RSA-PSS signature valid; only the hash comparison fails.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
