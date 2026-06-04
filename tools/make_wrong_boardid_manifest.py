"""
tools/make_wrong_boardid_manifest.py

Fixture helper for HARDWARE_ACCEPTANCE H15 (update-path board_id mismatch).

Takes a REAL, validly-signed binary manifest and rewrites board_id to a
DIFFERENT valid value, then re-signs the mutated payload with the
MANUFACTURER private key. Staged onto the SD as update_manifest.bin,
`secure_boot verify_update` rejects it with reason=4 (board_id mismatch) —
a SEPARATE reject enum from the POST reason=4 hash code (see SITL §14 Notes).
CRC and RSA-PSS signature both pass; only the board_id gate fails, against
the real STM32-derived board_id (SITL's board_id is synthetic, so this reject
code is hardware-only).

board_id is part of the signed payload, so — as with the hash helper — a raw
hex edit would fail at the signature check (reason=3). Re-signing with the
manufacturer key is what makes the board_id gate the failing check.

Default new board_id = 1064 (a valid-looking neighbour of the CubeOrange+
1063). The tool refuses a value equal to the compiled SECURE_BOOT_BOARD_ID
(1063) so the fixture cannot false-pass against the running target.

Output goes to .fixture_workdir/ (gitignored). Never commit fixtures.

Usage:
    py -3 tools/make_wrong_boardid_manifest.py \
        release/cubepilot_cubeorangeplus_default_manifest.bin \
        --output .fixture_workdir/wrong_boardid_update_manifest.bin

    py -3 tools/make_wrong_boardid_manifest.py \
        release/cubepilot_cubeorangeplus_default_manifest.bin \
        --board-id 9999 \
        --output .fixture_workdir/wrong_boardid_update_manifest.bin
"""

from __future__ import annotations

import argparse
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

# Compiled SECURE_BOOT_BOARD_ID on the CubeOrange+ bench unit (confirmed Day 1:
# bootloader flash log + firmware.prototype both report Board ID 1063). The
# device rejects any update manifest whose board_id != this value.
DEVICE_BOARD_ID = 1063
DEFAULT_WRONG_BOARD_ID = 1064


def make_wrong_boardid_manifest(input_manifest: bytes, new_board_id: int,
                                private_key_path: Path = PRIVATE_KEY_PATH,
                                public_key_path: Path = MFR_PUBLIC_KEY_PATH) -> bytes:
    """Produce a validly-signed manifest carrying a non-matching board_id.

    `public_key_path` is the key the input is verified against and the output
    is sanity-checked against (defaults to the manufacturer key; overridable
    for unit tests that use a throwaway keypair).
    Returns the 373-byte re-signed binary manifest.
    """
    if new_board_id == DEVICE_BOARD_ID:
        raise ValueError(
            f"new board_id {new_board_id} equals the device board_id "
            f"{DEVICE_BOARD_ID} — fixture would PASS, not reject. Pick another.")
    if not (0 <= new_board_id <= 0xFFFF):
        raise ValueError(f"board_id must fit a uint16 (0..65535), got {new_board_id}")

    # Input must be a real, currently-valid manufacturer-signed manifest.
    if not verify_binary_manifest(input_manifest, public_key_path):
        raise ValueError(
            "input manifest does not verify under the manufacturer public key — "
            "point this tool at the real provisioned manifest.bin (H2 output)")

    bundle = decode_binary_manifest(input_manifest)
    bundle["manifest"]["board_id"] = new_board_id

    out = export_binary_manifest(bundle, private_key_path=private_key_path)

    # Sanity guards — must be validly signed and actually carry the wrong id.
    out_m = decode_binary_manifest(out)["manifest"]
    if not verify_binary_manifest(out, public_key_path):
        raise RuntimeError("re-signed manifest does not verify — fixture broken")
    if out_m["board_id"] != new_board_id:
        raise RuntimeError("board_id did not take — fixture broken")
    if out_m["board_id"] == DEVICE_BOARD_ID:
        raise RuntimeError("board_id matches the device — fixture would not reject")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest", help="path to the real, validly-signed manifest.bin")
    ap.add_argument("--board-id", type=int, default=DEFAULT_WRONG_BOARD_ID,
                    help=f"wrong board_id to embed (default: {DEFAULT_WRONG_BOARD_ID}; "
                         f"must not equal device id {DEVICE_BOARD_ID})")
    ap.add_argument("--output", required=True, help="output path for the fixture .bin")
    ap.add_argument("--key", default=str(PRIVATE_KEY_PATH),
                    help="manufacturer private key (default: pki/manufacturer/private)")
    args = ap.parse_args()

    input_manifest = Path(args.manifest).read_bytes()
    out = make_wrong_boardid_manifest(input_manifest, args.board_id, Path(args.key))
    save_binary_manifest(out, Path(args.output))

    print(f"     board_id: {args.board_id} (device expects {DEVICE_BOARD_ID})  ->  "
          f"verify_update should REJECT with reason=4 (board_id mismatch)")
    print(f"     CRC + RSA-PSS signature valid; only the board_id gate fails.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
