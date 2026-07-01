"""
tools/signer/sign_bootloader.py

BOOT008 (T11-H) CLI: sign the secure bootloader .bin so on-device `bl_update`
verifies it before erasing sector 0.

This is a thin wrapper over pipeline.sign_bootloader_image(); the real work
lives there (and is unit-tested). Use it as a manufacturing one-liner after
building the `cubepilot_cubeorangeplus_bootloader` target:

    python tools/signer/sign_bootloader.py \
        ~/PX4-Autopilot/build/cubepilot_cubeorangeplus_bootloader/cubepilot_cubeorangeplus_bootloader.bin \
        boards/cubepilot/cubeorangeplus/bootloader_artifact/cubepilot_cubeorangeplus_bootloader.bin

The bootloader must be a fresh BOOT008 build (it now compiles bl_toc.c and
carries an image TOC). Signing the pre-BOOT008 artifact fails loudly — rebuild
first, never sign the stale .bin in place.
"""

import argparse
import sys
from pathlib import Path

# Allow running as a script (python tools/signer/sign_bootloader.py ...).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.pipeline import sign_bootloader_image, PRIVATE_KEY, PUBLIC_KEY


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign the CubeOrange+ secure bootloader .bin (BOOT008 / T11-H)."
    )
    parser.add_argument("input_bin", type=Path, help="freshly built bootloader .bin (with image TOC)")
    parser.add_argument(
        "output_bin",
        type=Path,
        nargs="?",
        default=None,
        help="signed .bin to emit (default: overwrite input_bin in place)",
    )
    parser.add_argument("--key", type=Path, default=PRIVATE_KEY, help="manufacturer private key (PEM)")
    parser.add_argument("--public-key", type=Path, default=PUBLIC_KEY, help="manufacturer public key (PEM)")
    args = parser.parse_args(argv)

    if not args.input_bin.exists():
        print(f"[ERROR] input not found: {args.input_bin}", file=sys.stderr)
        return 1
    if not args.key.exists():
        print(f"[ERROR] private key not found: {args.key}", file=sys.stderr)
        return 1

    output = args.output_bin or args.input_bin
    print(f"Signing bootloader {args.input_bin.name} ({args.input_bin.stat().st_size} bytes)")
    try:
        sign_bootloader_image(
            bin_path=args.input_bin,
            private_key_path=args.key,
            public_key_path=args.public_key,
            output_path=output,
            log=print,
        )
    except RuntimeError as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 1
    print(f"[OK] wrote signed bootloader -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
