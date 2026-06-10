"""
tools/pipeline.py

Firmware Release Pipeline
Chains the full manufacturer workflow: checksum → sign → bundle → export binary manifest

WHY this exists:
  Running 5 tools manually is error-prone. One missed step or wrong path
  means an unsigned or unverified bundle reaches a drone. This script
  enforces the correct order and verifies at every stage.

  Also reusable as a library: CI/CD and QGC plugin can import run_pipeline()
  instead of shelling out to individual tools.

USAGE (SITL):
  python tools/pipeline.py firmware.px4 --output-dir release/

USAGE (Hardware — CubeOrange+):
  # ADR-018: pass the firmware ELF directly. The host hashes the same FLASH
  # byte ranges the FC POST does (between _stext and _compliance_params_*).
  python tools/pipeline.py firmware.px4 --board-id 1063 \\
      --elf build/.../cubepilot_cubeorangeplus_default.elf --version 1.0.0

  # The legacy --code-bin/--data-bin two-file flow still works (with a
  # DeprecationWarning) but cannot reproduce the FC byte ranges.
"""

import base64
import json
import shutil
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.checksum.checksum import generate_manifest
from tools.signer.signer import sign_manifest, verify_bundle
from tools.bundler.bundler import create_bundle, verify_bundle as verify_fwbundle
from tools.provisioning.export_manifest import (
    export_binary_manifest,
    verify_binary_manifest,
    save_binary_manifest,
)
from tools.signer.toc_sign import (
    sign_image as _sign_boot_region,
    verify_image as _verify_boot_region,
    find_toc as _find_image_toc,
    TocParseError,
    TOC_OFFSET_DEFAULT,
)

# Default key paths
PKI_DIR = PROJECT_ROOT / "pki" / "manufacturer"
PRIVATE_KEY = PKI_DIR / "private" / "manufacturer_private.pem"
PUBLIC_KEY  = PKI_DIR / "public"  / "manufacturer_public.pem"


@dataclass
class PipelineResult:
    """Everything produced by a pipeline run."""
    manifest: dict
    signed_bundle: dict
    fwbundle_path: Path
    firmware_path: Path
    binary_manifest_path: Path
    all_verified: bool
    # True if the BOOT001 image signature was patched into firmware_path; False
    # for SITL / non-secure images (no image TOC -> nothing for the bootloader
    # to verify, so signing is correctly skipped).
    bootloader_image_signed: bool = False


def sign_px4_bootloader_image(
    px4_path: Path,
    private_key_path: Path,
    public_key_path: Path,
    output_path: Path,
    log=lambda _m: None,
) -> Path | None:
    """
    BOOT001: patch the RSA-PSS *image* signature into a hardware .px4.

    Separate from the manifest signature (SIG001). The verifying bootloader
    RSA-PSS-verifies the app-fw image against the manufacturer pubkey *before*
    handing off; that signature lives in the image's `.app_signature` region,
    located via the image TOC. A normally-built .px4 carries a 256-byte ZERO
    placeholder there — so without this step the bootloader rejects the image
    fail-closed and the unit will not boot (this is the gap the 2026-06-09
    bootloader review found).

    Decompresses the .px4 image, signs the BOOT region (SHA-256 + RSA-PSS
    saltlen=32 — identical to what the device's libtomcrypt verifier does),
    re-wraps with the same zlib(level 9)+base64 encoding px_mkfw uses, and
    writes `output_path`.

    Returns `output_path` on success, or **None** if the image has no TOC —
    i.e. a SITL or non-secure build. That is NOT an error: such images are
    never verified by a bootloader, so there is nothing to sign.

    The `.app_signature` region sits after `.compliance_params` in the image,
    outside both the POST `code_hash` and `data_hash` ranges, so signing here
    does not change the manifest checksums computed downstream.
    """
    desc = json.loads(Path(px4_path).read_text())
    if "image" not in desc:
        return None

    image = zlib.decompress(base64.b64decode(desc["image"]))

    # No image TOC => SITL / non-secure build => nothing for the bootloader to
    # verify. Skip silently (caller logs it); do not treat as an error.
    try:
        _find_image_toc(image, TOC_OFFSET_DEFAULT)
    except TocParseError:
        return None

    signed = _sign_boot_region(image, Path(private_key_path).read_bytes())

    # Fail-fast: the device bootloader would reject a bad signature, so prove
    # it verifies here rather than discovering it on the bench.
    if not _verify_boot_region(signed, Path(public_key_path).read_bytes()):
        raise RuntimeError("BOOT001 image signature failed its post-sign verify")

    desc["image_size"] = len(signed)
    desc["image"] = base64.b64encode(zlib.compress(signed, 9)).decode("utf-8")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(desc, indent=4))
    return output_path


def run_pipeline(
    px4_path: Path,
    output_dir: Path,
    firmware_version: str = "",
    board_id: int = None,
    elf_path: Path = None,
    code_bin_path: Path = None,
    data_bin_path: Path = None,
    private_key_path: Path = PRIVATE_KEY,
    public_key_path: Path = PUBLIC_KEY,
    sign_bootloader_image: bool = True,
    verbose: bool = True,
) -> PipelineResult:
    """
    Run the full firmware release pipeline.

    Steps:
      0. BOOT001 — patch the RSA-PSS image signature into the .px4 (hardware
         secure images only; SITL/non-secure images have no TOC and are skipped)
      1. CHK001 — compute SHA-256 checksums (code + data)
      2. SIG001 — sign manifest with manufacturer key
      3. Verify — confirm signature is valid before proceeding
      4. PKG001 — package into .fwbundle
      5. Verify — confirm bundle signature
      6. PRV001 — export binary manifest (501 bytes)
      7. Verify — confirm binary manifest CRC + signature

    Args:
        px4_path:         Path to the .px4 firmware file
        output_dir:       Directory for all output files
        firmware_version: Override version string (default: read from .px4)
        board_id:         Override board ID (default: read from .px4)
        elf_path:         Path to firmware ELF (hardware mode, ADR-018)
        code_bin_path:    DEPRECATED: extracted .text section binary
        data_bin_path:    DEPRECATED: extracted .data section binary
        private_key_path: Manufacturer private key
        public_key_path:  Manufacturer public key
        verbose:          Print progress to stdout

    Returns:
        PipelineResult with paths to all generated artifacts

    Raises:
        FileNotFoundError: If firmware or keys are missing
        RuntimeError: If any verification step fails
    """
    px4_path = Path(px4_path)
    output_dir = Path(output_dir)

    if not px4_path.exists():
        raise FileNotFoundError(f"Firmware not found: {px4_path}")
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key not found: {public_key_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = px4_path.stem  # e.g. "px4_fmu-v5_default"

    def log(msg: str):
        if verbose:
            print(msg)

    # Step 0: BOOT001 image signature (hardware secure images only).
    # The verifying bootloader rejects an unsigned image fail-closed, so the
    # signed .px4 must be the artifact everything downstream (manifest, bundle,
    # final copy) is built from. SITL / non-secure images have no image TOC and
    # are passed through untouched. Rebinding px4_path keeps the rest of the
    # pipeline unchanged.
    bootloader_image_signed = False
    if sign_bootloader_image:
        log(f"[0/7] Signing BOOT001 image (RSA-PSS over app-fw region)...")
        signed_px4 = sign_px4_bootloader_image(
            px4_path, private_key_path, public_key_path,
            output_dir / f"{stem}.px4", log=log,
        )
        if signed_px4 is not None:
            px4_path = signed_px4  # downstream manifest/bundle/copy use the signed image
            bootloader_image_signed = True
            log(f"      Signed image written: {signed_px4}")
        else:
            log(f"      No image TOC — SITL/non-secure build, skipping (not an error)")

    # Step 1: Checksums
    if elf_path:
        mode = "hardware (ELF — FC POST byte ranges)"
    elif code_bin_path:
        mode = "hardware (DEPRECATED two-file)"
    else:
        mode = "SITL (.px4 image)"
    log(f"[1/7] Computing SHA-256 checksums [{mode}]...")
    manifest = generate_manifest(
        px4_path,
        firmware_version=firmware_version,
        board_id=board_id,
        elf_path=elf_path,
        code_bin_path=code_bin_path,
        data_bin_path=data_bin_path,
    )
    log(f"      Code: {manifest['code_checksum'][:16]}...")
    log(f"      Data: {manifest['data_checksum'][:16]}...")

    # Save manifest for audit trail
    manifest_path = output_dir / f"{stem}_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=4)

    # Step 2: Sign
    log(f"[2/7] Signing manifest with manufacturer key...")
    signed_bundle = sign_manifest(manifest, private_key_path=private_key_path)
    log(f"      Signature: {signed_bundle['signature'][:24]}...")

    # Save signed bundle for audit trail
    signed_path = output_dir / f"{stem}_signed.json"
    with open(signed_path, "w") as f:
        json.dump(signed_bundle, f, indent=4)

    # Step 3: Verify signature
    log(f"[3/7] Verifying manifest signature...")
    if not verify_bundle(signed_bundle, public_key_path=public_key_path):
        raise RuntimeError("SIGNATURE VERIFICATION FAILED — aborting pipeline")
    log(f"      Signature valid")

    # Step 4: Bundle
    fwbundle_path = output_dir / f"{stem}.fwbundle"
    log(f"[4/7] Packaging .fwbundle...")
    create_bundle(px4_path, signed_bundle, fwbundle_path)

    # Step 5: Verify bundle
    log(f"[5/7] Verifying .fwbundle signature...")
    if not verify_fwbundle(fwbundle_path, public_key_path=public_key_path):
        raise RuntimeError("BUNDLE VERIFICATION FAILED — aborting pipeline")
    log(f"      Bundle valid")

    # Step 6: Binary manifest
    binary_manifest_path = output_dir / f"{stem}_manifest.bin"
    log(f"[6/7] Exporting binary manifest...")
    binary = export_binary_manifest(signed_bundle, private_key_path=private_key_path)
    save_binary_manifest(binary, binary_manifest_path)

    # Step 7: Verify binary manifest
    log(f"[7/7] Verifying binary manifest (CRC + RSA-PSS)...")
    if not verify_binary_manifest(binary, public_key_path=public_key_path):
        raise RuntimeError("BINARY MANIFEST VERIFICATION FAILED — aborting pipeline")
    log(f"      Binary manifest valid")

    # Copy the firmware .px4 into the output dir alongside its manifest/bundle.
    # create_bundle() embeds the .px4 inside the .fwbundle but leaves no loose
    # copy, so the .px4 in output_dir would otherwise go stale across rebuilds —
    # you flash an old image while the freshly-generated manifest expects the new
    # one (a code_hash mismatch that fails POST, or worse, silently flashing the
    # wrong firmware). Skip the copy if the source already IS the output path.
    firmware_path = output_dir / f"{stem}.px4"
    if px4_path.resolve() != firmware_path.resolve():
        shutil.copy2(px4_path, firmware_path)
        log(f"      Firmware copied:  {firmware_path}")
    else:
        firmware_path = px4_path

    log(f"\n{'='*60}")
    log(f"PIPELINE COMPLETE — all 3 verification gates passed")
    log(f"{'='*60}")
    log(f"  BOOT001 image:   {'SIGNED (RSA-PSS)' if bootloader_image_signed else 'not signed (no TOC — SITL/non-secure)'}")
    log(f"  Firmware:        {firmware_path}")
    log(f"  Bundle:          {fwbundle_path}")
    log(f"  Binary manifest: {binary_manifest_path}")
    log(f"  Signed JSON:     {signed_path}")
    log(f"  Version:         {manifest.get('firmware_version', 'unknown')}")
    log(f"  Board ID:        {manifest.get('board_id', 0)}")

    return PipelineResult(
        manifest=manifest,
        signed_bundle=signed_bundle,
        fwbundle_path=fwbundle_path,
        firmware_path=firmware_path,
        binary_manifest_path=binary_manifest_path,
        all_verified=True,
        bootloader_image_signed=bootloader_image_signed,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the full firmware release pipeline: checksum → sign → bundle → export."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--output-dir", default="release", help="Output directory (default: release/)")
    parser.add_argument("--version", default="", help="Firmware version string override")
    parser.add_argument("--board-id", type=int, default=None,
                        help="Override board ID (e.g. 1063 for CubeOrange+)")
    parser.add_argument("--elf", default=None,
                        help="Path to firmware ELF (hardware mode, ADR-018 — "
                             "hashes the same FLASH ranges the FC POST hashes)")
    parser.add_argument("--code-bin", default=None,
                        help="DEPRECATED: pre-extracted .text section binary")
    parser.add_argument("--data-bin", default=None,
                        help="DEPRECATED: pre-extracted .data section binary")
    parser.add_argument("--private-key", default=str(PRIVATE_KEY), help="Manufacturer private key path")
    parser.add_argument("--public-key", default=str(PUBLIC_KEY), help="Manufacturer public key path")
    parser.add_argument("--no-bootloader-sign", action="store_true",
                        help="Skip the BOOT001 image signature (step 0). Use for "
                             "SITL, or when the image is signed out-of-band. "
                             "Hardware secure images need this signature or the "
                             "verifying bootloader rejects them fail-closed.")
    args = parser.parse_args()

    try:
        result = run_pipeline(
            px4_path=Path(args.px4_file),
            output_dir=Path(args.output_dir),
            firmware_version=args.version,
            board_id=args.board_id,
            elf_path=Path(args.elf) if args.elf else None,
            code_bin_path=Path(args.code_bin) if args.code_bin else None,
            data_bin_path=Path(args.data_bin) if args.data_bin else None,
            private_key_path=Path(args.private_key),
            public_key_path=Path(args.public_key),
            sign_bootloader_image=not args.no_bootloader_sign,
        )
    except (FileNotFoundError, RuntimeError) as e:
        print(f"\n[FATAL] {e}")
        sys.exit(1)
