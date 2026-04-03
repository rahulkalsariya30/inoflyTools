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

USAGE:
  python tools/pipeline.py firmware.px4 --output-dir release/
  python tools/pipeline.py firmware.px4 --version 1.14.0 --board-id 140
"""

import json
import sys
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
    binary_manifest_path: Path
    all_verified: bool


def run_pipeline(
    px4_path: Path,
    output_dir: Path,
    firmware_version: str = "",
    private_key_path: Path = PRIVATE_KEY,
    public_key_path: Path = PUBLIC_KEY,
    verbose: bool = True,
) -> PipelineResult:
    """
    Run the full firmware release pipeline.

    Steps:
      1. CHK001 — compute SHA-256 checksums (code + data)
      2. SIG001 — sign manifest with manufacturer key
      3. Verify — confirm signature is valid before proceeding
      4. PKG001 — package into .fwbundle
      5. Verify — confirm bundle signature
      6. PRV001 — export binary manifest (188 bytes)
      7. Verify — confirm binary manifest CRC + signature

    Args:
        px4_path:         Path to the .px4 firmware file
        output_dir:       Directory for all output files
        firmware_version: Override version string (default: read from .px4)
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

    # Step 1: Checksums
    log(f"[1/7] Computing SHA-256 checksums...")
    manifest = generate_manifest(px4_path, firmware_version=firmware_version)
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
    log(f"[6/7] Exporting binary manifest (188 bytes)...")
    binary = export_binary_manifest(signed_bundle, private_key_path=private_key_path)
    save_binary_manifest(binary, binary_manifest_path)

    # Step 7: Verify binary manifest
    log(f"[7/7] Verifying binary manifest (CRC + ECDSA)...")
    if not verify_binary_manifest(binary, public_key_path=public_key_path):
        raise RuntimeError("BINARY MANIFEST VERIFICATION FAILED — aborting pipeline")
    log(f"      Binary manifest valid")

    log(f"\n{'='*60}")
    log(f"PIPELINE COMPLETE — all 3 verification gates passed")
    log(f"{'='*60}")
    log(f"  Bundle:          {fwbundle_path}")
    log(f"  Binary manifest: {binary_manifest_path}")
    log(f"  Signed JSON:     {signed_path}")
    log(f"  Version:         {manifest.get('firmware_version', 'unknown')}")
    log(f"  Board ID:        {manifest.get('board_id', 0)}")

    return PipelineResult(
        manifest=manifest,
        signed_bundle=signed_bundle,
        fwbundle_path=fwbundle_path,
        binary_manifest_path=binary_manifest_path,
        all_verified=True,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the full firmware release pipeline: checksum → sign → bundle → export."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--output-dir", default="release", help="Output directory (default: release/)")
    parser.add_argument("--version", default="", help="Firmware version string override")
    parser.add_argument("--private-key", default=str(PRIVATE_KEY), help="Manufacturer private key path")
    parser.add_argument("--public-key", default=str(PUBLIC_KEY), help="Manufacturer public key path")
    args = parser.parse_args()

    try:
        result = run_pipeline(
            px4_path=Path(args.px4_file),
            output_dir=Path(args.output_dir),
            firmware_version=args.version,
            private_key_path=Path(args.private_key),
            public_key_path=Path(args.public_key),
        )
    except (FileNotFoundError, RuntimeError) as e:
        print(f"\n[FATAL] {e}")
        sys.exit(1)
