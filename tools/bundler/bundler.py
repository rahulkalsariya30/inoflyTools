"""
tools/bundler/bundler.py

Firmware Update Bundle Packager
Requirement: PKG001 - Package signed firmware into a distributable update bundle

WHY a bundle?
  A vendor receives ONE file. It contains everything needed to update a drone
  and verify the update is authentic:
    - The firmware binary (.px4) to flash onto the flight controller
    - The signed manifest (checksums + manufacturer signature) to register

  The bundle ties the firmware and its signed proof together. You cannot swap
  the firmware for a different version while keeping the original signature —
  the checksums in the manifest would no longer match.

BUNDLE FORMAT:
  A ZIP file with a .fwbundle extension. ZIP was chosen because:
    - Human-readable: unzip it and inspect the contents
    - Auditable: any tool can verify the contents without our software
    - Standard: no custom binary parsing needed

  Contents:
    firmware.px4          — the firmware binary (copy of the original .px4)
    signed_manifest.json  — signed manifest from Phase 1.3 (signer.py)
    update_manifest.bin   — 373-byte security_manifest_t for UPD001 flow
                            (RSA-PSS-signed over the 102-byte fixed payload;
                            uploaded to the FC's SD card and verified by
                            FirmwareUpdateGatekeeper). See security_manifest.h.
    firmware_update.bin   — (hardware bundles only, v1.2+) the raw signed
                            flash image for the ADR-023 SD-staged update.
                            QGC uploads it to /fs/microsd/UPDATE.BIN; the
                            bootloader RSA-PSS-verifies it before erasing.
    update_image.meta     — (hardware bundles only, v1.2+) sidecar for
                            firmware_update.bin. QGC uploads it to
                            /fs/microsd/UPDATE.MTA. See build_update_artifacts.
    bundle_info.json      — top-level metadata (version, board, created_at)

WHY two manifests?
  signed_manifest.json    is JSON, signed over canonicalized JSON bytes.
                          Used by QGC for client-side authenticity check.
  update_manifest.bin     is the fixed-layout binary the FC's gatekeeper
                          reads. Its signature covers a 102-byte payload
                          (code_hash + data_hash + board_id + version), NOT
                          the JSON bytes. The drone never parses JSON; the
                          bundler bakes the binary form so QGC just FTPs it.

VENDOR WORKFLOW:
  Manufacturer runs: keygen → checksum → sign → package (this tool)
  Vendor receives:   firmware_v1.14.0_cubeorange.fwbundle
  QGC plugin opens bundle, verifies signature, uploads binary manifest +
  triggers `secure_boot verify_update` on the FC (UPD001 flow).
"""

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.signer.signer import verify_bundle as _verify_signed_bundle, load_signed_bundle
from tools.provisioning.export_manifest import export_binary_manifest
from tools.pki.keygen import PRIVATE_KEY_PATH as _DEFAULT_PRIVATE_KEY_PATH
from tools.checksum.checksum import extract_image_bytes, _read_elf_symbols
from tools.signer.toc_sign import (
    find_toc as _find_image_toc,
    verify_image as _verify_image_signature,
    TocParseError,
    TOC_OFFSET_DEFAULT,
    APP_LOAD_ADDRESS_DEFAULT,
    RSA_2048_SIG_LEN,
)

# 1.1.0 — bundles now include update_manifest.bin (UPD001 / FC gatekeeper).
# 1.2.0 — hardware bundles include firmware_update.bin + update_image.meta
#         (ADR-023 A-8: artifacts for the SD-staged bootloader update path).
BUNDLER_VERSION = "1.2.0"

# In-bundle names are descriptive; the on-card names are the 8.3 forms the
# bootloader's read-only FatFs looks for at the SD root (UPDATE.BIN/UPDATE.MTA).
UPDATE_IMAGE_NAME = "firmware_update.bin"
UPDATE_META_NAME = "update_image.meta"


def build_update_artifacts(
    px4_path: Path,
    elf_path: Path,
    manifest: dict = None,
) -> tuple:
    """
    Build the ADR-023 SD-staged update artifacts from a SIGNED hardware .px4.

    Returns (image_bytes, meta_dict) where image_bytes is the raw signed flash
    image (what lands on the card as UPDATE.BIN) and meta_dict is the UPDATE.MTA
    sidecar content. The meta format is the device contract defined by
    FirmwareUpdateGatekeeper::applyUpdate (A-5) — flat JSON, integer sizes:

        {"image_size": N, "code_len": N, "data_len": N, "sha256": "..."}

    The device enforces: file size == image_size == signed_len + 256 and
    code_len + data_len == signed_len (both nonzero). "sha256" (whole file) is
    ignored by the device — it exists so QGC/host tools can integrity-check the
    upload without re-deriving anything.

    The meta is untrusted on the device but self-validating: a tampered
    code_len/data_len makes the computed region digests diverge from the
    RSA-signed manifest hashes, so the apply is refused. To guarantee we never
    ship a sidecar that fails that binding, this function PROVES it on the
    host when the checksum manifest is provided: the split must reproduce the
    manifest's code/data checksums exactly (also catches a mismatched ELF).

    Raises ValueError if the image has no TOC (SITL/non-secure build — there
    is no bootloader update path for those), is still carrying the zeroed
    signature placeholder (unsigned — the bootloader would refuse it), or
    violates any device-side invariant.
    """
    px4_path = Path(px4_path)
    elf_path = Path(elf_path)

    image = extract_image_bytes(px4_path)

    try:
        _entry_count, entries = _find_image_toc(image, TOC_OFFSET_DEFAULT)
    except TocParseError as e:
        raise ValueError(
            f"{px4_path.name} has no image TOC — SITL/non-secure build? "
            f"Update artifacts exist only for hardware secure images. ({e})"
        )

    # Mirror the bootloader's sd_update.c layout checks so a bad artifact
    # fails HERE, not on the bench: BOOT region starts at APP_LOAD_ADDRESS,
    # the 256-byte SIG region directly follows it, and the SIG region is the
    # last thing in the file (image_size == signed_len + 256).
    boot = entries[0]
    sig_idx = boot["signature_idx"]
    if sig_idx == 0 or sig_idx >= len(entries):
        raise ValueError(f"BOOT entry signature_idx={sig_idx} out of range")
    sig = entries[sig_idx]

    if boot["start"] != APP_LOAD_ADDRESS_DEFAULT:
        raise ValueError(
            f"BOOT region starts at {boot['start']:#x}, expected APP_LOAD_ADDRESS "
            f"{APP_LOAD_ADDRESS_DEFAULT:#x}"
        )
    signed_len = boot["end"] - boot["start"]
    if sig["start"] != boot["end"] or sig["end"] - sig["start"] != RSA_2048_SIG_LEN:
        raise ValueError("SIG region must directly follow BOOT and be 256 bytes")
    image_size = sig["end"] - boot["start"]
    if image_size != len(image):
        raise ValueError(
            f"image_size from TOC ({image_size}) != extracted image size "
            f"({len(image)}) — SIG region must be the last bytes of the image"
        )
    if signed_len % 4 or image_size % 4:
        # sd_update.c writes flash word-by-word and rejects unaligned lengths.
        raise ValueError(f"lengths not word-aligned: signed_len={signed_len} image_size={image_size}")

    sig_bytes = image[signed_len:signed_len + RSA_2048_SIG_LEN]
    if sig_bytes == b"\x00" * RSA_2048_SIG_LEN:
        raise ValueError(
            f"{px4_path.name} carries the zeroed signature placeholder — it was "
            "never BOOT001-signed. The bootloader refuses unsigned images; run "
            "the pipeline signing step (or toc_sign.py) first."
        )

    # code/data split from the same linker symbols the FC POST hashes between.
    syms = _read_elf_symbols(elf_path)
    code_len = syms["_compliance_params_start"] - syms["_stext"]
    data_len = syms["_compliance_params_end"] - syms["_compliance_params_start"]
    if code_len <= 0 or data_len <= 0:
        raise ValueError(f"degenerate region split: code_len={code_len} data_len={data_len}")
    if code_len + data_len != signed_len:
        raise ValueError(
            f"code_len + data_len ({code_len} + {data_len}) != signed range "
            f"({signed_len}) — is {elf_path.name} the ELF this .px4 was built from?"
        )

    # Host-side proof of the hash binding the device will perform before
    # rebooting into the bootloader. A mismatch here means the ELF and the
    # .px4 are from different builds — shipping that bundle would brick the
    # update flow (refused on-device), so refuse to build it instead.
    if manifest is not None:
        code_hash = hashlib.sha256(image[:code_len]).hexdigest()
        data_hash = hashlib.sha256(image[code_len:code_len + data_len]).hexdigest()
        if code_hash != manifest.get("code_checksum"):
            raise ValueError(
                "update image code region does not reproduce the manifest "
                "code_checksum — .px4 and ELF are from different builds"
            )
        if data_hash != manifest.get("data_checksum"):
            raise ValueError(
                "update image data region does not reproduce the manifest "
                "data_checksum — .px4 and ELF are from different builds"
            )

    meta = {
        "image_size": len(image),
        "code_len": code_len,
        "data_len": data_len,
        "sha256": hashlib.sha256(image).hexdigest(),
    }
    return image, meta


def create_bundle(
    px4_path: Path,
    signed_manifest: dict,
    output_path: Path,
    private_key_path: Path = _DEFAULT_PRIVATE_KEY_PATH,
    elf_path: Path = None,
) -> Path:
    """
    Package a firmware file and its signed manifest into a .fwbundle file.

    Args:
        px4_path:        Path to the .px4 firmware file (for hardware bundles
                         this must be the BOOT001-SIGNED image — the pipeline
                         rebinds to it after step 0)
        signed_manifest: The signed bundle dict from signer.sign_manifest()
        output_path:     Where to write the .fwbundle file
        elf_path:        Firmware ELF (hardware mode). When given, the bundle
                         also carries firmware_update.bin + update_image.meta
                         for the ADR-023 SD-staged update path.

    Returns:
        Path to the created bundle file
    """
    px4_path = Path(px4_path)
    output_path = Path(output_path)

    if not px4_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {px4_path}")

    # Validate the signed manifest has required fields before bundling
    required = {"manifest", "signature", "signed_at"}
    missing = required - set(signed_manifest.keys())
    if missing:
        raise ValueError(f"Signed manifest is missing fields: {missing}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Build the top-level bundle_info — describes what's in the bundle
    # without requiring the consumer to parse the manifest
    manifest_data = signed_manifest["manifest"]
    bundle_info = {
        "bundler_version": BUNDLER_VERSION,
        "firmware_version": manifest_data.get("firmware_version", "unknown"),
        "board_id": manifest_data.get("board_id", 0),
        "firmware_file": px4_path.name,
        "algorithm": manifest_data.get("algorithm", "SHA-256"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # ADR-023 (A-8): hardware bundles carry the SD-staged update artifacts.
    # Built (and binding-proven) BEFORE the zip is opened so a failure never
    # leaves a half-written bundle behind.
    update_image = None
    update_meta = None
    if elf_path is not None:
        update_image, update_meta = build_update_artifacts(
            px4_path, elf_path, manifest=manifest_data
        )
        bundle_info["update_image"] = update_meta

    # Build the binary security_manifest_t the FC's FirmwareUpdateGatekeeper reads.
    # This is a separate RSA-PSS signature over the 102-byte fixed-layout payload
    # (code_hash + data_hash + board_id + version) — distinct from the JSON
    # manifest's signature, which is over the canonicalized JSON. The drone
    # never parses JSON; this binary is what gets FTP-uploaded by QGC during
    # the UPD001 install flow.
    binary_manifest = export_binary_manifest(signed_manifest, private_key_path)
    assert len(binary_manifest) == 373, f"binary manifest size wrong: {len(binary_manifest)}"

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Store firmware binary
        zf.write(px4_path, arcname="firmware.px4")

        # Store signed manifest (manifest + signature)
        zf.writestr(
            "signed_manifest.json",
            json.dumps(signed_manifest, indent=4)
        )

        # Store the FC-facing binary manifest (UPD001 / gatekeeper input)
        zf.writestr("update_manifest.bin", binary_manifest)

        # Store the ADR-023 staged-update artifacts (hardware bundles only).
        # The trailing newline on the meta matches what the A-5 SITL fixtures
        # shipped; the device's key-scan parser doesn't care either way.
        if update_image is not None:
            zf.writestr(UPDATE_IMAGE_NAME, update_image)
            zf.writestr(UPDATE_META_NAME, json.dumps(update_meta) + "\n")

        # Store bundle info (human-readable summary at top level)
        zf.writestr(
            "bundle_info.json",
            json.dumps(bundle_info, indent=4)
        )

    print(f"[OK] Bundle created: {output_path}")
    print(f"     Firmware:        {px4_path.name}")
    print(f"     Version:         {bundle_info['firmware_version']}")
    print(f"     Board ID:        {bundle_info['board_id']}")
    print(f"     update_manifest.bin: 373 bytes (FC gatekeeper input)")
    if update_image is not None:
        print(f"     {UPDATE_IMAGE_NAME}: {len(update_image)} bytes "
              f"(SD-staged update image, code_len={update_meta['code_len']} "
              f"data_len={update_meta['data_len']})")
    return output_path


def verify_bundle(bundle_path: Path, public_key_path: Path) -> bool:
    """
    Verify the signature inside a .fwbundle file.

    Opens the bundle, extracts the signed manifest, and checks that the
    manufacturer signature is valid. Does NOT verify that the firmware
    binary matches the checksums — that happens on the drone at boot (POST).

    For v1.2+ hardware bundles it additionally checks the staged-update
    artifacts: the meta sidecar must be consistent with firmware_update.bin,
    and the image's TOC signature must RSA-PSS-verify under the manufacturer
    public key — the same check the bootloader performs before erasing, so a
    pass here ≈ "the device will accept this update".

    Returns:
        True if the signatures are valid, False otherwise
    """
    bundle_path = Path(bundle_path)

    if not bundle_path.exists():
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()

        # Check all expected files are present. update_manifest.bin is
        # required for v1.1.0+ bundles (carries the FC-facing binary manifest).
        for required_file in ["firmware.px4", "signed_manifest.json",
                              "update_manifest.bin", "bundle_info.json"]:
            if required_file not in names:
                raise ValueError(
                    f"Bundle is missing '{required_file}'. "
                    "This bundle may be corrupt or tampered with."
                )

        # The staged-update artifacts are optional (SITL bundles don't have
        # them) but must come as a pair — one without the other means the
        # bundle was hand-edited or corrupted.
        has_image = UPDATE_IMAGE_NAME in names
        has_meta = UPDATE_META_NAME in names
        if has_image != has_meta:
            raise ValueError(
                f"Bundle carries {UPDATE_IMAGE_NAME if has_image else UPDATE_META_NAME} "
                f"without its counterpart. This bundle may be corrupt or tampered with."
            )

        signed_manifest = json.loads(zf.read("signed_manifest.json"))

        update_image = zf.read(UPDATE_IMAGE_NAME) if has_image else None
        update_meta = json.loads(zf.read(UPDATE_META_NAME)) if has_meta else None

    if not _verify_signed_bundle(signed_manifest, public_key_path=public_key_path):
        return False

    if update_image is not None:
        # Transport integrity: the sidecar must describe the image it ships with.
        if update_meta.get("image_size") != len(update_image):
            raise ValueError(
                f"{UPDATE_META_NAME} image_size ({update_meta.get('image_size')}) "
                f"does not match {UPDATE_IMAGE_NAME} ({len(update_image)} bytes)"
            )
        if update_meta.get("sha256") != hashlib.sha256(update_image).hexdigest():
            raise ValueError(
                f"{UPDATE_META_NAME} sha256 does not match {UPDATE_IMAGE_NAME} — "
                "the bundle contents were modified after packaging"
            )
        # Authenticity: same RSA-PSS-over-signed-range check the bootloader does.
        try:
            if not _verify_image_signature(update_image, Path(public_key_path).read_bytes()):
                return False
        except TocParseError as e:
            raise ValueError(
                f"{UPDATE_IMAGE_NAME} has no parseable image TOC — not a valid "
                f"staged update image ({e})"
            )

    return True


def inspect_bundle(bundle_path: Path) -> dict:
    """
    Read bundle metadata without verifying the signature.
    Useful for displaying bundle info in QGC before installing.

    Returns:
        The bundle_info dict from inside the bundle
    """
    bundle_path = Path(bundle_path)

    with zipfile.ZipFile(bundle_path, "r") as zf:
        return json.loads(zf.read("bundle_info.json"))


def extract_firmware(bundle_path: Path, output_dir: Path) -> Path:
    """
    Extract only the firmware .px4 file from a bundle.
    Used by QGC plugin (Phase 4) after signature verification.

    Returns:
        Path to the extracted .px4 file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(bundle_path, "r") as zf:
        zf.extract("firmware.px4", path=output_dir)

    return output_dir / "firmware.px4"


if __name__ == "__main__":
    import argparse

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.checksum.checksum import generate_manifest
    from tools.signer.signer import sign_manifest
    from tools.pki.keygen import PUBLIC_KEY_PATH

    parser = argparse.ArgumentParser(
        description="Package a PX4 firmware file into a signed .fwbundle for distribution."
    )
    parser.add_argument("px4_file", help="Path to the .px4 firmware file")
    parser.add_argument("--version", default="", help="Firmware version string")
    parser.add_argument("--output", default="", help="Output path for .fwbundle file")
    parser.add_argument("--elf", default=None,
                        help="Firmware ELF (hardware mode) — bundle also carries "
                             "the ADR-023 SD-staged update artifacts. The .px4 "
                             "must already be BOOT001-signed.")
    parser.add_argument("--verify", action="store_true", help="Verify bundle after creation")
    args = parser.parse_args()

    px4_path = Path(args.px4_file)
    if not px4_path.exists():
        print(f"[ERROR] File not found: {px4_path}")
        sys.exit(1)
    elf_path = Path(args.elf) if args.elf else None
    if elf_path and not elf_path.exists():
        print(f"[ERROR] ELF not found: {elf_path}")
        sys.exit(1)

    # Default output name based on firmware file
    output_path = Path(args.output) if args.output else px4_path.with_suffix(".fwbundle")

    print(f"Step 1/3 — Computing checksums...")
    manifest = generate_manifest(px4_path, firmware_version=args.version, elf_path=elf_path)

    print(f"Step 2/3 — Signing manifest...")
    signed = sign_manifest(manifest)

    print(f"Step 3/3 — Packaging bundle...")
    create_bundle(px4_path, signed, output_path, elf_path=elf_path)

    if args.verify:
        print(f"\nVerifying bundle signature...")
        valid = verify_bundle(output_path, public_key_path=PUBLIC_KEY_PATH)
        print(f"[{'OK' if valid else 'FAIL'}] Signature: {'valid' if valid else 'INVALID'}")
        if not valid:
            sys.exit(1)
