"""
tools/regenerate_attacker_fixtures.py

Stronger negative-path fixtures: artifacts that are *correctly signed*
but with an attacker keypair, not the manufacturer's. CRC is valid;
only the RSA-PSS signature verification against the embedded
manufacturer public key fails. This exercises a different branch on
the FC than our CRC-mismatch tests (which fail before the signature
check runs).

Produces, under .attacker_fixtures/ at the repo root:
  attacker_private.pem            — fresh RSA-2048 keypair
  attacker_public.pem
  attacker_manifest.bin           — drop in place of inofly/manifest.bin
                                    to exercise POST signature-mismatch
  attacker_firmware.fwbundle      — drop into QGC to exercise client-side
                                    signature reject (load only; never install)
  attacker_update_manifest.bin    — drop in place of inofly/update_manifest.bin
                                    to exercise UPD001 sig-mismatch on FC

Usage:
    py -3 tools/regenerate_attacker_fixtures.py
"""

from __future__ import annotations

import base64
import json
import shutil
import sys
import zipfile
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.bundler.bundler import create_bundle, verify_bundle
from tools.checksum.checksum import generate_manifest
from tools.pki.keygen import PUBLIC_KEY_PATH as MFR_PUBLIC_KEY_PATH
from tools.pki.keygen import generate_keypair
from tools.provisioning.export_manifest import (
    export_binary_manifest, save_binary_manifest, verify_binary_manifest,
)
from tools.signer.signer import sign_manifest


SITL_TEST_BUNDLE = {
    "manifest": {
        "algorithm":        "SHA-256",
        "firmware_version": "1.14.0-sitl-attacker",
        "source_file":      "px4_sitl_default.px4",
        "board_id":         50,
        "git_hash":         "attacker",
        "code_checksum":    "a" * 64,
        "data_checksum":    "b" * 64,
        "generated_at":     "2026-01-01T00:00:00+00:00",
    },
    "signature":  "placeholder",
    "signed_at":  "2026-01-01T00:00:01+00:00",
}


def _make_px4(path: Path) -> Path:
    image = b"\x7fELF" + b"\x00" * 256
    path.write_text(json.dumps({
        "magic": "PX4FWv1",
        "board_id": 50,
        "version": "1.0.0-attacker",
        "git_hash": "attacker",
        "build_time": 1700000000,
        "image_size": len(image),
        "image": base64.b64encode(zlib.compress(image, 9)).decode("utf-8"),
    }, indent=4))
    return path


def main() -> int:
    out = REPO_ROOT / ".attacker_fixtures"
    out.mkdir(exist_ok=True)

    # 1. Fresh attacker keypair (NOT in pki/ — only in .attacker_fixtures/).
    atk_priv = out / "attacker_private.pem"
    atk_pub  = out / "attacker_public.pem"
    priv_pem, pub_pem = generate_keypair()
    atk_priv.write_bytes(priv_pem)
    atk_pub.write_bytes(pub_pem)

    # 2. POST fixture — manifest.bin signed by attacker.
    atk_manifest = export_binary_manifest(
        SITL_TEST_BUNDLE, private_key_path=atk_priv)
    atk_manifest_path = out / "attacker_manifest.bin"
    save_binary_manifest(atk_manifest, atk_manifest_path)

    # Local sanity: attacker-signed manifest must NOT pass verification
    # against the manufacturer public key (else our attacker model is broken).
    if verify_binary_manifest(atk_manifest, MFR_PUBLIC_KEY_PATH):
        print("ERROR: attacker-signed manifest accepted by manufacturer key")
        return 1

    # 3. UPD001 fixtures — fwbundle + extracted update_manifest.bin.
    px4 = _make_px4(out / "attacker_firmware.px4")
    manifest = generate_manifest(px4, firmware_version="1.0.0-attacker")
    signed = sign_manifest(manifest, private_key_path=atk_priv)

    bundle = out / "attacker_firmware.fwbundle"
    # IMPORTANT: pass the attacker key for BOTH paths. create_bundle's
    # private_key_path arg controls update_manifest.bin (FC-facing binary
    # signature); the `signed` dict carries signed_manifest.json (QGC-facing
    # JSON signature). Defaulting to the manufacturer key here would produce
    # a half-attacker artifact that QGC rejects but the FC accepts — exactly
    # the symptom that caused Test C to falsely pass on 2026-05-17.
    create_bundle(px4, signed, bundle, private_key_path=atk_priv)

    # Bundle must verify under attacker key (sanity) and fail under
    # manufacturer key (the property under test).
    if not verify_bundle(bundle, public_key_path=atk_pub):
        print("ERROR: attacker bundle failed under attacker key — broken")
        return 1
    if verify_bundle(bundle, public_key_path=MFR_PUBLIC_KEY_PATH):
        print("ERROR: attacker bundle accepted by manufacturer key — broken")
        return 1

    # Extract attacker's update_manifest.bin for direct SD-tamper test.
    with zipfile.ZipFile(bundle, "r") as zf:
        atk_um = zf.read("update_manifest.bin")
    (out / "attacker_update_manifest.bin").write_bytes(atk_um)

    # Strong sanity: the bundled update_manifest.bin must NOT verify under
    # the manufacturer public key. verify_bundle() only checks
    # signed_manifest.json — it can't catch a half-attacker bundle where
    # update_manifest.bin defaulted to the manufacturer key. This guard
    # closes that gap. (Regression we hit on 2026-05-17: Test C false-passed
    # because create_bundle's private_key_path defaulted to the manufacturer
    # key, signing update_manifest.bin with the wrong key.)
    if verify_binary_manifest(atk_um, MFR_PUBLIC_KEY_PATH):
        print("ERROR: attacker update_manifest.bin accepted by manufacturer "
              "key — fixture is half-attacker (signed_manifest.json correct, "
              "update_manifest.bin wrong)")
        return 1

    print(f"  attacker_private.pem               (NEW keypair, do not commit)")
    print(f"  attacker_public.pem")
    print(f"  attacker_manifest.bin            {atk_manifest_path.stat().st_size:>5} B  "
          f"verify(mfr)=FAIL  (POST sig-mismatch test)")
    print(f"  attacker_firmware.fwbundle       {bundle.stat().st_size:>5} B  "
          f"verify(mfr)=FAIL  (QGC client reject test)")
    print(f"  attacker_update_manifest.bin     {len(atk_um):>5} B  "
          f"(UPD001 FC sig-mismatch test)")
    print()
    print(f"Output: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
