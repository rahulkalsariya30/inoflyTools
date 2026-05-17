"""
tools/regenerate_test_fixtures.py

Regenerate the gitignored test fixtures used by SITL_ACCEPTANCE §11/§12:
  - test_firmware.fwbundle           (correctly signed, must pass)
  - test_firmware_tampered.fwbundle  (signed then 1 byte flipped, must reject)

Run after any bundler format bump (e.g. v1.0.0 → v1.1.0 on 2026-05-16
which baked update_manifest.bin into every bundle).

Usage:
    py -3 tools/regenerate_test_fixtures.py
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
from tools.pki.keygen import PUBLIC_KEY_PATH
from tools.signer.signer import sign_manifest


def _make_px4(path: Path) -> Path:
    image = b"\x7fELF" + b"\x00" * 256
    path.write_text(json.dumps({
        "magic": "PX4FWv1",
        "board_id": 50,
        "version": "1.0.0-test",
        "git_hash": "abc123",
        "build_time": 1700000000,
        "image_size": len(image),
        "image": base64.b64encode(zlib.compress(image, 9)).decode("utf-8"),
    }, indent=4))
    return path


def _tamper(src: Path, dst: Path) -> None:
    # Corrupt one base64 char of the manifest signature. JSON stays valid;
    # bundle structure stays valid; but RSA-PSS verification fails. Both
    # QGC client-side and drone-side gatekeeper reject.
    with zipfile.ZipFile(src, "r") as zin:
        names = zin.namelist()
        contents = {n: zin.read(n) for n in names}

    manifest = json.loads(contents["signed_manifest.json"])
    sig = manifest["signature"]
    # Swap one base64 char; A↔B leaves length intact and keeps valid b64.
    swap = "B" if sig[10] == "A" else "A"
    manifest["signature"] = sig[:10] + swap + sig[11:]
    contents["signed_manifest.json"] = json.dumps(manifest, indent=2).encode()

    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in names:
            zout.writestr(n, contents[n])


def main() -> int:
    work = REPO_ROOT / ".fixture_workdir"
    work.mkdir(exist_ok=True)
    try:
        px4 = _make_px4(work / "test_firmware.px4")
        manifest = generate_manifest(px4, firmware_version="1.0.0-test")
        signed = sign_manifest(manifest)

        good = REPO_ROOT / "test_firmware.fwbundle"
        create_bundle(px4, signed, good)

        bad = REPO_ROOT / "test_firmware_tampered.fwbundle"
        _tamper(good, bad)

        good_ok = verify_bundle(good, public_key_path=PUBLIC_KEY_PATH)
        bad_ok = verify_bundle(bad, public_key_path=PUBLIC_KEY_PATH)

        print(f"  test_firmware.fwbundle           {good.stat().st_size:>6} B  "
              f"verify={'PASS' if good_ok else 'FAIL'}")
        print(f"  test_firmware_tampered.fwbundle  {bad.stat().st_size:>6} B  "
              f"verify={'PASS' if bad_ok else 'FAIL'}")

        if not good_ok:
            print("ERROR: valid bundle failed verification — fixture broken")
            return 1
        if bad_ok:
            print("ERROR: tampered bundle passed verification — tamper too weak")
            return 1
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
