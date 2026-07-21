"""
tools/build_cb_test_kit.py

Build a self-contained CB (Certification Body) demo test kit: every artifact
needed to run the §7.1 hardware tests in front of the auditor, generated from
the REAL signed CubeOrange+ (board 1063) build, with clear names and a
MANIFEST that says what each file is for and the expected result.

Output folder:  Docs/audit/cb_test_kit/

Usage:
    py -3 tools/build_cb_test_kit.py
    py -3 tools/build_cb_test_kit.py --manifest <good_manifest.bin> --bundle <good.fwbundle>

By default it uses the B9 bench build under release/b9/new/. If you flash a
DIFFERENT firmware build to the unit for the demo, regenerate the kit from THAT
build's manifest/bundle (the wrong-hash and update artifacts are tied to the
exact build on the unit).

Everything is derived by re-signing (manufacturer or a throwaway attacker key)
and re-CRC — no hand hex-editing — so each negative artifact fails at exactly
the intended check with a valid CRC where required.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
import json
import base64
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from tools.provisioning.export_manifest import (
    decode_binary_manifest,
    export_binary_manifest,
    verify_binary_manifest,
    save_binary_manifest,
    PRIVATE_KEY_PATH,
)
from tools.make_hash_mismatch_manifest import make_hash_mismatch_manifest
from tools.make_wrong_boardid_manifest import make_wrong_boardid_manifest

MFR_PUB = REPO / "pki" / "manufacturer" / "public" / "manufacturer_public.pem"
KIT = REPO / "Docs" / "audit" / "cb_test_kit"

DEFAULT_MANIFEST = REPO / "release" / "b9" / "new" / "cubepilot_cubeorangeplus_default_manifest.bin"
DEFAULT_BUNDLE = REPO / "release" / "b9" / "new" / "cubepilot_cubeorangeplus_default.fwbundle"


def _flip_crc_byte(raw: bytes, offset: int = 100) -> bytes:
    b = bytearray(raw)
    b[offset] ^= 0xFF
    return bytes(b)


def _gen_attacker_key(path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub = path.with_name("attacker_public.pem")
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path


def _attacker_sign_manifest(good_raw: bytes, attacker_key: Path) -> bytes:
    """Re-sign the good manifest's payload with the attacker key (board_id and
    hashes unchanged): valid CRC, valid structure, signature fails vs the
    manufacturer key -> POST / verify_update reason=3."""
    bundle = decode_binary_manifest(good_raw)
    return export_binary_manifest(bundle, private_key_path=attacker_key)


def _tamper_bundle(good_bundle: Path, out: Path):
    """Corrupt one base64 char of the bundle's manifest signature. QGC rejects
    on the manufacturer-signature check (client-side)."""
    with zipfile.ZipFile(good_bundle) as z:
        names = z.namelist()
        man_name = next(n for n in names if n == "signed_manifest.json")
        data = {n: z.read(n) for n in names}
    manifest = json.loads(data[man_name])
    sig = manifest["signature"]
    swap = "B" if sig[10] != "B" else "A"
    manifest["signature"] = sig[:10] + swap + sig[11:]
    data[man_name] = json.dumps(manifest, indent=4).encode()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in data.items():
            z.writestr(n, b)


def _attacker_bundle(good_bundle: Path, attacker_key: Path, out: Path):
    """Re-sign the good bundle's manifest with the attacker key and repackage:
    valid structure, signature fails vs the manufacturer key. QGC client-side
    rejects it (red FAILED)."""
    from tools.signer.signer import sign_manifest
    from tools.bundler.bundler import create_bundle
    with zipfile.ZipFile(good_bundle) as z:
        px4_bytes = z.read("firmware.px4")
        signed = json.loads(z.read("signed_manifest.json"))
    attacker_signed = sign_manifest(signed["manifest"], attacker_key)
    tmp_px4 = out.with_name("_tmp_firmware.px4")
    tmp_px4.write_bytes(px4_bytes)
    try:
        create_bundle(tmp_px4, attacker_signed, out, private_key_path=attacker_key)
    finally:
        tmp_px4.unlink(missing_ok=True)


def _extract_manifest_json(good_bundle: Path, out: Path):
    """Copy the human-readable signed manifest JSON (code/data checksums, for
    showing the CB the separate registered checksums)."""
    with zipfile.ZipFile(good_bundle) as z:
        out.write_bytes(z.read("signed_manifest.json"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                    help="the real, validly-signed board-1063 manifest.bin")
    ap.add_argument("--bundle", default=str(DEFAULT_BUNDLE),
                    help="the real, board-1063 signed .fwbundle")
    args = ap.parse_args()

    good_manifest_path = Path(args.manifest)
    good_bundle_path = Path(args.bundle)

    if not good_manifest_path.exists():
        print(f"ERROR: good manifest not found: {good_manifest_path}")
        return 1
    good_raw = good_manifest_path.read_bytes()
    if not verify_binary_manifest(good_raw, MFR_PUB):
        print("ERROR: the --manifest does not verify under the manufacturer key. "
              "Point this at the real provisioned manifest.bin for the build on the unit.")
        return 1

    KIT.mkdir(parents=True, exist_ok=True)
    board_id = decode_binary_manifest(good_raw)["manifest"]["board_id"]

    # throwaway attacker keypair (never the manufacturer key)
    attacker_key = _gen_attacker_key(KIT / "attacker_private.pem")

    made = []

    def write(name, data: bytes, note):
        (KIT / name).write_bytes(data)
        made.append((name, note))

    # ── POST path (swap onto SD as /fs/microsd/inofly/manifest.bin) ──────────
    write("good_manifest.bin", good_raw,
          "Valid signed manifest for this build. Baseline / restore after a negative test. POST PASS.")
    write("tampered_manifest.bin", _flip_crc_byte(good_raw),
          "One byte flipped in the CRC-covered region. POST FAILS reason=2 (manifest CRC).")
    write("attacker_manifest.bin", _attacker_sign_manifest(good_raw, attacker_key),
          "Re-signed with a non-manufacturer key (valid CRC). POST FAILS reason=3 (signature).")
    write("wrong_code_hash_manifest.bin", make_hash_mismatch_manifest(good_raw, "code"),
          "Validly signed, deliberately wrong code_hash. POST FAILS reason=4 (code hash vs live flash).")
    write("wrong_data_hash_manifest.bin", make_hash_mismatch_manifest(good_raw, "data"),
          "Validly signed, correct code_hash, wrong data_hash. POST FAILS reason=5 (data hash).")

    # ── Update path (stage as /fs/microsd/inofly/update_manifest.bin, then
    #    `secure_boot verify_update`) ──────────────────────────────────────────
    write("good_update_manifest.bin", good_raw,
          "Valid staged update manifest. `secure_boot verify_update` ACCEPTS.")
    write("tampered_update_manifest.bin", _flip_crc_byte(good_raw),
          "Byte-flipped staged update. verify_update REJECTS reason=2 (CRC).")
    write("attacker_update_manifest.bin", _attacker_sign_manifest(good_raw, attacker_key),
          "Attacker-signed staged update (valid CRC). verify_update REJECTS reason=3 (signature).")
    write("wrong_boardid_update_manifest.bin", make_wrong_boardid_manifest(good_raw, 1064),
          "Validly signed but board_id=1064. verify_update REJECTS reason=4 (board_id mismatch).")

    # ── GCS path (.fwbundle loaded in QGC) ───────────────────────────────────
    if good_bundle_path.exists():
        shutil.copy(good_bundle_path, KIT / "good_firmware.fwbundle")
        made.append(("good_firmware.fwbundle",
                     "Valid board-1063 signed bundle. QGC shows VERIFIED; Install on Drone ACCEPTS."))
        _tamper_bundle(good_bundle_path, KIT / "tampered_firmware.fwbundle")
        made.append(("tampered_firmware.fwbundle",
                     "Signature byte corrupted. QGC shows red FAILED; Install button hidden."))
        _attacker_bundle(good_bundle_path, attacker_key, KIT / "attacker_firmware.fwbundle")
        made.append(("attacker_firmware.fwbundle",
                     "Re-signed with a non-manufacturer key. QGC shows red FAILED (signature invalid)."))
        _extract_manifest_json(good_bundle_path, KIT / "good_manifest.json")
        made.append(("good_manifest.json",
                     "Human-readable signed manifest: shows the separate code + data SHA-256 registered checksums (§7.1 a.ii)."))
    else:
        print(f"WARN: bundle {good_bundle_path} not found — skipping .fwbundle artifacts.")

    # ── sanity guards: negatives must NOT verify under the manufacturer key ──
    assert verify_binary_manifest((KIT / "good_manifest.bin").read_bytes(), MFR_PUB)
    assert not verify_binary_manifest((KIT / "tampered_manifest.bin").read_bytes(), MFR_PUB)
    assert not verify_binary_manifest((KIT / "attacker_manifest.bin").read_bytes(), MFR_PUB)
    assert verify_binary_manifest((KIT / "wrong_code_hash_manifest.bin").read_bytes(), MFR_PUB)   # valid sig, wrong hash
    assert verify_binary_manifest((KIT / "wrong_data_hash_manifest.bin").read_bytes(), MFR_PUB)
    assert verify_binary_manifest((KIT / "wrong_boardid_update_manifest.bin").read_bytes(), MFR_PUB)
    if good_bundle_path.exists():
        from tools.bundler.bundler import verify_bundle
        assert verify_bundle(KIT / "good_firmware.fwbundle", MFR_PUB), "good bundle must verify"
        assert not verify_bundle(KIT / "tampered_firmware.fwbundle", MFR_PUB), "tampered bundle must fail"
        assert not verify_bundle(KIT / "attacker_firmware.fwbundle", MFR_PUB), "attacker bundle must fail"

    # ── MANIFEST.md ──────────────────────────────────────────────────────────
    lines = [
        "# CB Test Kit — artifact manifest",
        "",
        f"Generated from board **{board_id}** build `{good_manifest_path.name}`.",
        "Regenerate with `py -3 tools/build_cb_test_kit.py` (re-run if you flash a different build).",
        "",
        "> The attacker keypair (`attacker_private.pem` / `attacker_public.pem`) is a fresh throwaway,",
        "> generated at build time. It is **not** the manufacturer key. Do not ship it.",
        "",
        "| Artifact | Purpose / expected result |",
        "|---|---|",
    ]
    for name, note in made:
        lines.append(f"| `{name}` | {note} |")
    lines += [
        "",
        "## Reason codes",
        "",
        "**POST (`firmware_integrity_status.failure_reason`):** 0 pass · 2 manifest CRC · "
        "3 manifest signature · 4 code-hash · 5 data-hash · 6 board-id.",
        "",
        "**Update gate (`secure_boot verify_update`, separate enum):** 1 no manifest · 2 CRC · "
        "3 signature · 4 board-id.",
        "",
        "Full step-by-step commands: **CB_TEST_RUNBOOK.md** (one folder up).",
    ]
    (KIT / "MANIFEST.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] CB test kit written to {KIT}  ({len(made)} artifacts + MANIFEST.md)")
    for name, _ in made:
        print(f"     {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
