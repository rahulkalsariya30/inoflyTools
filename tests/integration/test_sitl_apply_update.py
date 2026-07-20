"""
tests/integration/test_sitl_apply_update.py

End-to-end SITL integration test for the ADR-023 staged-update flow (A-10).

WHAT THIS COVERS:
  UPD001 apply path — `secure_boot apply_update` accept/reject matrix
    (gate 1: meta parse, hash binding, RSA spot check, created_at rollback)
  ADR-023 first-boot promotion — `secure_boot start` promotion choreography
    (rename staged manifest -> manifest.bin, cleanup, quarantine UPDATE.BAD)
  LOG001 — audit events 5 UPDATE_APPLIED / 6 UPDATE_APPLY_FAILED land with
    the right detail_code

Fixtures are SELF-GENERATED at run time: a synthetic ~4 KB cubeorangeplus-
layout image (TOC at 0x2a8) signed with the repo manufacturer key, plus the
negative set from tools/make_a10_fixtures.py — so this test depends only on
the repo, not on any release/ artifacts. The compliance suite proves the
fixtures behave (tests/compliance/test_ADR023_sd_update.py); this test
proves the DEVICE code agrees with the host reference.

On SITL, matchesRunningFirmware()/flash hashing are stubbed (no flash), so
the flash-match leg is hardware-only (B9/H16). What runs here is the trigger
logic, manifest verification, meta binding, rollback refusal, promotion file
choreography, and the audit trail.

PREREQUISITES:
  - WSL2 with PX4 SITL built (cd ~/PX4-Autopilot && make px4_sitl_default)
  - Repo manufacturer keypair present (tools/pki/keygen.py) — the SAME test
    key that is embedded in the SITL binary
  - pyelftools + cryptography on the Windows python (py -3)

NOTE: NOT collected by pytest (testpaths = tests/compliance). Run manually:
  py -3 tests/integration/test_sitl_apply_update.py

Gotchas encoded here (learned on the bench / earlier SITL matrices):
  - PX4_SIM_MODEL=shell rcS exits before its own `secure_boot start` line, so
    every boot pipes the commands explicitly.
  - PX4_STORAGEDIR is CWD-relative: staging goes to the build dir root
    (UPDATE.BIN/UPDATE.MTA) and build-dir inofly/ (manifests, marker, audit).
"""

import json
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "compliance"))

from tools.checksum.checksum import generate_manifest
from tools.signer.signer import sign_manifest
from tools.provisioning.export_manifest import export_binary_manifest, decode_binary_manifest
from tools.make_a10_fixtures import make_fixtures
from test_ADR023_sd_update import build_synthetic_setup

PRIVATE_KEY = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"
PUBLIC_KEY = PROJECT_ROOT / "pki" / "manufacturer" / "public" / "manufacturer_public.pem"

BD = "~/PX4-Autopilot/build/px4_sitl_default"   # SITL build dir (WSL side)
FIX_WSL = "~/a10_sitl_fixtures"                 # fixture copy inside WSL

# security_manifest_t offset (373-byte binary manifest): created_at u32 at 365.
# Since format v4 created_at is INSIDE the RSA-signed payload, so the rollback
# fixture (NEWER.BIN) has to be re-signed with the bumped timestamp — a
# bump-and-refix-CRC edit would (correctly) fail signature verification now.
_CREATED_AT_OFF = 365

PASS = 0
FAIL = 0


def wsl_run(cmd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["wsl", "-e", "bash", "-lc", cmd],
                          capture_output=True, text=True, timeout=timeout)


def check(case: str, label: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  [{case}] {label}  {detail}")


def check_prerequisites() -> bool:
    try:
        if wsl_run("echo ok", timeout=10).returncode != 0:
            print("[FAIL] WSL2 not available")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[FAIL] WSL2 not available or timed out")
        return False
    r = wsl_run(f"test -f {BD}/bin/px4 && echo ok")
    if "ok" not in r.stdout:
        print("[FAIL] PX4 SITL not built (make px4_sitl_default)")
        return False
    if not PRIVATE_KEY.exists() or not PUBLIC_KEY.exists():
        print("[FAIL] Manufacturer keys not found (tools/pki/keygen.py)")
        return False
    return True


def make_all_fixtures(tmp: Path) -> Path:
    """Synthetic build + A-10 negative set + binary manifests (GOOD/NEWER/BAD)."""
    setup = build_synthetic_setup(tmp, PRIVATE_KEY.read_bytes())
    fixtures = make_fixtures(setup["signed_px4"], setup["elf_path"], tmp / "fix",
                             public_key_path=PUBLIC_KEY, log=lambda _m: None)
    out = tmp / "fix"

    # GOOD.BIN — signed binary manifest whose hashes bind to the synthetic image
    manifest = generate_manifest(setup["signed_px4"], elf_path=setup["elf_path"])
    signed = sign_manifest(manifest, private_key_path=PRIVATE_KEY)
    good = export_binary_manifest(signed, PRIVATE_KEY)
    assert len(good) == 373
    (out / "GOOD.BIN").write_bytes(good)

    # NEWER.BIN — created_at +1 day, RE-SIGNED (rollback fixture). v4 signs
    # created_at, so the newer timestamp must go through a full re-export.
    created_at = struct.unpack_from("<I", good, _CREATED_AT_OFF)[0]
    newer_bundle = decode_binary_manifest(good)
    newer_bundle["manifest"]["generated_at"] = \
        datetime.fromtimestamp(created_at + 86400, tz=timezone.utc).isoformat()
    newer = export_binary_manifest(newer_bundle, PRIVATE_KEY)
    (out / "NEWER.BIN").write_bytes(newer)

    # BADMANIFEST.BIN — one payload byte flipped (RSA fails -> corrupt, reason 2)
    bad = bytearray(good)
    bad[100] ^= 0x01
    (out / "BADMANIFEST.BIN").write_bytes(bad)

    print(f"[fixtures] generated in {out} "
          f"(image {setup['signed_len'] + 256} B, created_at {created_at})")
    return out


def stage_fixtures_into_wsl(fix_dir: Path):
    win_path = str(fix_dir).replace("\\", "/")
    r = wsl_run(f'rm -rf {FIX_WSL} && cp -r "$(wslpath -u \'{win_path}\')" {FIX_WSL}')
    if r.returncode != 0:
        raise RuntimeError(f"fixture copy into WSL failed: {r.stderr}")


def fresh(active_manifest: str, staged: dict):
    """Reset SITL storage: active manifest + optional staged files.
    staged keys: update_manifest / update_bin / update_mta / marker."""
    cmds = [
        f"cd {BD}", "mkdir -p inofly",
        "rm -f UPDATE.BIN UPDATE.MTA UPDATE.BAD inofly/update_pending "
        "inofly/update_manifest.bin inofly/audit_log.bin inofly/audit_log.sig",
        f"cp {FIX_WSL}/{active_manifest} inofly/manifest.bin",
    ]
    if "update_manifest" in staged:
        cmds.append(f"cp {FIX_WSL}/{staged['update_manifest']} inofly/update_manifest.bin")
    if "update_bin" in staged:
        cmds.append(f"cp {FIX_WSL}/{staged['update_bin']} UPDATE.BIN")
    if "update_mta" in staged:
        cmds.append(f"cp {FIX_WSL}/{staged['update_mta']} UPDATE.MTA")
    if staged.get("marker"):
        cmds.append(r"printf 'version=matrix\ncode_hash=00\ncreated_at=0\n' > inofly/update_pending")
    r = wsl_run(" && ".join(cmds))
    if r.returncode != 0:
        raise RuntimeError(f"staging failed: {r.stderr}")


def boot(px4_commands: str) -> str:
    """One headless SITL boot; returns ANSI-stripped console output."""
    r = wsl_run(
        f"cd {BD} && export PX4_SIM_MODEL=shell; "
        f"echo -e '{px4_commands}\\nshutdown' | "
        f"timeout 90 ./bin/px4 -s ../../ROMFS/px4fmu_common/init.d-posix/rcS 2>&1 | "
        r"sed -r 's/\x1b\[[0-9;]*[A-Za-z]|\[2K//g'"
    )
    return r.stdout


def field(out: str, name: str) -> str:
    for line in out.splitlines():
        if f"{name}:" in line:
            return line.split(f"{name}:")[1].strip().split()[0]
    return "?"


def audit_events() -> str:
    """'type:code ...' per 316-byte audit entry (same parse the A-6 matrix used)."""
    r = wsl_run(
        f"cd {BD} && python3 -c '"
        'import pathlib\n'
        'p = pathlib.Path("inofly/audit_log.bin")\n'
        'out = []\n'
        'if p.exists():\n'
        '    d = p.read_bytes()\n'
        '    for i in range(len(d) // 316):\n'
        '        e = d[i*316:(i+1)*316]\n'
        '        out.append(f"{e[5]}:{e[7]}")\n'
        'print(" ".join(out))\'')
    return r.stdout.strip()


def wsl_file_exists(path: str) -> bool:
    return "yes" in wsl_run(f"cd {BD} && test -e {path} && echo yes || echo no").stdout


# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------

def apply_case(case: str, staged: dict, active: str,
               want_auth: str, want_reason: str, want_marker: bool):
    fresh(active, staged)
    out = boot("secure_boot apply_update\\nlistener firmware_update_authorization -n 1")
    auth, reason = field(out, "authorized"), field(out, "reject_reason")
    check(case, f"authorized={want_auth}", auth == want_auth, f"got {auth}")
    check(case, f"reject_reason={want_reason}", reason == want_reason, f"got {reason}")
    check(case, f"marker {'written' if want_marker else 'absent'}",
          wsl_file_exists("inofly/update_pending") == want_marker)
    print(f"  [{case}] authorized={auth} image_verified={field(out, 'image_verified')} "
          f"reason={reason}")


def run_apply_matrix():
    print("\n=== UPD001 apply_update matrix (gate 1) ===")
    good_stage = {"update_manifest": "GOOD.BIN", "update_bin": "UPDATE.BIN",
                  "update_mta": "UPDATE.MTA"}

    print("--- apply 1: good image + meta + manifest -> ACCEPT, marker written")
    apply_case("A1", good_stage, "GOOD.BIN", "True", "0", want_marker=True)

    print("--- apply 2: tampered code byte -> 6 IMAGE_HASH_MISMATCH")
    apply_case("A2", {**good_stage, "update_bin": "UPDATE_TAMPERED.BIN"},
               "GOOD.BIN", "False", "6", want_marker=False)

    print("--- apply 3: zeroed signature -> 7 IMAGE_SIG_INVALID")
    apply_case("A3", {**good_stage, "update_bin": "UPDATE_BADSIG.BIN"},
               "GOOD.BIN", "False", "7", want_marker=False)

    print("--- apply 4: attacker-key signature (binding passes!) -> 7 key pinning")
    apply_case("A4", {**good_stage, "update_bin": "UPDATE_ATTACKER.BIN"},
               "GOOD.BIN", "False", "7", want_marker=False)

    print("--- apply 5: truncated image vs meta -> 6")
    apply_case("A5", {**good_stage, "update_bin": "UPDATE_TRUNC.BIN"},
               "GOOD.BIN", "False", "6", want_marker=False)

    print("--- apply 6: tampered meta split (invariants hold) -> 6 self-validation")
    apply_case("A6", {**good_stage, "update_mta": "UPDATE_BADMETA.MTA"},
               "GOOD.BIN", "False", "6", want_marker=False)

    print("--- apply 7: meta missing -> 5 IMAGE_MISSING")
    apply_case("A7", {k: v for k, v in good_stage.items() if k != "update_mta"},
               "GOOD.BIN", "False", "5", want_marker=False)

    print("--- apply 8: image missing -> 5 IMAGE_MISSING")
    apply_case("A8", {k: v for k, v in good_stage.items() if k != "update_bin"},
               "GOOD.BIN", "False", "5", want_marker=False)

    print("--- apply 9: active manifest newer than staged -> 8 ROLLBACK")
    apply_case("A9", good_stage, "NEWER.BIN", "False", "8", want_marker=False)

    print("--- apply 10: regression — verify_update manifest-only path -> ACCEPT")
    fresh("GOOD.BIN", {"update_manifest": "NEWER.BIN"})
    out = boot("secure_boot verify_update\\nlistener firmware_update_authorization -n 1")
    check("A10", "authorized=True", field(out, "authorized") == "True",
          f"got {field(out, 'authorized')}")
    check("A10", "reject_reason=0", field(out, "reject_reason") == "0",
          f"got {field(out, 'reject_reason')}")


def promotion_case(case: str, active: str, staged: dict, checks: list):
    fresh(active, staged)
    out = boot("secure_boot start\\nlistener firmware_integrity_status -n 1")
    for label, path, want in checks:
        check(case, label, wsl_file_exists(path) == want)
    return out


def run_promotion_matrix():
    print("\n=== ADR-023 first-boot promotion (secure_boot start) ===")

    print("--- promote 1: full post-flash state (NEWER staged) -> PROMOTED, event 5:0")
    promotion_case("P1", "GOOD.BIN",
                   {"update_manifest": "NEWER.BIN", "update_bin": "UPDATE.BIN",
                    "update_mta": "UPDATE.MTA", "marker": True},
                   [("UPDATE.BIN deleted", "UPDATE.BIN", False),
                    ("UPDATE.MTA deleted", "UPDATE.MTA", False),
                    ("marker deleted", "inofly/update_pending", False),
                    ("staged manifest consumed", "inofly/update_manifest.bin", False),
                    ("no quarantine", "UPDATE.BAD", False)])
    promoted = wsl_run(f"cd {BD} && cmp -s inofly/manifest.bin {FIX_WSL}/NEWER.BIN "
                       "&& echo same || echo diff").stdout
    check("P1", "manifest.bin == staged (NEWER)", "same" in promoted)
    check("P1", "audit has 5:0 UPDATE_APPLIED", "5:0" in audit_events(),
          f"audit: {audit_events()}")

    print("--- promote 2: tampered staged manifest -> quarantine + event 6:2")
    promotion_case("P2", "GOOD.BIN",
                   {"update_manifest": "BADMANIFEST.BIN", "update_bin": "UPDATE.BIN",
                    "update_mta": "UPDATE.MTA", "marker": True},
                   [("UPDATE.BAD quarantined", "UPDATE.BAD", True),
                    ("UPDATE.BIN gone", "UPDATE.BIN", False),
                    ("marker deleted (audit once)", "inofly/update_pending", False)])
    kept = wsl_run(f"cd {BD} && cmp -s inofly/manifest.bin {FIX_WSL}/GOOD.BIN "
                   "&& echo same || echo diff").stdout
    check("P2", "active manifest untouched", "same" in kept)
    check("P2", "audit has 6:2 UPDATE_APPLY_FAILED corrupt", "6:2" in audit_events(),
          f"audit: {audit_events()}")

    print("--- promote 3: BL-path rollback (staged older than active) -> refuse + 6:8")
    promotion_case("P3", "NEWER.BIN",
                   {"update_manifest": "GOOD.BIN", "update_bin": "UPDATE.BIN",
                    "marker": True},
                   [("UPDATE.BAD quarantined", "UPDATE.BAD", True)])
    kept = wsl_run(f"cd {BD} && cmp -s inofly/manifest.bin {FIX_WSL}/NEWER.BIN "
                   "&& echo same || echo diff").stdout
    check("P3", "active (newer) manifest kept", "same" in kept)
    check("P3", "audit has 6:8 rollback", "6:8" in audit_events(),
          f"audit: {audit_events()}")


def main() -> int:
    print("=" * 64)
    print("ADR-023 / UPD001 SITL apply_update + promotion integration test")
    print("=" * 64)
    if not check_prerequisites():
        return 1

    with tempfile.TemporaryDirectory(prefix="a10_sitl_") as tmp:
        fix_dir = make_all_fixtures(Path(tmp))
        stage_fixtures_into_wsl(fix_dir)

        run_apply_matrix()
        run_promotion_matrix()

        # leave SITL storage clean (no staged update surprising the next run)
        fresh("GOOD.BIN", {})

    print("\n" + "=" * 64)
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    print("=" * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
