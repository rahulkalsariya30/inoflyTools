"""
tools/regenerate_param_changed_fixture.py

Deterministic fixtures to test DGCA 7.1(c) A.ii — "Change should be recorded
in the logs." The secure_boot module logs a PARAM_CHANGE/SUCCESS audit entry
when a manufacturer-signed firmware update changes the certified flight
parameters, detected as a change in data_hash (SHA-256 of the
.compliance_params partition). A code-only update (data_hash unchanged) must
NOT log a parameter change.

This emits three validly-signed 373-byte binary manifests into
.param_fixtures/ (gitignored):

  active_manifest.bin                code=AA  data=BB   <- provision as the active manifest
  update_manifest_paramchanged.bin   code=AA  data=CC   <- data_hash differs  => MUST log PARAM_CHANGE
  update_manifest_codeonly.bin       code=DD  data=BB   <- data_hash same     => MUST NOT log PARAM_CHANGE

All three use board_id=50 and stubbed hashes, so they pass SITL POST exactly
like provision_sitl.py's manifest (SITL stubs _verify_code/_data_hash; only
CRC32 + RSA-PSS signature are actually checked). The point under test is the
verify_update data_hash diff + audit logging, not the hash compute.

Usage:
    py -3 tools/regenerate_param_changed_fixture.py

Then in WSL (see SITL_ACCEPTANCE Sec.7 / the 7.1(c) test):
    SITL=~/PX4-Autopilot/build/px4_sitl_default/rootfs/inofly
    cp /mnt/d/Projects/Drone/.param_fixtures/active_manifest.bin              $SITL/manifest.bin
    # pxh> secure_boot start              # POST PASS
    cp /mnt/d/Projects/Drone/.param_fixtures/update_manifest_paramchanged.bin $SITL/update_manifest.bin
    # pxh> secure_boot verify_update      # expect "...changed flight parameters (data_hash changed)" + PARAM_CHANGE/SUCCESS
    # pxh> secure_boot clear_update
    cp /mnt/d/Projects/Drone/.param_fixtures/update_manifest_codeonly.bin     $SITL/update_manifest.bin
    # pxh> secure_boot verify_update      # authorized, but NO param-change line (data_hash unchanged)
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.pki.keygen import PUBLIC_KEY_PATH  # noqa: E402
from tools.provisioning.export_manifest import (  # noqa: E402
    export_binary_manifest,
    save_binary_manifest,
    verify_binary_manifest,
)

OUT = REPO_ROOT / ".param_fixtures"

# 32-byte placeholder hashes (hex string * 64 -> 32 bytes of that nibble pair).
# AA/BB match provision_sitl.py's active manifest so this fixture set is
# consistent with the standard SITL provisioning baseline.
AA = "a" * 64   # code_hash of the active manifest
BB = "b" * 64   # data_hash of the active manifest (compliance-param partition)
CC = "c" * 64   # data_hash after a LOCKED parameter was changed
DD = "d" * 64   # a different code_hash (code-only update)


def _bundle(code_hex: str, data_hex: str, version: str) -> dict:
    """Minimal signed-bundle dict accepted by export_binary_manifest().
    export_binary_manifest re-signs a binary payload over the hashes, so the
    JSON 'signature' here is unused and intentionally a placeholder."""
    return {
        "manifest": {
            "algorithm": "SHA-256",
            "firmware_version": version,
            "board_id": 50,                # OrangeCube board ID (matches provision_sitl)
            "code_checksum": code_hex,
            "data_checksum": data_hex,
            "generated_at": "2026-01-01T00:00:00+00:00",
        },
        "signature": "placeholder-binary-manifest-has-its-own-signature",
        "signed_at": "2026-01-01T00:00:01+00:00",
    }


def _emit(name: str, code_hex: str, data_hex: str, version: str) -> bytes:
    binary = export_binary_manifest(_bundle(code_hex, data_hex, version))
    if not verify_binary_manifest(binary, PUBLIC_KEY_PATH):
        print(f"ERROR: {name} failed self-verification — signature/CRC broken")
        sys.exit(1)
    save_binary_manifest(binary, OUT / name)
    # data_hash lives at offset 41..73 in the 373-byte struct
    print(f"       code_hash[:8]={code_hex[:8]}  data_hash[:8]={data_hex[:8]}  ({version})")
    return binary


def main() -> int:
    OUT.mkdir(exist_ok=True)
    print(f"Writing 7.1(c) param-change fixtures to {OUT}\n")

    _emit("active_manifest.bin", AA, BB, "1.14.0-sitl-active")
    _emit("update_manifest_paramchanged.bin", AA, CC, "1.14.1-sitl-paramchg")
    _emit("update_manifest_codeonly.bin", DD, BB, "1.15.0-sitl-codeonly")

    print("\nExpected verify_update behaviour against active (data=BB):")
    print("  update_manifest_paramchanged.bin -> data_hash BB->CC differs -> PARAM_CHANGE/SUCCESS logged")
    print("  update_manifest_codeonly.bin     -> data_hash BB==BB same    -> NO param-change entry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
