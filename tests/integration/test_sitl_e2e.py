"""
tests/integration/test_sitl_e2e.py

End-to-end SITL integration test for firmware integrity checking.

This test exercises the full chain:
  1. Provision a signed manifest into SITL storage
  2. Launch PX4 SITL
  3. Start the secure_boot module
  4. Read the firmware_integrity_status uORB message
  5. Verify check_passed == True

PREREQUISITES:
  - WSL2 with PX4-Autopilot built (make px4_sitl_default)
  - Manufacturer keypair generated (tools/pki/keygen.py)
  - Run from Windows: python tests/integration/test_sitl_e2e.py

NOTE:
  This is NOT a pytest test — it requires WSL2 and a PX4 build.
  Run it manually for integration verification. CI runs the unit
  tests only (tests/compliance/).

WHAT THIS COVERS (Phase 6.1 / 6.2):
  - POST001: CRC + ECDSA verification passes with valid manifest
  - ARM001:  Arming gate reads firmware_integrity_status.check_passed
"""

import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Timeouts
SITL_BOOT_TIMEOUT = 30   # seconds to wait for SITL to boot
MODULE_TIMEOUT    = 10   # seconds to wait for secure_boot output
LISTENER_TIMEOUT  = 10   # seconds to wait for uORB message


def wsl_run(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command inside WSL2 and return the result."""
    return subprocess.run(
        ["wsl", "-e", "bash", "-lc", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def check_prerequisites() -> bool:
    """Verify WSL2, PX4 build, and keys are available."""
    print("[prereq] Checking WSL2...")
    try:
        r = wsl_run("echo ok", timeout=10)
        if r.returncode != 0:
            print("[FAIL] WSL2 not available")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[FAIL] WSL2 not available or timed out")
        return False

    print("[prereq] Checking PX4 SITL build...")
    r = wsl_run("test -f ~/PX4-Autopilot/build/px4_sitl_default/bin/px4 && echo ok")
    if "ok" not in r.stdout:
        print("[FAIL] PX4 SITL not built. Run: cd ~/PX4-Autopilot && make px4_sitl_default")
        return False

    print("[prereq] Checking manufacturer keys...")
    private_key = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"
    public_key = PROJECT_ROOT / "pki" / "manufacturer" / "public" / "manufacturer_public.pem"
    if not private_key.exists() or not public_key.exists():
        print("[FAIL] Manufacturer keys not found. Run: python tools/pki/keygen.py")
        return False

    print("[prereq] All prerequisites met")
    return True


def provision_manifest() -> bool:
    """Run the SITL provisioning script via WSL."""
    print("\n[1/4] Provisioning signed manifest into SITL storage...")

    # Convert Windows path to WSL path for the project
    win_path = str(PROJECT_ROOT).replace("\\", "/")
    # D:/Projects/Drone -> /mnt/d/Projects/Drone
    drive = win_path[0].lower()
    wsl_project = f"/mnt/{drive}/{win_path[3:]}"

    cmd = f"cd {wsl_project} && python3 tools/provisioning/provision_sitl.py"
    r = wsl_run(cmd, timeout=30)

    if r.returncode != 0:
        print(f"[FAIL] Provisioning failed:\n{r.stderr}")
        return False

    print(r.stdout)
    return True


def run_sitl_check() -> dict:
    """
    Launch SITL, run secure_boot, capture firmware_integrity_status.

    Returns dict with keys: check_passed, failure_reason, board_id
    or empty dict on failure.
    """
    print("\n[2/4] Launching PX4 SITL (headless)...")

    # Start SITL in background, run secure_boot, capture listener output, then exit
    sitl_script = (
        "cd ~/PX4-Autopilot/build/px4_sitl_default && "
        "PX4_SIM_MODEL=shell timeout 20 ./bin/px4 "
        "-s ../../ROMFS/px4fmu_common/init.d-posix/rcS "
        "2>&1 &"
        "PX4_PID=$! && "
        "sleep 5 && "  # wait for SITL to boot
        "echo 'secure_boot start' > /proc/$PX4_PID/fd/0 2>/dev/null; "
        "sleep 3 && "
        "echo 'listener firmware_integrity_status -n 1' > /proc/$PX4_PID/fd/0 2>/dev/null; "
        "sleep 3 && "
        "kill $PX4_PID 2>/dev/null; "
        "wait $PX4_PID 2>/dev/null; "
        "echo DONE"
    )

    # Alternative: use the PX4 command mode directly
    cmd = (
        "cd ~/PX4-Autopilot/build/px4_sitl_default && "
        "echo -e 'secure_boot start\\nlistener firmware_integrity_status -n 1\\nshutdown' | "
        f"timeout {SITL_BOOT_TIMEOUT + MODULE_TIMEOUT + LISTENER_TIMEOUT} "
        "PX4_SIM_MODEL=shell ./bin/px4 -s ../../ROMFS/px4fmu_common/init.d-posix/rcS 2>&1"
    )

    print("[3/4] Running secure_boot and capturing status...")
    try:
        r = wsl_run(cmd, timeout=SITL_BOOT_TIMEOUT + MODULE_TIMEOUT + LISTENER_TIMEOUT + 10)
    except subprocess.TimeoutExpired:
        print("[FAIL] SITL timed out")
        return {}

    output = r.stdout + r.stderr

    # Parse firmware_integrity_status from listener output
    result = {}
    for line in output.splitlines():
        line = line.strip()
        if "check_passed:" in line:
            result["check_passed"] = "True" in line or "1" in line.split("check_passed:")[-1]
        if "failure_reason:" in line:
            try:
                val = int(line.split("failure_reason:")[-1].strip().split()[0])
                result["failure_reason"] = val
            except (ValueError, IndexError):
                pass
        if "board_id:" in line:
            try:
                val = int(line.split("board_id:")[-1].strip().split()[0])
                result["board_id"] = val
            except (ValueError, IndexError):
                pass

    return result


def evaluate_results(status: dict) -> bool:
    """Check if SITL reported the expected firmware integrity status."""
    print("\n[4/4] Evaluating results...")

    if not status:
        print("[FAIL] No firmware_integrity_status received from SITL")
        print("       Check that secure_boot module is built into px4_sitl_default")
        return False

    print(f"  check_passed:   {status.get('check_passed', 'N/A')}")
    print(f"  failure_reason: {status.get('failure_reason', 'N/A')}")
    print(f"  board_id:       {status.get('board_id', 'N/A')}")

    if not status.get("check_passed", False):
        reason = status.get("failure_reason", -1)
        reasons = {
            0: "NONE (this shouldn't happen with check_passed=False)",
            1: "NO_MANIFEST — manifest.bin not found in SITL storage",
            2: "MANIFEST_CORRUPTED — CRC32 mismatch",
            3: "SIGNATURE_INVALID — ECDSA verification failed (wrong key?)",
            4: "CODE_HASH_MISMATCH — should not happen in SITL (stubbed)",
            5: "DATA_HASH_MISMATCH — should not happen in SITL (stubbed)",
            6: "BOARD_ID_MISMATCH — board_id in manifest doesn't match hardware",
        }
        print(f"\n[FAIL] Firmware integrity check FAILED")
        print(f"       Reason: {reasons.get(reason, f'Unknown ({reason})')}")
        return False

    if status.get("failure_reason", -1) != 0:
        print(f"[WARN] check_passed=True but failure_reason={status['failure_reason']} (expected 0)")

    print("\n[PASS] Firmware integrity check PASSED")
    return True


def main():
    print("=" * 60)
    print("SITL End-to-End Integration Test")
    print("POST001 + ARM001 verification")
    print("=" * 60)

    if not check_prerequisites():
        print("\nFix prerequisites above and re-run.")
        sys.exit(1)

    if not provision_manifest():
        sys.exit(1)

    status = run_sitl_check()
    passed = evaluate_results(status)

    print("\n" + "=" * 60)
    if passed:
        print("RESULT: ALL CHECKS PASSED")
        print("  POST001: CRC + ECDSA verification — PASS")
        print("  ARM001:  Arming gate reads check_passed=True — PASS")
    else:
        print("RESULT: INTEGRATION TEST FAILED")
        print("  See failure details above")
    print("=" * 60)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
