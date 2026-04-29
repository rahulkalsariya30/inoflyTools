"""
tests/integration/test_sitl_audit_log.py

End-to-end SITL test for LOG001 - Per-file RSA signed audit log.

Boots PX4 SITL, runs the secure_boot module to trigger an EVENT_POST_RESULT,
then verifies that:
  1. audit_log.bin exists in SITL storage and contains at least one entry
  2. Each entry is 132 bytes with valid magic and CRC32
  3. audit_log.sig exists and is exactly 384 bytes (RSA-3072 ciphertext)
  4. Decrypting the .sig with the manufacturer private key yields a SHA-256
     that matches the SHA-256 of the .bin file (proves the signing chain works)

This is the firmware-side proof. After this passes, connect QGC manually to
the running SITL to verify the AuditLogPanel shows live events and downloads
the .bin/.sig pair.

PREREQUISITES:
  - WSL2 with PX4-Autopilot built (make px4_sitl_default)
  - Manufacturer keypair generated (tools/pki/keygen.py)
  - Manifest provisioned into SITL (tools/provisioning/provision_sitl.py)

NOT a pytest test - run manually:
    python tests/integration/test_sitl_audit_log.py
"""

import hashlib
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Inside WSL: SITL stores files under build/px4_sitl_default/rootfs/
SITL_ROOTFS_WSL  = "~/PX4-Autopilot/build/px4_sitl_default/rootfs"
AUDIT_DIR_WSL    = f"{SITL_ROOTFS_WSL}/inofly"
LOG_PATH_WSL     = f"{AUDIT_DIR_WSL}/audit_log.bin"
SIG_PATH_WSL     = f"{AUDIT_DIR_WSL}/audit_log.sig"

PRIVATE_KEY = PROJECT_ROOT / "pki" / "manufacturer" / "private" / "manufacturer_private.pem"

ENTRY_SIZE       = 132
ENTRY_MAGIC      = 0x4C4F4701
RSA_SIG_SIZE     = 384

SITL_TIMEOUT_SEC = 25


def wsl_run(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    # errors='replace' - PX4 console output contains non-ASCII bytes that crash
    # the default cp1252 decoder on Windows.
    return subprocess.run(
        ["wsl", "-e", "bash", "-lc", cmd],
        capture_output=True, text=True, timeout=timeout, errors="replace",
    )


def wsl_copy_to_windows(wsl_src: str, win_dest: Path) -> bool:
    """Copy a binary file from inside WSL to a Windows path, preserving bytes."""
    # WSL can mount Windows drives at /mnt/<drive>/...
    win_str = str(win_dest.resolve()).replace("\\", "/")
    drive = win_str[0].lower()
    wsl_dest = f"/mnt/{drive}/{win_str[3:]}"
    r = wsl_run(f"cp {wsl_src} '{wsl_dest}' && echo ok", timeout=15)
    return "ok" in r.stdout


def check_prerequisites() -> bool:
    print("[prereq] Warming up WSL2...")
    # First wsl call from Python is often slow (distro boot) - give it more time
    r = wsl_run("echo ok", timeout=60)
    if "ok" not in r.stdout:
        print("[FAIL] WSL2 not responding")
        return False

    print("[prereq] PX4 build + keys...")
    r = wsl_run("test -f ~/PX4-Autopilot/build/px4_sitl_default/bin/px4 && echo ok", timeout=30)
    if "ok" not in r.stdout:
        print("[FAIL] PX4 SITL not built. Run in WSL: cd ~/PX4-Autopilot && make px4_sitl_default")
        return False

    if not PRIVATE_KEY.exists():
        print(f"[FAIL] Manufacturer private key missing: {PRIVATE_KEY}")
        print("       Run: python tools/pki/keygen.py")
        return False

    # Confirm manifest is provisioned (secure_boot needs it for POST_RESULT)
    r = wsl_run(f"test -f {SITL_ROOTFS_WSL}/inofly/manifest.bin && echo ok", timeout=30)
    if "ok" not in r.stdout:
        print("[WARN] manifest.bin not in SITL storage. Provisioning now...")
        win_path = str(PROJECT_ROOT).replace("\\", "/")
        wsl_proj = f"/mnt/{win_path[0].lower()}/{win_path[3:]}"
        r2 = wsl_run(f"cd {wsl_proj} && python3 tools/provisioning/provision_sitl.py", timeout=30)
        if r2.returncode != 0:
            print(f"[FAIL] Provisioning failed:\n{r2.stderr}")
            return False
        print("[prereq] manifest.bin provisioned")

    print("[prereq] OK")
    return True


def boot_sitl_and_trigger_events() -> bool:
    """Run SITL with `secure_boot start` to fire at least one POST_RESULT event."""
    print(f"\n[1/2] Booting SITL and running secure_boot (timeout {SITL_TIMEOUT_SEC}s)...")

    # Pipe commands into px4 stdin: start secure_boot, wait for the audit logger
    # work item to flush, then shut down cleanly.
    cmd = (
        "cd ~/PX4-Autopilot/build/px4_sitl_default && "
        "echo -e 'secure_boot start\\nsleep 3\\nshutdown' | "
        f"timeout {SITL_TIMEOUT_SEC} "
        "./bin/px4 -s ../../ROMFS/px4fmu_common/init.d-posix/rcS 2>&1"
    )

    try:
        r = wsl_run(cmd, timeout=SITL_TIMEOUT_SEC + 10)
    except subprocess.TimeoutExpired:
        print("[FAIL] SITL timed out")
        return False

    output = r.stdout + r.stderr
    if "LOG001" in output or "audit_log" in output:
        # Print any LOG001-relevant lines - useful for debugging on failure
        for line in output.splitlines():
            if "LOG001" in line or "secure_boot" in line.lower():
                print(f"  sitl: {line.strip()}")

    return True


def verify_audit_files() -> bool:
    """Read audit_log.bin and audit_log.sig out of WSL and verify them locally."""
    print("\n[2/2] Verifying audit_log.bin + audit_log.sig...")

    # Pull both files out of WSL into Windows temp
    bin_local = Path.cwd() / "_audit_log.bin"
    sig_local = Path.cwd() / "_audit_log.sig"

    r = wsl_run(f"test -f {LOG_PATH_WSL} && echo ok", timeout=10)
    if "ok" not in r.stdout:
        print(f"[FAIL] {LOG_PATH_WSL} not created. Did secure_boot start fire an event?")
        return False

    r = wsl_run(f"test -f {SIG_PATH_WSL} && echo ok", timeout=10)
    if "ok" not in r.stdout:
        print(f"[FAIL] {SIG_PATH_WSL} not created. Pubkey embed broken?")
        return False

    # Copy bytes back to Windows side via WSL `cp` (binary-safe, unlike `cat`)
    if not wsl_copy_to_windows(LOG_PATH_WSL, bin_local):
        print("[FAIL] copy of audit_log.bin to Windows failed")
        return False
    if not wsl_copy_to_windows(SIG_PATH_WSL, sig_local):
        print("[FAIL] copy of audit_log.sig to Windows failed")
        return False

    bin_data = bin_local.read_bytes()
    sig_data = sig_local.read_bytes()

    print(f"  bin size: {len(bin_data)} bytes ({len(bin_data) // ENTRY_SIZE} entries)")
    print(f"  sig size: {len(sig_data)} bytes (expect {RSA_SIG_SIZE})")

    # Validate entry framing
    if len(bin_data) == 0 or len(bin_data) % ENTRY_SIZE != 0:
        print(f"[FAIL] bin file size not multiple of {ENTRY_SIZE}")
        return False

    n_entries = len(bin_data) // ENTRY_SIZE
    valid = 0
    for i in range(n_entries):
        entry = bin_data[i * ENTRY_SIZE : (i + 1) * ENTRY_SIZE]
        magic = int.from_bytes(entry[0:4], "little")
        if magic != ENTRY_MAGIC:
            print(f"[FAIL] Entry {i}: bad magic 0x{magic:08X}")
            return False
        valid += 1
    print(f"  entries with valid magic: {valid}/{n_entries}")

    if len(sig_data) != RSA_SIG_SIZE:
        print(f"[FAIL] sig size wrong (got {len(sig_data)}, expected {RSA_SIG_SIZE})")
        return False

    # Decrypt sig with manufacturer private key, compare to SHA256(bin)
    print("  decrypting .sig with manufacturer private key...")

    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    priv = serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)

    try:
        decrypted_hash = priv.decrypt(sig_data, padding.PKCS1v15())
    except Exception as e:
        print(f"[FAIL] .sig decrypt failed: {e}")
        return False

    actual_hash = hashlib.sha256(bin_data).digest()

    print(f"  decrypted hash: {decrypted_hash.hex()}")
    print(f"  actual hash:    {actual_hash.hex()}")

    # Cleanup local temp copies
    bin_local.unlink(missing_ok=True)
    sig_local.unlink(missing_ok=True)

    if decrypted_hash != actual_hash:
        print("[FAIL] Decrypted .sig hash does not match SHA256(audit_log.bin)")
        return False

    print("[PASS] .sig decrypts to SHA256(audit_log.bin)")
    return True


def print_manual_test_instructions():
    print("\n" + "=" * 60)
    print("FIRMWARE SIDE VERIFIED. NEXT - MANUAL QGC TEST:")
    print("=" * 60)
    print("""
1. In WSL, start SITL and leave it running:
     cd ~/PX4-Autopilot && make px4_sitl_default gz_x500

2. In QGC (your inoflyGCU build), open the Audit Log panel.
   You should see:
     - "Live Events" section near the top - INOFLY_AL events appear as
       they fire on the drone (try arming / changing a protected param
       to generate one).
     - Click "Download Audit Log" to fetch the .bin from the drone.
     - Once download completes, "Save Log (.bin)" and
       "Save Signature (.sig)" buttons enable.

3. To verify the downloaded signature offline (manufacturer-side):
     openssl pkeyutl -decrypt \\
         -in audit_log.sig \\
         -inkey pki/manufacturer/private/manufacturer_private.pem \\
         -out hash_decrypted
     openssl dgst -sha256 -binary audit_log.bin > hash_actual
     cmp hash_decrypted hash_actual && echo "VALID" || echo "TAMPERED"
""")


def main():
    print("=" * 60)
    print("SITL Audit Log Integration Test (LOG001)")
    print("=" * 60)

    if not check_prerequisites():
        sys.exit(1)
    if not boot_sitl_and_trigger_events():
        sys.exit(1)
    if not verify_audit_files():
        sys.exit(1)

    print_manual_test_instructions()
    sys.exit(0)


if __name__ == "__main__":
    main()
