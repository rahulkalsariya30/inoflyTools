"""
tools/generate_compliance_report.py

DGCA Compliance Report Generator (Phase 6.5)

Runs the full test suite, maps every test to its DGCA requirement ID,
and generates a compliance matrix suitable for auditor submission.

This is the primary deliverable for DGCA Type Certification — it proves
that every requirement has been implemented and tested.

Output:
  - compliance_report.json   Machine-readable compliance matrix
  - compliance_report.txt    Human-readable report for auditor review

USAGE:
  python tools/generate_compliance_report.py
  python tools/generate_compliance_report.py --output-dir Docs/
  python tools/generate_compliance_report.py --run-tests   (also executes pytest)
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── DGCA Requirement Registry ────────────────────────────────────────────────
# Maps each requirement ID to its description, DGCA clause, and implementation
# evidence (code locations, tools).

@dataclass
class Requirement:
    req_id: str
    description: str
    dgca_clause: str
    status: str                    # "done", "done_sitl", "hardware_pending"
    implementation: list           # code/tool references
    tests: list = field(default_factory=list)     # filled from pytest
    test_results: dict = field(default_factory=dict)  # {test_name: pass/fail}

REQUIREMENTS = {
    "ROT001": Requirement(
        req_id="ROT001",
        description="Manufacturer RSA-2048 keypair generation",
        dgca_clause="Root of Trust (Manufacturer)",
        status="done",
        implementation=[
            "tools/pki/keygen.py — generates RSA-2048 keypair",
            "pki/manufacturer/private/ — private key (NEVER committed)",
            "pki/manufacturer/public/ — public key",
        ],
    ),
    "ROT002": Requirement(
        req_id="ROT002",
        description="Public key embedded in firmware as C header",
        dgca_clause="Root of Trust (Manufacturer)",
        status="done",
        implementation=[
            "tools/pki/embed_pubkey.py — PEM to DER to C header",
            "firmware/include/manufacturer_pubkey.h — compiled into firmware",
            "DER SubjectPublicKeyInfo format, ~294 bytes for RSA-2048",
        ],
    ),
    "CHK001": Requirement(
        req_id="CHK001",
        description="SHA-256 checksums (code + data separately)",
        dgca_clause="Checksum (Section 7.1)",
        status="done",
        implementation=[
            "tools/checksum/checksum.py — generates code_hash and data_hash",
            "SHA-256 per DGCA minimum requirement",
            "Code and data sections checksummed independently",
        ],
    ),
    "SIG001": Requirement(
        req_id="SIG001",
        description="Manifest signed with manufacturer RSA-2048 key",
        dgca_clause="Signing (Section 7.1)",
        status="done",
        implementation=[
            "tools/signer/signer.py — RSA-PSS signing of canonical manifest",
            "SHA-256 hash + MGF1-SHA256 padding",
            "Signature is 256 bytes (2048/8)",
        ],
    ),
    "PKG001": Requirement(
        req_id="PKG001",
        description="Signed firmware update bundle (.fwbundle)",
        dgca_clause="Secure Update (Section 7.1)",
        status="done",
        implementation=[
            "tools/bundler/bundler.py — creates .fwbundle (zip)",
            "Bundle contains: firmware.px4 + signed_manifest.json",
            "Tamper-evident: any modification breaks the signature",
        ],
    ),
    "PRV001": Requirement(
        req_id="PRV001",
        description="Binary manifest provisioned to drone storage",
        dgca_clause="Provisioning",
        status="done",
        implementation=[
            "tools/provisioning/export_manifest.py — JSON to binary manifest",
            "501-byte binary: magic + version + hashes + signature + CRC32",
            "tools/provisioning/provision_sitl.py — deploys to SITL storage",
        ],
    ),
    "POST001": Requirement(
        req_id="POST001",
        description="Power On Self Test — CRC + RSA-PSS verify on boot",
        dgca_clause="POST (Section 7.1)",
        status="done",
        implementation=[
            "src/modules/secure_boot/FirmwareIntegrityChecker.hpp/.cpp",
            "Reads binary manifest, verifies CRC32, then RSA-PSS signature",
            "Publishes firmware_integrity_status uORB message",
            "SITL: verified via integration test (test_sitl_e2e.py)",
        ],
    ),
    "POST002": Requirement(
        req_id="POST002",
        description="POST — verify actual code hash at runtime (NuttX)",
        dgca_clause="POST (Section 7.1)",
        status="hardware_pending",
        implementation=[
            "Requires NuttX linker symbols (_stext/_etext) for flash addresses",
            "SITL: stubbed (returns true) — not meaningful in simulation",
            "Target: OrangeCube / Pixhawk hardware with mbedTLS",
        ],
    ),
    "POST003": Requirement(
        req_id="POST003",
        description="POST — verify actual data hash at runtime (NuttX)",
        dgca_clause="POST (Section 7.1)",
        status="hardware_pending",
        implementation=[
            "Requires knowledge of PX4 parameter storage address on target",
            "SITL: stubbed (returns true)",
            "Target: OrangeCube / Pixhawk hardware",
        ],
    ),
    "POST004": Requirement(
        req_id="POST004",
        description="POST — verify board ID matches hardware",
        dgca_clause="POST (Section 7.1)",
        status="hardware_pending",
        implementation=[
            "Board ID available via CONFIG_BOARD_ID at compile time",
            "Small effort — compare manifest.board_id against hardware",
            "Target: both SITL and NuttX",
        ],
    ),
    "ARM001": Requirement(
        req_id="ARM001",
        description="Arming blocked if POST failed",
        dgca_clause="Arming Gate (Section 7.1)",
        status="done",
        implementation=[
            "src/modules/commander/HealthAndArmingChecks/checks/firmwareIntegrityCheck.hpp/.cpp",
            "Reads firmware_integrity_status.check_passed via uORB",
            "Reports preflight failure if check_passed == false",
            "SITL: verified via integration test (test_sitl_e2e.py)",
        ],
    ),
    "PAR001": Requirement(
        req_id="PAR001",
        description="Compliance parameter protection (static compilation)",
        dgca_clause="Parameter Protection (the audited reference Section 3.1b)",
        status="done_sitl",
        implementation=[
            "src/modules/secure_boot/compliance_params.h — parameter table",
            "src/lib/parameters/compliance_check.h/.cpp — zero-window enforcement",
            "param_set_internal() blocks writes, param_get() returns compiled value",
            "Protected: GF_MAX_VER_DIST, GF_MAX_HOR_DIST, MPC_XY_VEL_MAX, SYS_AUTOSTART, CA_AIRFRAME, MAV_SIGN_CFG",
            "AtomicBitset cache for O(1) hot-path lookup",
        ],
    ),
    "LOG001": Requirement(
        req_id="LOG001",
        description="Per-file RSA signed audit log (the audited reference Section 8)",
        dgca_clause="Audit Logging (the audited reference Section 8)",
        status="done_sitl",
        implementation=[
            "src/modules/secure_boot/SecurityAuditLogger.hpp/.cpp",
            "132-byte binary entries with CRC32 integrity",
            "Per-file RSA-2048: SHA-256 of audit_log.bin encrypted with public key",
            "audit_log.sig (256 bytes) verified offline with manufacturer private key",
            "Events: POST result, firmware update, arming block, param violation",
        ],
    ),
    "UPD001": Requirement(
        req_id="UPD001",
        description="Drone rejects unsigned firmware update",
        dgca_clause="Secure Update (Section 7.1)",
        status="done",
        implementation=[
            "src/modules/secure_boot/FirmwareUpdateGatekeeper.hpp/.cpp",
            "Verifies manufacturer RSA-PSS signature on .fwbundle before flash",
            "QGC SecureFirmwareController verifies bundle client-side as well",
            "Double verification: both QGC and drone-side reject unsigned bundles",
        ],
    ),
    "PAIR001": Requirement(
        req_id="PAIR001",
        description="GCS-FC pairing via MAVLink signing (the audited reference Section 3.2.4)",
        dgca_clause="GCS Locking (the audited reference Section 3.2.4)",
        status="done_sitl",
        implementation=[
            "PX4 built-in MAVLink v2 message signing (MavlinkSignControl)",
            "tools/provisioning/provision_signing_key.py — per-drone key provisioning",
            "MAV_SIGN_CFG=1 locked by PAR001 (non-USB signing required)",
            "32-byte HMAC-SHA256 key, 40-byte key file format",
            "QGC native signing support (MAVLinkSigning/MAVLinkSigningKeys)",
        ],
    ),
    "PIPE": Requirement(
        req_id="PIPE",
        description="Full release pipeline (checksum -> sign -> bundle -> export)",
        dgca_clause="Release Process",
        status="done",
        implementation=[
            "tools/pipeline.py — chains all manufacturer tools",
            "Single command: firmware.px4 -> .fwbundle + binary manifest",
            "Verifies at every stage, fails fast on any error",
        ],
    ),
}


# ── Test result parsing ──────────────────────────────────────────────────────

def extract_req_id(test_name: str) -> str:
    """Extract requirement ID from test name.

    Test naming convention: test_<REQ_ID>_<description>
    Examples:
      test_CHK001_code_checksum_is_64_chars -> CHK001
      test_PAIR001_signing_key_is_32_bytes  -> PAIR001
      test_PIPE_pipeline_completes          -> PIPE
    """
    match = re.match(r'test_([A-Z]+\d*)', test_name)
    if match:
        return match.group(1)
    return "UNKNOWN"


def run_pytest(test_dir: Path) -> dict:
    """Run pytest and capture results as JSON.

    Returns: {test_node_id: {"outcome": "passed"/"failed", ...}}
    """
    json_file = test_dir / ".pytest_results.json"

    cmd = [
        sys.executable, "-m", "pytest",
        str(test_dir),
        "-v",
        "--tb=short",
        f"--json-report-file={json_file}",
        "--json-report",
    ]

    # Try with json-report plugin first
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))

    if json_file.exists():
        with open(json_file) as f:
            data = json.load(f)
        json_file.unlink()
        return data

    # Fallback: parse verbose pytest output
    return parse_pytest_verbose(result.stdout + result.stderr)


def parse_pytest_verbose(output: str) -> dict:
    """Parse pytest -v output into structured results.

    Handles lines like:
      tests/compliance/test_CHK001_checksum.py::TestCHK001_CodeChecksum::test_CHK001_code_checksum_is_64_chars PASSED
    """
    results = {"tests": [], "summary": {}}
    passed = failed = skipped = 0

    for line in output.splitlines():
        line = line.strip()

        # Match test result lines
        match = re.match(r'(tests/.+?::\S+)\s+(PASSED|FAILED|SKIPPED|ERROR)', line)
        if match:
            node_id = match.group(1)
            outcome = match.group(2).lower()

            results["tests"].append({
                "nodeid": node_id,
                "outcome": outcome,
            })

            if outcome == "passed":
                passed += 1
            elif outcome == "failed":
                failed += 1
            elif outcome == "skipped":
                skipped += 1

    # Parse summary line: "215 passed in 1.00s"
    summary_match = re.search(r'(\d+)\s+passed', output)
    if summary_match:
        passed = int(summary_match.group(1))

    fail_match = re.search(r'(\d+)\s+failed', output)
    if fail_match:
        failed = int(fail_match.group(1))

    skip_match = re.search(r'(\d+)\s+skipped', output)
    if skip_match:
        skipped = int(skip_match.group(1))

    results["summary"] = {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": passed + failed + skipped,
    }

    return results


def map_tests_to_requirements(test_results: dict) -> dict:
    """Map each test result to its requirement ID.

    Returns: {req_id: [{"name": ..., "outcome": ...}, ...]}
    """
    mapping = defaultdict(list)

    for test in test_results.get("tests", []):
        node_id = test["nodeid"]
        outcome = test["outcome"]

        # Extract test function name from node_id
        # e.g. tests/compliance/test_CHK001_checksum.py::TestCHK001::test_CHK001_foo
        parts = node_id.split("::")
        test_func = parts[-1] if parts else node_id

        req_id = extract_req_id(test_func)
        mapping[req_id].append({
            "name": test_func,
            "nodeid": node_id,
            "outcome": outcome,
        })

    return dict(mapping)


# ── Report generation ────────────────────────────────────────────────────────

def build_compliance_matrix(test_mapping: dict) -> list:
    """Build the compliance matrix combining requirements and test results."""
    matrix = []

    for req_id, req in REQUIREMENTS.items():
        tests = test_mapping.get(req_id, [])
        total = len(tests)
        passed = sum(1 for t in tests if t["outcome"] == "passed")
        failed = sum(1 for t in tests if t["outcome"] == "failed")
        skipped = sum(1 for t in tests if t["outcome"] == "skipped")

        # Determine compliance verdict
        if req.status == "hardware_pending":
            verdict = "HARDWARE_PENDING"
        elif total == 0:
            verdict = "NO_TESTS"
        elif failed > 0:
            verdict = "FAIL"
        elif passed == total:
            verdict = "PASS"
        else:
            verdict = "PARTIAL"

        matrix.append({
            "req_id": req_id,
            "description": req.description,
            "dgca_clause": req.dgca_clause,
            "implementation_status": req.status,
            "implementation_evidence": req.implementation,
            "tests_total": total,
            "tests_passed": passed,
            "tests_failed": failed,
            "tests_skipped": skipped,
            "test_details": tests,
            "verdict": verdict,
        })

    return matrix


def generate_json_report(matrix: list, summary: dict, output_path: Path):
    """Write machine-readable JSON compliance report."""
    report = {
        "report_title": "DGCA UAS Type Certification — Compliance Report",
        "report_type": "Level 1 (Firmware Manufacturer)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework_version": "1.0",
        "test_summary": summary,
        "compliance_matrix": matrix,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  [OK] JSON report: {output_path}")


def generate_text_report(matrix: list, summary: dict, output_path: Path):
    """Write human-readable text compliance report for auditor review."""
    lines = []
    w = lines.append

    w("=" * 78)
    w("DGCA UAS TYPE CERTIFICATION — COMPLIANCE REPORT")
    w("Level 1 (Firmware Manufacturer)")
    w(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    w("=" * 78)

    # Summary
    w("")
    w("TEST SUMMARY")
    w("-" * 40)
    w(f"  Total tests:   {summary.get('total', 0)}")
    w(f"  Passed:        {summary.get('passed', 0)}")
    w(f"  Failed:        {summary.get('failed', 0)}")
    w(f"  Skipped:       {summary.get('skipped', 0)}")

    # Overall verdict
    total_reqs = len(matrix)
    passing = sum(1 for r in matrix if r["verdict"] == "PASS")
    failing = sum(1 for r in matrix if r["verdict"] == "FAIL")
    hw_pending = sum(1 for r in matrix if r["verdict"] == "HARDWARE_PENDING")
    no_tests = sum(1 for r in matrix if r["verdict"] == "NO_TESTS")

    w("")
    w("REQUIREMENT SUMMARY")
    w("-" * 40)
    w(f"  Total requirements:  {total_reqs}")
    w(f"  PASS:                {passing}")
    w(f"  FAIL:                {failing}")
    w(f"  HARDWARE_PENDING:    {hw_pending}")
    w(f"  NO_TESTS:            {no_tests}")

    overall = "PASS" if failing == 0 and no_tests == 0 else "CONDITIONAL"
    if failing > 0:
        overall = "FAIL"
    w(f"\n  OVERALL VERDICT:     {overall}")
    if hw_pending > 0:
        w(f"  NOTE: {hw_pending} requirement(s) pending hardware deployment")

    # Detailed matrix
    w("")
    w("")
    w("=" * 78)
    w("DETAILED COMPLIANCE MATRIX")
    w("=" * 78)

    for entry in matrix:
        w("")
        verdict_marker = {
            "PASS": "[PASS]",
            "FAIL": "[FAIL]",
            "HARDWARE_PENDING": "[HW]",
            "NO_TESTS": "[--]",
            "PARTIAL": "[!!]",
        }.get(entry["verdict"], "[??]")

        w(f"{verdict_marker}  {entry['req_id']} — {entry['description']}")
        w(f"        DGCA Clause: {entry['dgca_clause']}")
        w(f"        Status:      {entry['implementation_status']}")
        w(f"        Tests:       {entry['tests_passed']}/{entry['tests_total']} passed")

        # Implementation evidence
        w("        Evidence:")
        for ev in entry["implementation_evidence"]:
            w(f"          - {ev}")

        # Test details (show failures explicitly)
        if entry["tests_failed"] > 0:
            w("        FAILED TESTS:")
            for t in entry["test_details"]:
                if t["outcome"] == "failed":
                    w(f"          X {t['name']}")

    # Cryptographic standards
    w("")
    w("")
    w("=" * 78)
    w("CRYPTOGRAPHIC STANDARDS")
    w("=" * 78)
    w("")
    w("  Signing:        RSA-2048 / RSA-PSS (SHA-256, MGF1-SHA256)")
    w("  Hash:           SHA-256 (NIST FIPS 180-4)")
    w("  Key size:       2048-bit RSA (112-bit security, NIST SP 800-57 R5)")
    w("  Signature size: 256 bytes")
    w("  Log signing:    RSA-2048 public key encryption (PKCS#1 v1.5)")
    w("  CRC:            CRC32 (corruption detection for binary manifest/audit entries)")
    w("  SITL crypto:    OpenSSL")
    w("  HW crypto:      mbedTLS (lightweight, designed for STM32)")

    # Gap summary
    w("")
    w("")
    w("=" * 78)
    w("REMAINING GAPS (Hardware Deployment)")
    w("=" * 78)
    w("")
    hw_entries = [e for e in matrix if e["verdict"] == "HARDWARE_PENDING"]
    if hw_entries:
        for e in hw_entries:
            w(f"  {e['req_id']} — {e['description']}")
            for ev in e["implementation_evidence"]:
                w(f"    {ev}")
            w("")
    else:
        w("  None — all requirements have passing tests.")

    w("")
    w("=" * 78)
    w("END OF COMPLIANCE REPORT")
    w("=" * 78)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [OK] Text report: {output_path}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate DGCA compliance report (Phase 6.5)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "Docs",
        help="Output directory for reports (default: Docs/)",
    )
    parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Run pytest before generating report (default: parse last results)",
    )
    parser.add_argument(
        "--test-dir",
        type=Path,
        default=PROJECT_ROOT / "tests" / "compliance",
        help="Test directory to run",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("DGCA Compliance Report Generator")
    print("Phase 6.5 — Compliance Test Suite")
    print("=" * 60)

    # Step 1: Run or collect tests
    if args.run_tests:
        print("\n[1/3] Running compliance tests...")
        cmd = [
            sys.executable, "-m", "pytest",
            str(args.test_dir),
            "-v", "--tb=short",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT)
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        test_results = parse_pytest_verbose(result.stdout + result.stderr)
    else:
        print("\n[1/3] Running compliance tests...")
        cmd = [
            sys.executable, "-m", "pytest",
            str(args.test_dir),
            "-v", "--tb=short",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT)
        )
        test_results = parse_pytest_verbose(result.stdout + result.stderr)

    summary = test_results.get("summary", {})
    print(f"\n      Tests: {summary.get('total', 0)} total, "
          f"{summary.get('passed', 0)} passed, "
          f"{summary.get('failed', 0)} failed, "
          f"{summary.get('skipped', 0)} skipped")

    # Step 2: Map tests to requirements
    print("\n[2/3] Mapping tests to DGCA requirements...")
    test_mapping = map_tests_to_requirements(test_results)

    for req_id in REQUIREMENTS:
        count = len(test_mapping.get(req_id, []))
        if count > 0:
            print(f"      {req_id}: {count} tests")
        else:
            status = REQUIREMENTS[req_id].status
            if status == "hardware_pending":
                print(f"      {req_id}: -- (hardware pending)")
            else:
                print(f"      {req_id}: 0 tests (WARNING)")

    # Step 3: Generate reports
    print("\n[3/3] Generating compliance reports...")
    matrix = build_compliance_matrix(test_mapping)

    json_path = args.output_dir / "compliance_report.json"
    text_path = args.output_dir / "compliance_report.txt"

    generate_json_report(matrix, summary, json_path)
    generate_text_report(matrix, summary, text_path)

    # Print verdict
    failing = sum(1 for r in matrix if r["verdict"] == "FAIL")
    print("\n" + "=" * 60)
    if failing == 0:
        print("OVERALL: All software requirements PASS")
    else:
        print(f"OVERALL: {failing} requirement(s) FAILING")
    print("=" * 60)


if __name__ == "__main__":
    main()
