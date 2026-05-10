"""
tests/compliance/test_POST004_board_id.py

Compliance tests for POST004 — Board ID verification on POST.

Requirement: POST004 (DGCA Section 7.1 — Power On Self Test, board-binding clause)
  - On every boot, the FC must verify the manifest's `board_id` field matches
    the hardware it is running on.
  - The expected board_id is injected at compile time from each board's
    `firmware.prototype` JSON (CubeOrange+ = 1063).
  - A mismatch (e.g. flashing CubeOrange+ firmware onto a Pixhawk) must fail
    POST and report `REASON_BOARD_ID_MISMATCH`.

This closes the gap where the manifest already carried a `board_id` field and
the failure-reason code already existed, but no runtime check was wired in.

These tests run against the PX4 firmware source in WSL (see PAR001 helpers).
"""

import re

import pytest

# Reuse the WSL plumbing from the PAR001 suite — same conventions, same
# skip-cleanly behavior on bare-Linux teammate machines.
from test_PAR001_param_protection import (
    WSL_SECURE_BOOT,
    _wsl_read,
)


WSL_BOARD_DIR = "$HOME/PX4-Autopilot/boards/cubepilot/cubeorangeplus"


def _read_cmake():
    return _wsl_read(f"{WSL_SECURE_BOOT}/CMakeLists.txt")


def _read_hpp():
    return _wsl_read(f"{WSL_SECURE_BOOT}/FirmwareIntegrityChecker.hpp")


def _read_cpp():
    return _wsl_read(f"{WSL_SECURE_BOOT}/FirmwareIntegrityChecker.cpp")


def _read_manifest_header():
    return _wsl_read(f"{WSL_SECURE_BOOT}/security_manifest.h")


def _read_status_msg():
    return _wsl_read("$HOME/PX4-Autopilot/msg/FirmwareIntegrityStatus.msg")


def _read_board_prototype():
    return _wsl_read(f"{WSL_BOARD_DIR}/firmware.prototype")


# ── 1. Hardware injection at compile time ────────────────────────────────────


class TestPOST004_BoardIdInjection:
    """The expected board_id must be injected from firmware.prototype, not
    hardcoded in C++. That's what keeps the check board-agnostic."""

    def test_POST004_cmake_reads_firmware_prototype(self):
        cmake = _read_cmake()
        assert 'PX4_BOARD_DIR}/firmware.prototype' in cmake, \
            "CMakeLists must read board_id from firmware.prototype"
        assert "string(JSON" in cmake and "board_id" in cmake, \
            "CMakeLists must parse board_id out of the JSON"

    def test_POST004_cmake_emits_compile_definition(self):
        cmake = _read_cmake()
        assert "SECURE_BOOT_BOARD_ID=" in cmake, \
            "CMakeLists must emit SECURE_BOOT_BOARD_ID as a compile-time constant"

    def test_POST004_cubeorangeplus_prototype_has_board_id(self):
        proto = _read_board_prototype()
        # Must be parseable JSON with a numeric board_id
        m = re.search(r'"board_id"\s*:\s*(\d+)', proto)
        assert m, "cubeorangeplus firmware.prototype is missing board_id"
        assert int(m.group(1)) == 1063, \
            f"CubeOrange+ board_id is canonically 1063, found {m.group(1)}"


# ── 2. Runtime check is declared and implemented ─────────────────────────────


class TestPOST004_RuntimeCheck:
    """The verify function must exist on both sides of the .hpp/.cpp split,
    must be guarded by SECURE_BOOT_BOARD_ID (so SITL stays a no-op), and
    must compare against m.board_id."""

    def test_POST004_method_declared_in_header(self):
        hpp = _read_hpp()
        assert "_verify_board_id" in hpp, \
            "FirmwareIntegrityChecker.hpp must declare _verify_board_id"

    def test_POST004_method_implemented_in_cpp(self):
        cpp = _read_cpp()
        assert "FirmwareIntegrityChecker::_verify_board_id" in cpp, \
            "FirmwareIntegrityChecker.cpp must implement _verify_board_id"

    def test_POST004_implementation_guarded_by_compile_define(self):
        cpp = _read_cpp()
        # The guard ensures SITL (no firmware.prototype) skips the check
        # rather than failing it.
        assert "defined(SECURE_BOOT_BOARD_ID)" in cpp, \
            "_verify_board_id must be guarded by SECURE_BOOT_BOARD_ID so SITL skips"

    def test_POST004_implementation_compares_manifest_board_id(self):
        cpp = _read_cpp()
        # m.board_id vs SECURE_BOOT_BOARD_ID — the actual comparison
        assert re.search(
            r"m\.board_id\s*!=\s*\(?\s*uint16_t\s*\)?\s*SECURE_BOOT_BOARD_ID",
            cpp,
        ), "Implementation must compare m.board_id against SECURE_BOOT_BOARD_ID"


# ── 3. Wired into the POST sequence with the right failure code ──────────────


class TestPOST004_PostSequenceWiring:
    """The check must be invoked from run() and report
    REASON_BOARD_ID_MISMATCH on failure — otherwise infrastructure is in place
    but POST silently passes for the wrong board."""

    def test_POST004_invoked_from_run(self):
        cpp = _read_cpp()
        # Look for the call site inside run()
        run_section = cpp.split("FirmwareIntegrityChecker::run", 1)
        assert len(run_section) == 2, "run() must exist in cpp"
        body = run_section[1]
        assert "_verify_board_id(manifest)" in body, \
            "run() must invoke _verify_board_id(manifest)"

    def test_POST004_failure_sets_board_id_mismatch_reason(self):
        cpp = _read_cpp()
        # The failure branch must set REASON_BOARD_ID_MISMATCH so the arming
        # check and audit log show the right reason. Generic "POST failed"
        # is not enough.
        assert "REASON_BOARD_ID_MISMATCH" in cpp, \
            "run() must set REASON_BOARD_ID_MISMATCH when _verify_board_id fails"

    def test_POST004_reason_code_declared_in_status_msg(self):
        msg = _read_status_msg()
        assert re.search(
            r"REASON_BOARD_ID_MISMATCH\s*=\s*6\b", msg
        ), "FirmwareIntegrityStatus.msg must declare REASON_BOARD_ID_MISMATCH = 6"

    def test_POST004_manifest_carries_board_id_field(self):
        # Sanity check: the field POST004 reads must exist in the manifest.
        # If anyone removes board_id from security_manifest_t, every POST004
        # check silently devolves to comparing zeros.
        hdr = _read_manifest_header()
        assert "uint16_t board_id" in hdr, \
            "security_manifest_t must carry uint16_t board_id"
