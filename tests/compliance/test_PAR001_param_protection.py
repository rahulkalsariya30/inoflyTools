"""
tests/compliance/test_PAR001_param_protection.py

Compliance tests for PAR001 — Compliance parameter protection (static compilation)

Requirement: PAR001
  - Safety-critical parameters must be statically compiled into firmware
  - Parameters cannot be changed from any GCS at runtime
  - compliance_params.h must define all required DGCA parameters
  - Values must be within safe/sane ranges
  - Table-driven: adding a parameter requires only editing the header

Reference: the audited reference-audited compliance document, Sections 3.1(b) and 7
"""

import re
import pytest
from pathlib import Path

# Path to PX4 source in WSL (accessible from Windows)
WSL_PX4 = Path(r"\\wsl.localhost\Ubuntu-22.04\home\rahul\PX4-Autopilot\src")
WSL_SECURE_BOOT = WSL_PX4 / "modules" / "secure_boot"
WSL_PARAMETERS = WSL_PX4 / "lib" / "parameters"
WSL_MAVLINK = WSL_PX4 / "modules" / "mavlink"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_header():
    """Read compliance_params.h and return its content."""
    header_path = WSL_SECURE_BOOT / "compliance_params.h"
    assert header_path.exists(), f"compliance_params.h not found at {header_path}"
    return header_path.read_text(encoding="utf-8")


def _strip_comments(content):
    """Remove C block comments (/* ... */) to avoid matching examples."""
    return re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)


def _parse_table_entries(content):
    """Extract parameter entries from the COMPLIANCE_PARAMS table.

    Returns list of (px4_name, description) tuples.
    Only matches non-commented entries.
    """
    cleaned = _strip_comments(content)
    pattern = r'\{"(\w+)",\s*"([^"]+)"'
    return re.findall(pattern, cleaned)


def _parse_table_values(content):
    """Extract parameter names and their compiled values from the table.

    Returns dict of {px4_name: value} where value is float or int.
    """
    cleaned = _strip_comments(content)
    result = {}

    # Match float entries: {"NAME", "desc", COMPLIANCE_TYPE_FLOAT, {.f = 120.0f}}
    float_pattern = r'\{"(\w+)",[^}]*COMPLIANCE_TYPE_FLOAT,\s*\{\.f\s*=\s*([\d.]+)f?\}'
    for name, val in re.findall(float_pattern, cleaned, re.DOTALL):
        result[name] = float(val)

    # Match int entries: {"NAME", "desc", COMPLIANCE_TYPE_INT32, {.i = 4001}}
    int_pattern = r'\{"(\w+)",[^}]*COMPLIANCE_TYPE_INT32,\s*\{\.i\s*=\s*(\d+)\}'
    for name, val in re.findall(int_pattern, cleaned, re.DOTALL):
        result[name] = int(val)

    return result


# ── Required parameters from DGCA audit (Section 3.1b) ──────────────────────

REQUIRED_PARAMS_DGCA = [
    "Max Altitude",   # GF_MAX_VER_DIST or similar
    "Max Speed",      # MPC_XY_VEL_MAX or similar
    "Fence Range",    # GF_MAX_HOR_DIST or similar
    "Frame Type",     # SYS_AUTOSTART or similar
]

# PX4 parameter names we expect in the table (minimum set)
EXPECTED_PX4_PARAMS = [
    "GF_MAX_VER_DIST",
    "GF_MAX_HOR_DIST",
    "MPC_XY_VEL_MAX",
    "SYS_AUTOSTART",
]


# ── Tests ────────────────────────────────────────────────────────────────────

class TestPAR001_HeaderExists:
    """PAR001: compliance_params.h must exist and be well-formed."""

    def test_PAR001_header_file_exists(self):
        """compliance_params.h must exist in the secure_boot module."""
        header_path = WSL_SECURE_BOOT / "compliance_params.h"
        assert header_path.exists()

    def test_PAR001_header_has_pragma_once(self):
        """Header must have include guard."""
        content = _read_header()
        assert "#pragma once" in content

    def test_PAR001_header_has_table(self):
        """Header must define the COMPLIANCE_PARAMS table."""
        content = _read_header()
        assert "COMPLIANCE_PARAMS[]" in content

    def test_PAR001_header_has_auto_count(self):
        """COMPLIANCE_PARAM_COUNT must be auto-calculated from table size."""
        content = _read_header()
        assert "sizeof(COMPLIANCE_PARAMS)" in content, \
            "COMPLIANCE_PARAM_COUNT should use sizeof for auto-calculation"


class TestPAR001_RequiredParameters:
    """PAR001: all DGCA-required parameters must be in the table."""

    def test_PAR001_has_max_altitude(self):
        """Table must include a max altitude parameter."""
        entries = _parse_table_entries(_read_header())
        px4_names = [e[0] for e in entries]
        assert "GF_MAX_VER_DIST" in px4_names, \
            "Missing max altitude (GF_MAX_VER_DIST)"

    def test_PAR001_has_max_speed(self):
        """Table must include a max speed parameter."""
        entries = _parse_table_entries(_read_header())
        px4_names = [e[0] for e in entries]
        assert "MPC_XY_VEL_MAX" in px4_names, \
            "Missing max speed (MPC_XY_VEL_MAX)"

    def test_PAR001_has_fence_range(self):
        """Table must include a fence range parameter."""
        entries = _parse_table_entries(_read_header())
        px4_names = [e[0] for e in entries]
        assert "GF_MAX_HOR_DIST" in px4_names, \
            "Missing fence range (GF_MAX_HOR_DIST)"

    def test_PAR001_has_frame_type(self):
        """Table must include a frame type parameter."""
        entries = _parse_table_entries(_read_header())
        px4_names = [e[0] for e in entries]
        assert "SYS_AUTOSTART" in px4_names, \
            "Missing frame type (SYS_AUTOSTART)"

    def test_PAR001_minimum_param_count(self):
        """Table must have at least 4 entries (DGCA minimum)."""
        entries = _parse_table_entries(_read_header())
        assert len(entries) >= 4, \
            f"Expected at least 4 protected parameters, found {len(entries)}"


class TestPAR001_ValueRanges:
    """PAR001: compiled values must be within safe/sane ranges."""

    def test_PAR001_altitude_positive(self):
        """Max altitude must be positive."""
        values = _parse_table_values(_read_header())
        assert "GF_MAX_VER_DIST" in values
        assert values["GF_MAX_VER_DIST"] > 0, "Altitude must be > 0"

    def test_PAR001_altitude_reasonable(self):
        """Max altitude must be <= 500m (reasonable for most drones)."""
        values = _parse_table_values(_read_header())
        assert values["GF_MAX_VER_DIST"] <= 500.0, \
            "Altitude > 500m seems unreasonable"

    def test_PAR001_speed_positive(self):
        """Max speed must be positive."""
        values = _parse_table_values(_read_header())
        assert "MPC_XY_VEL_MAX" in values
        assert values["MPC_XY_VEL_MAX"] > 0, "Speed must be > 0"

    def test_PAR001_speed_reasonable(self):
        """Max speed must be <= 50 m/s (reasonable for most drones)."""
        values = _parse_table_values(_read_header())
        assert values["MPC_XY_VEL_MAX"] <= 50.0, \
            "Speed > 50 m/s seems unreasonable"

    def test_PAR001_fence_range_positive(self):
        """Fence range must be positive."""
        values = _parse_table_values(_read_header())
        assert "GF_MAX_HOR_DIST" in values
        assert values["GF_MAX_HOR_DIST"] > 0, "Fence range must be > 0"

    def test_PAR001_frame_type_valid(self):
        """Frame type (SYS_AUTOSTART) must be a positive ID."""
        values = _parse_table_values(_read_header())
        assert "SYS_AUTOSTART" in values
        assert values["SYS_AUTOSTART"] > 0, \
            "Frame type must be a valid airframe ID"


class TestPAR001_TableFormat:
    """PAR001: table entries must be correctly structured."""

    def test_PAR001_entries_have_descriptions(self):
        """Every table entry must have a human-readable description."""
        entries = _parse_table_entries(_read_header())
        for px4_name, description in entries:
            assert len(description) > 0, \
                f"Parameter {px4_name} has empty description"

    def test_PAR001_entries_have_types(self):
        """Every table entry must specify COMPLIANCE_TYPE_FLOAT or INT32."""
        content = _read_header()
        entries = _parse_table_entries(content)
        for px4_name, _ in entries:
            # Find the type for this entry in the table
            pattern = rf'"{px4_name}".*?COMPLIANCE_TYPE_(FLOAT|INT32)'
            match = re.search(pattern, content, re.DOTALL)
            assert match, f"Parameter {px4_name} missing type specification"

    def test_PAR001_no_duplicate_params(self):
        """No parameter should appear twice in the table."""
        entries = _parse_table_entries(_read_header())
        px4_names = [e[0] for e in entries]
        assert len(px4_names) == len(set(px4_names)), \
            f"Duplicate parameters found: {px4_names}"


class TestPAR001_EnforcementCode:
    """PAR001: ComplianceParamGuard code must exist and be wired in."""

    def test_PAR001_guard_hpp_exists(self):
        """ComplianceParamGuard.hpp must exist."""
        assert (WSL_SECURE_BOOT / "ComplianceParamGuard.hpp").exists()

    def test_PAR001_guard_cpp_exists(self):
        """ComplianceParamGuard.cpp must exist."""
        assert (WSL_SECURE_BOOT / "ComplianceParamGuard.cpp").exists()

    def test_PAR001_guard_in_cmake(self):
        """ComplianceParamGuard.cpp must be in CMakeLists.txt."""
        cmake = (WSL_SECURE_BOOT / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "ComplianceParamGuard.cpp" in cmake

    def test_PAR001_guard_included_in_main(self):
        """secure_boot_main.cpp must include ComplianceParamGuard."""
        main = (WSL_SECURE_BOOT / "secure_boot_main.cpp").read_text(encoding="utf-8")
        assert '#include "ComplianceParamGuard.hpp"' in main

    def test_PAR001_guard_instantiated_in_main(self):
        """secure_boot_main.cpp must instantiate ComplianceParamGuard."""
        main = (WSL_SECURE_BOOT / "secure_boot_main.cpp").read_text(encoding="utf-8")
        assert "ComplianceParamGuard" in main
        assert "g_param_guard" in main

    def test_PAR001_param_status_command(self):
        """secure_boot must support 'param_status' command."""
        main = (WSL_SECURE_BOOT / "secure_boot_main.cpp").read_text(encoding="utf-8")
        assert "param_status" in main

    def test_PAR001_audit_event_on_violation(self):
        """ComplianceParamGuard must publish audit events on violations."""
        cpp = (WSL_SECURE_BOOT / "ComplianceParamGuard.cpp").read_text(encoding="utf-8")
        assert "security_audit_event" in cpp
        assert "EVENT_PARAM_CHANGE" in cpp

    def test_PAR001_guard_registers_violation_callback(self):
        """ComplianceParamGuard must register a violation callback."""
        cpp = (WSL_SECURE_BOOT / "ComplianceParamGuard.cpp").read_text(encoding="utf-8")
        assert "param_set_compliance_violation_cb" in cpp


class TestPAR001_ZeroWindowProtection:
    """PAR001: zero-window protection must be wired into PX4 parameter library."""

    def test_PAR001_compliance_check_h_exists(self):
        """compliance_check.h must exist in the parameters library."""
        assert (WSL_PARAMETERS / "compliance_check.h").exists()

    def test_PAR001_compliance_check_cpp_exists(self):
        """compliance_check.cpp must exist in the parameters library."""
        assert (WSL_PARAMETERS / "compliance_check.cpp").exists()

    def test_PAR001_compliance_check_in_cmake(self):
        """compliance_check.cpp must be in the parameters CMakeLists.txt."""
        cmake = (WSL_PARAMETERS / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "compliance_check.cpp" in cmake

    def test_PAR001_param_h_declares_protection(self):
        """param.h must declare param_is_compliance_protected."""
        header = (WSL_PARAMETERS / "param.h").read_text(encoding="utf-8")
        assert "param_is_compliance_protected" in header

    def test_PAR001_param_set_has_guard(self):
        """param_set_internal must block writes to protected params."""
        cpp = (WSL_PARAMETERS / "parameters.cpp").read_text(encoding="utf-8")
        assert "param_is_compliance_protected" in cpp
        assert "param_notify_compliance_violation" in cpp

    def test_PAR001_param_get_has_override(self):
        """param_get must return compiled value for protected params."""
        cpp = (WSL_PARAMETERS / "parameters.cpp").read_text(encoding="utf-8")
        assert "param_get_compliance_value" in cpp

    def test_PAR001_param_reset_has_guard(self):
        """param_reset_internal must skip protected params."""
        cpp = (WSL_PARAMETERS / "parameters.cpp").read_text(encoding="utf-8")
        # Check that compliance protection is checked in reset context
        pattern = r'param_reset_internal.*?param_is_compliance_protected'
        assert re.search(pattern, cpp, re.DOTALL), \
            "param_reset_internal must check compliance protection"

    def test_PAR001_param_reset_all_skips_protected(self):
        """param_reset_all_internal must skip protected params in loop."""
        cpp = (WSL_PARAMETERS / "parameters.cpp").read_text(encoding="utf-8")
        pattern = r'param_reset_all_internal.*?param_is_compliance_protected.*?continue'
        assert re.search(pattern, cpp, re.DOTALL), \
            "param_reset_all_internal must skip protected params"

    def test_PAR001_mavlink_handler_checks_protection(self):
        """MAVLink PARAM_SET handler must check compliance protection."""
        cpp = (WSL_MAVLINK / "mavlink_parameters.cpp").read_text(encoding="utf-8")
        assert "param_is_compliance_protected" in cpp
        assert "MAV_PARAM_ERROR_READ_ONLY" in cpp

    def test_PAR001_compliance_check_has_bitset_cache(self):
        """compliance_check.cpp must use AtomicBitset for O(1) lookups."""
        cpp = (WSL_PARAMETERS / "compliance_check.cpp").read_text(encoding="utf-8")
        assert "AtomicBitset" in cpp

    def test_PAR001_compliance_check_has_stubs(self):
        """compliance_check.cpp must have no-op stubs when secure_boot is disabled."""
        cpp = (WSL_PARAMETERS / "compliance_check.cpp").read_text(encoding="utf-8")
        assert "CONFIG_MODULES_SECURE_BOOT" in cpp
        # Stubs must return false / -1 (no protection when module not enabled)
        assert "return false" in cpp
        assert "return -1" in cpp

    def test_PAR001_compliance_check_includes_table(self):
        """compliance_check.cpp must include compliance_params.h."""
        cpp = (WSL_PARAMETERS / "compliance_check.cpp").read_text(encoding="utf-8")
        assert 'compliance_params.h' in cpp

    def test_PAR001_cmake_has_include_path(self):
        """Parameters CMakeLists.txt must add secure_boot include path."""
        cmake = (WSL_PARAMETERS / "CMakeLists.txt").read_text(encoding="utf-8")
        assert "CONFIG_MODULES_SECURE_BOOT" in cmake
        assert "secure_boot" in cmake
