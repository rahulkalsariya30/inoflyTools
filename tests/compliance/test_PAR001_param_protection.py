"""
tests/compliance/test_PAR001_param_protection.py

Compliance tests for PAR001 — Compliance parameter protection
(static ceiling + cap-semantics, ADR-019, supersedes ADR-007 enforcement
model).

Requirement: PAR001
  - Safety-critical parameters' ceilings are statically compiled into
    firmware in the .compliance_params flash table covered by data_hash
  - Operator may param_set v for v in (0, ceiling]; values live in RAM
    only and are not persisted across reboots
  - Boot value is 0; pre-arm blocks arming until every compliance param
    has been set above 0 (Commander ComplianceParamCheck)
  - Over-cap attempts (v > ceiling, or v <= 0) are rejected and routed
    through the violation callback for LOG001 audit logging, with
    attempted+ceiling included in the detail field
  - compliance_params.h must define all required DGCA parameters
  - Values (ceilings) must be within safe/sane ranges
  - Table-driven: adding a parameter requires only editing the header

Reference: the audited reference-audited compliance document Sections 3.1(b) and 7;
Docs/ARCHITECTURE.md ADR-019 for the cap-semantics rationale.
"""

import re
import subprocess
from functools import lru_cache

import pytest

# WSL paths to PX4 source. Windows-side pytest cannot resolve
# `\\wsl.localhost\...` UNC paths through pathlib reliably, so we
# shell out via `wsl -e bash -c "..."` (the same pattern PAIR001 uses)
# and skip cleanly if WSL or the file is unavailable.
WSL_PX4_SRC = "$HOME/PX4-Autopilot/src"
WSL_SECURE_BOOT = f"{WSL_PX4_SRC}/modules/secure_boot"
WSL_PARAMETERS = f"{WSL_PX4_SRC}/lib/parameters"
WSL_MAVLINK = f"{WSL_PX4_SRC}/modules/mavlink"
WSL_COMMANDER_CHECKS = (
    f"{WSL_PX4_SRC}/modules/commander/HealthAndArmingChecks/checks"
)


# ── Helpers ──────────────────────────────────────────────────────────────────

@lru_cache(maxsize=None)
def _wsl_available():
    """Detect once whether `wsl` itself is callable on this machine.

    The PX4 source is only present on machines with a WSL2 install — on a
    teammate's bare Linux/macOS box there is no `wsl` command at all, and
    these tests should skip cleanly there.
    """
    try:
        # 30s, not 10 — WSL cold-start (first call after the VM idles
        # out) routinely takes 12–20s on Windows hosts. A 10s timeout
        # here was masking a cold WSL as "not available" and silently
        # skipping the entire suite.
        result = subprocess.run(
            ["wsl", "-e", "bash", "-c", "true"],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _require_wsl():
    if not _wsl_available():
        pytest.skip("WSL not available on this machine")


@lru_cache(maxsize=None)
def _wsl_read(wsl_path):
    """Read a file from WSL via `wsl -e bash -c 'cat ...'`.

    Skips when WSL itself is unavailable (env issue); raises a clear
    AssertionError when the file is missing (implementation gap — we
    want this to surface as a test failure, not a silent skip).
    """
    _require_wsl()
    result = subprocess.run(
        ["wsl", "-e", "bash", "-c", f"cat {wsl_path}"],
        capture_output=True,
    )
    assert result.returncode == 0, (
        f"Cannot read {wsl_path} from WSL: "
        f"{result.stderr.decode('utf-8', errors='replace').strip()}"
    )
    return result.stdout.decode("utf-8", errors="replace")


@lru_cache(maxsize=None)
def _wsl_exists(wsl_path):
    """Return True if `wsl_path` exists in WSL. Skips if WSL itself is unavailable."""
    _require_wsl()
    result = subprocess.run(
        ["wsl", "-e", "bash", "-c", f"test -e {wsl_path} && echo 1 || echo 0"],
        capture_output=True,
    )
    return result.stdout.strip() == b"1"


def _read_header():
    """Read compliance_params.h and return its content."""
    return _wsl_read(f"{WSL_SECURE_BOOT}/compliance_params.h")


def _read_table_source():
    """Read compliance_params.cpp — where the COMPLIANCE_PARAMS[] table now
    lives (moved from the header in ADR-018, code/data hash split). The
    section attribute on the definition forces the table into the dedicated
    .compliance_params flash section; only one .cpp can hold it.
    """
    return _wsl_read(f"{WSL_SECURE_BOOT}/compliance_params.cpp")


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
    float_pattern = r'\{"(\w+)",[^}]*COMPLIANCE_TYPE_FLOAT,\s*COMPLIANCE_KIND_\w+,\s*\{\.f\s*=\s*([\d.]+)f?\}'
    for name, val in re.findall(float_pattern, cleaned, re.DOTALL):
        result[name] = float(val)

    # Match int entries: {"NAME", "desc", COMPLIANCE_TYPE_INT32, {.i = 4001}}
    int_pattern = r'\{"(\w+)",[^}]*COMPLIANCE_TYPE_INT32,\s*COMPLIANCE_KIND_\w+,\s*\{\.i\s*=\s*(\d+)\}'
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
        assert _wsl_exists(f"{WSL_SECURE_BOOT}/compliance_params.h")

    def test_PAR001_header_has_pragma_once(self):
        """Header must have include guard."""
        content = _read_header()
        assert "#pragma once" in content

    def test_PAR001_header_declares_table(self):
        """Header must forward-declare the COMPLIANCE_PARAMS table.

        The table itself lives in compliance_params.cpp (ADR-018) so that
        a single definition can be tagged into the .compliance_params flash
        section. The header carries only the extern declaration.
        """
        content = _read_header()
        assert "extern const compliance_param_def_t COMPLIANCE_PARAMS[]" in content
        assert "extern const size_t" in content and "COMPLIANCE_PARAM_COUNT" in content

    def test_PAR001_table_source_has_auto_count(self):
        """COMPLIANCE_PARAM_COUNT must be auto-calculated from table size
        in compliance_params.cpp (no hand-maintained literal)."""
        content = _read_table_source()
        assert "sizeof(COMPLIANCE_PARAMS)" in content, \
            "COMPLIANCE_PARAM_COUNT should be derived via sizeof, not a literal"

    def test_PAR001_table_in_compliance_params_section(self):
        """Definition must carry the .compliance_params section attribute
        so the linker places it where POST003 / data_hash hashes it."""
        content = _read_table_source()
        assert 'section(".compliance_params")' in content, \
            "COMPLIANCE_PARAMS[] must use __attribute__((section(\".compliance_params\")))"


class TestPAR001_RequiredParameters:
    """PAR001: all DGCA-required parameters must be in the table."""

    def test_PAR001_has_max_altitude(self):
        """Table must include a max altitude parameter."""
        entries = _parse_table_entries(_read_table_source())
        px4_names = [e[0] for e in entries]
        assert "GF_MAX_VER_DIST" in px4_names, \
            "Missing max altitude (GF_MAX_VER_DIST)"

    def test_PAR001_has_max_speed(self):
        """Table must include a max speed parameter."""
        entries = _parse_table_entries(_read_table_source())
        px4_names = [e[0] for e in entries]
        assert "MPC_XY_VEL_MAX" in px4_names, \
            "Missing max speed (MPC_XY_VEL_MAX)"

    def test_PAR001_has_fence_range(self):
        """Table must include a fence range parameter."""
        entries = _parse_table_entries(_read_table_source())
        px4_names = [e[0] for e in entries]
        assert "GF_MAX_HOR_DIST" in px4_names, \
            "Missing fence range (GF_MAX_HOR_DIST)"

    def test_PAR001_has_frame_type(self):
        """Table must include a frame type parameter."""
        entries = _parse_table_entries(_read_table_source())
        px4_names = [e[0] for e in entries]
        assert "SYS_AUTOSTART" in px4_names, \
            "Missing frame type (SYS_AUTOSTART)"

    def test_PAR001_minimum_param_count(self):
        """Table must have at least 4 entries (DGCA minimum)."""
        entries = _parse_table_entries(_read_table_source())
        assert len(entries) >= 4, \
            f"Expected at least 4 protected parameters, found {len(entries)}"


class TestPAR001_ValueRanges:
    """PAR001: compiled values must be within safe/sane ranges."""

    def test_PAR001_altitude_positive(self):
        """Max altitude must be positive."""
        values = _parse_table_values(_read_table_source())
        assert "GF_MAX_VER_DIST" in values
        assert values["GF_MAX_VER_DIST"] > 0, "Altitude must be > 0"

    def test_PAR001_altitude_reasonable(self):
        """Max altitude must be <= 500m (reasonable for most drones)."""
        values = _parse_table_values(_read_table_source())
        assert values["GF_MAX_VER_DIST"] <= 500.0, \
            "Altitude > 500m seems unreasonable"

    def test_PAR001_speed_positive(self):
        """Max speed must be positive."""
        values = _parse_table_values(_read_table_source())
        assert "MPC_XY_VEL_MAX" in values
        assert values["MPC_XY_VEL_MAX"] > 0, "Speed must be > 0"

    def test_PAR001_speed_reasonable(self):
        """Max speed must be <= 50 m/s (reasonable for most drones)."""
        values = _parse_table_values(_read_table_source())
        assert values["MPC_XY_VEL_MAX"] <= 50.0, \
            "Speed > 50 m/s seems unreasonable"

    def test_PAR001_fence_range_positive(self):
        """Fence range must be positive."""
        values = _parse_table_values(_read_table_source())
        assert "GF_MAX_HOR_DIST" in values
        assert values["GF_MAX_HOR_DIST"] > 0, "Fence range must be > 0"

    def test_PAR001_frame_type_valid(self):
        """Frame type (SYS_AUTOSTART) must be a positive ID."""
        values = _parse_table_values(_read_table_source())
        assert "SYS_AUTOSTART" in values
        assert values["SYS_AUTOSTART"] > 0, \
            "Frame type must be a valid airframe ID"


class TestPAR001_TableFormat:
    """PAR001: table entries must be correctly structured."""

    def test_PAR001_entries_have_descriptions(self):
        """Every table entry must have a human-readable description."""
        entries = _parse_table_entries(_read_table_source())
        for px4_name, description in entries:
            assert len(description) > 0, \
                f"Parameter {px4_name} has empty description"

    def test_PAR001_entries_have_types(self):
        """Every table entry must specify COMPLIANCE_TYPE_FLOAT or INT32."""
        content = _read_table_source()
        entries = _parse_table_entries(content)
        for px4_name, _ in entries:
            # Find the type for this entry in the table
            pattern = rf'"{px4_name}".*?COMPLIANCE_TYPE_(FLOAT|INT32)'
            match = re.search(pattern, content, re.DOTALL)
            assert match, f"Parameter {px4_name} missing type specification"

    def test_PAR001_no_duplicate_params(self):
        """No parameter should appear twice in the table."""
        entries = _parse_table_entries(_read_table_source())
        px4_names = [e[0] for e in entries]
        assert len(px4_names) == len(set(px4_names)), \
            f"Duplicate parameters found: {px4_names}"


class TestPAR001_EnforcementCode:
    """PAR001: ComplianceParamGuard code must exist and be wired in."""

    def test_PAR001_guard_hpp_exists(self):
        """ComplianceParamGuard.hpp must exist."""
        assert _wsl_exists(f"{WSL_SECURE_BOOT}/ComplianceParamGuard.hpp")

    def test_PAR001_guard_cpp_exists(self):
        """ComplianceParamGuard.cpp must exist."""
        assert _wsl_exists(f"{WSL_SECURE_BOOT}/ComplianceParamGuard.cpp")

    def test_PAR001_guard_in_cmake(self):
        """ComplianceParamGuard.cpp must be in CMakeLists.txt."""
        cmake = _wsl_read(f"{WSL_SECURE_BOOT}/CMakeLists.txt")
        assert "ComplianceParamGuard.cpp" in cmake

    def test_PAR001_guard_included_in_main(self):
        """secure_boot_main.cpp must include ComplianceParamGuard."""
        main = _wsl_read(f"{WSL_SECURE_BOOT}/secure_boot_main.cpp")
        assert '#include "ComplianceParamGuard.hpp"' in main

    def test_PAR001_guard_instantiated_in_main(self):
        """secure_boot_main.cpp must instantiate ComplianceParamGuard."""
        main = _wsl_read(f"{WSL_SECURE_BOOT}/secure_boot_main.cpp")
        assert "ComplianceParamGuard" in main
        assert "g_param_guard" in main

    def test_PAR001_param_status_command(self):
        """secure_boot must support 'param_status' command."""
        main = _wsl_read(f"{WSL_SECURE_BOOT}/secure_boot_main.cpp")
        assert "param_status" in main

    def test_PAR001_audit_event_on_violation(self):
        """ComplianceParamGuard must publish audit events on violations."""
        cpp = _wsl_read(f"{WSL_SECURE_BOOT}/ComplianceParamGuard.cpp")
        assert "security_audit_event" in cpp
        assert "EVENT_PARAM_CHANGE" in cpp

    def test_PAR001_guard_registers_violation_callback(self):
        """ComplianceParamGuard must register a violation callback."""
        cpp = _wsl_read(f"{WSL_SECURE_BOOT}/ComplianceParamGuard.cpp")
        assert "param_set_compliance_violation_cb" in cpp


class TestPAR001_CapSemanticsProtection:
    """PAR001 cap-semantics (ADR-019) must be wired into PX4 parameter library."""

    def test_PAR001_compliance_check_h_exists(self):
        """compliance_check.h must exist in the parameters library."""
        assert _wsl_exists(f"{WSL_PARAMETERS}/compliance_check.h")

    def test_PAR001_compliance_check_cpp_exists(self):
        """compliance_check.cpp must exist in the parameters library."""
        assert _wsl_exists(f"{WSL_PARAMETERS}/compliance_check.cpp")

    def test_PAR001_compliance_check_in_cmake(self):
        """compliance_check.cpp must be in the parameters CMakeLists.txt."""
        cmake = _wsl_read(f"{WSL_PARAMETERS}/CMakeLists.txt")
        assert "compliance_check.cpp" in cmake

    def test_PAR001_param_h_declares_protection(self):
        """param.h must declare param_is_compliance_protected."""
        header = _wsl_read(f"{WSL_PARAMETERS}/param.h")
        assert "param_is_compliance_protected" in header

    def test_PAR001_api_exposes_cap_semantics_helpers(self):
        """compliance_check.h must expose the cap-semantics helpers
        (ADR-019): ceiling getter, cap check, pre-arm helper. The
        legacy zero-window getter (param_get_compliance_value) must be
        gone — no caller should still depend on the old name."""
        header = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.h")
        assert "param_get_compliance_ceiling" in header
        assert "param_check_within_cap" in header
        assert "param_compliance_first_unset" in header
        assert "param_get_compliance_value" not in header, (
            "Legacy zero-window getter must be removed (ADR-019)"
        )

    def test_PAR001_param_set_uses_cap_check(self):
        """param_set_internal must use the cap check, not a blanket
        block, for compliance-protected params (ADR-019). The new
        violation notifier carries (name, attempted, param) — the
        old single-arg call signature must be gone."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        assert "param_check_within_cap" in cpp, (
            "param_set must call param_check_within_cap (ADR-019)"
        )
        assert "param_notify_compliance_violation(param_name(param), val, param)" in cpp, (
            "Violation notifier must carry attempted+param for audit detail"
        )

    def test_PAR001_param_get_lazy_zeroes_unset_compliance_params(self):
        """param_get must return 0 for compliance-protected params that
        the operator has not yet set this flight (boot-at-zero, ADR-019).
        The legacy 'return the compiled value' branch must be gone."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        assert "param_get_compliance_value" not in cpp, (
            "Legacy zero-window get-override must be removed (ADR-019)"
        )
        # Lazy-zero pattern: compliance-protected AND !user_config.contains
        pattern = (
            r'param_is_compliance_protected\(param\)\s*&&\s*'
            r'!user_config\.contains\(param\)'
        )
        assert re.search(pattern, cpp), (
            "param_get must lazy-zero compliance params not yet set "
            "in user_config (ADR-019 boot-at-zero)"
        )

    def test_PAR001_param_reset_no_longer_blocks_compliance(self):
        """Under cap-semantics (ADR-019), reset is allowed for
        compliance-protected params — clearing user_config makes the
        param read back as 0 via the lazy-zero path. The old 'reset is
        blocked' guard must be gone from param_reset_internal."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        # The legacy guard returned `false` immediately for protected
        # params before touching user_config. Make sure no such early
        # return exists in the param_reset_internal body.
        m = re.search(
            r'static int param_reset_internal\([^)]*\)\s*\{(.*?)\n\}',
            cpp, re.DOTALL,
        )
        assert m, "param_reset_internal not found"
        body = m.group(1)
        assert "return false" not in body or "param_is_compliance_protected" not in body, (
            "param_reset_internal must not early-return on compliance "
            "protection under cap-semantics (ADR-019)"
        )

    def test_PAR001_param_reset_all_no_longer_skips_compliance(self):
        """Under cap-semantics, reset_all also resets compliance params
        to 0 (lazy-zero). The old `continue` skip must be gone."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        pattern = (
            r'param_reset_all_internal[^{]*\{[^}]*'
            r'param_is_compliance_protected[^}]*continue'
        )
        assert not re.search(pattern, cpp, re.DOTALL), (
            "param_reset_all_internal must not skip compliance params "
            "under cap-semantics (ADR-019)"
        )

    def test_PAR001_param_export_skips_compliance(self):
        """Operator-set values for compliance params must NEVER persist
        across reboots — autosave-skip is enforced inside
        param_export_internal so the export loop omits them (ADR-019)."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        m = re.search(
            r'static int param_export_internal\([^)]*\)\s*\{(.*?)\n\}',
            cpp, re.DOTALL,
        )
        assert m, "param_export_internal not found"
        body = m.group(1)
        assert "param_is_compliance_protected" in body and "continue" in body, (
            "param_export_internal must skip compliance-protected "
            "params so they don't persist across reboots (ADR-019)"
        )

    def test_PAR001_mavlink_handler_routes_through_cap_check(self):
        """MAVLink PARAM_SET handler must call param_set (which runs the
        cap check) and surface a cap-violation rejection as
        VALUE_OUT_OF_RANGE — not the legacy upfront READ_ONLY block."""
        cpp = _wsl_read(f"{WSL_MAVLINK}/mavlink_parameters.cpp")
        # Compliance-protected branch must use OUT_OF_RANGE under
        # cap-semantics, not READ_ONLY.
        # (READ_ONLY may still appear elsewhere in the file for
        # _HASH_CHECK or unrelated reasons; we only assert the
        # compliance-protected branch uses OUT_OF_RANGE.)
        compliance_block = re.search(
            r'param_is_compliance_protected[^}]+}',
            cpp, re.DOTALL,
        )
        assert compliance_block is not None, (
            "MAVLink handler must reference param_is_compliance_protected "
            "for the cap-violation surfacing path"
        )
        assert "MAV_PARAM_ERROR_VALUE_OUT_OF_RANGE" in compliance_block.group(0), (
            "Compliance cap-violation must surface as VALUE_OUT_OF_RANGE "
            "(ADR-019), not the legacy READ_ONLY"
        )

    def test_PAR001_compliance_check_has_bitset_cache(self):
        """compliance_check.cpp must use AtomicBitset for O(1) lookups."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        assert "AtomicBitset" in cpp

    def test_PAR001_compliance_check_has_stubs(self):
        """compliance_check.cpp must have no-op stubs when secure_boot is disabled."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        assert "CONFIG_MODULES_SECURE_BOOT" in cpp
        assert "return false" in cpp
        assert "return -1" in cpp

    def test_PAR001_compliance_check_includes_table(self):
        """compliance_check.cpp must include compliance_params.h."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        assert 'compliance_params.h' in cpp

    def test_PAR001_cmake_has_include_path(self):
        """Parameters CMakeLists.txt must add secure_boot include path."""
        cmake = _wsl_read(f"{WSL_PARAMETERS}/CMakeLists.txt")
        assert "CONFIG_MODULES_SECURE_BOOT" in cmake
        assert "secure_boot" in cmake


class TestPAR001_PreArmGate:
    """PAR001 cap-semantics adds a pre-arm gate (ADR-019): arming is
    blocked until every compliance-protected parameter has been set
    above 0. The check lives in the Commander HealthAndArmingChecks
    framework alongside firmwareIntegrityCheck."""

    def test_PAR001_pre_arm_check_files_exist(self):
        """complianceParamCheck.{cpp,hpp} must exist."""
        assert _wsl_exists(f"{WSL_COMMANDER_CHECKS}/complianceParamCheck.cpp")
        assert _wsl_exists(f"{WSL_COMMANDER_CHECKS}/complianceParamCheck.hpp")

    def test_PAR001_pre_arm_check_in_cmake(self):
        """complianceParamCheck.cpp must be in the HealthAndArmingChecks CMakeLists."""
        cmake = _wsl_read(
            f"{WSL_PX4_SRC}/modules/commander/HealthAndArmingChecks/CMakeLists.txt"
        )
        assert "complianceParamCheck.cpp" in cmake

    def test_PAR001_pre_arm_check_registered(self):
        """ComplianceParamCheck must be registered in HealthAndArmingChecks.hpp."""
        hpp = _wsl_read(
            f"{WSL_PX4_SRC}/modules/commander/HealthAndArmingChecks/"
            "HealthAndArmingChecks.hpp"
        )
        assert '#include "checks/complianceParamCheck.hpp"' in hpp
        assert "ComplianceParamCheck _compliance_param_checks" in hpp
        assert "&_compliance_param_checks" in hpp

    def test_PAR001_pre_arm_check_uses_first_unset_helper(self):
        """The pre-arm check must drive its decision off
        param_compliance_first_unset() — not its own table walk —
        so the source of truth stays in compliance_check.cpp."""
        cpp = _wsl_read(f"{WSL_COMMANDER_CHECKS}/complianceParamCheck.cpp")
        assert "param_compliance_first_unset" in cpp

    def test_PAR001_pre_arm_check_publishes_audit_event(self):
        """When pre-arm fails, the check must publish a security audit
        event (LOG001) on transition into the BLOCKED state — once,
        not on every commander tick."""
        cpp = _wsl_read(f"{WSL_COMMANDER_CHECKS}/complianceParamCheck.cpp")
        assert "security_audit_event" in cpp
        assert "EVENT_ARMING_BLOCKED" in cpp

    def test_PAR001_pre_arm_check_includes_param_name_in_message(self):
        """The mavlink_log message must identify which compliance
        parameter is unset so the operator knows what to fix."""
        cpp = _wsl_read(f"{WSL_COMMANDER_CHECKS}/complianceParamCheck.cpp")
        assert "first_unset" in cpp
        assert "mavlink_log_critical" in cpp


class TestPAR001_ViolationDetailFormat:
    """ADR-019: the violation callback carries an
    `attempted=X ceiling=Y` detail string into the audit log so the
    operator can see (post-flight) what value was attempted and what
    the registered ceiling was."""

    def test_PAR001_callback_signature_carries_details(self):
        """compliance_violation_cb_t must take (name, details) — the
        legacy single-arg signature is gone."""
        header = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.h")
        # The typedef line must include both params.
        m = re.search(
            r'typedef\s+void\s*\(\*compliance_violation_cb_t\)\(([^)]*)\)',
            header,
        )
        assert m, "compliance_violation_cb_t typedef not found"
        params = m.group(1)
        assert "param_name" in params and "details" in params, (
            f"Callback must take (name, details); got: {params}"
        )

    def test_PAR001_violation_notifier_formats_attempted_and_ceiling(self):
        """compliance_check.cpp must format kind-aware detail strings.
        For CAPPED rejections the label is 'ceiling'; for LOCKED it is
        'registered' (ADR-020). Both strings live as label values; the
        runtime format embeds them as 'ceiling=' or 'registered='."""
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        assert "attempted=" in cpp, "Violation detail must include 'attempted=' (ADR-019)"
        assert "\"ceiling\"" in cpp, "Violation detail must include 'ceiling' label (ADR-019)"
        assert "\"registered\"" in cpp, "Violation detail must include 'registered' label (ADR-020)"
        assert "(LOCKED)" in cpp, "LOCKED-kind detail string must include '(LOCKED)' marker (ADR-020)"

    def test_PAR001_guard_writes_details_to_audit_event(self):
        """ComplianceParamGuard.cpp must write the violated parameter into
        the security_audit_event_s::detail field so the blocked change
        reaches audit_log.bin. (The persisted detail is the parameter NAME
        only — it always fits the 32-byte field; the attempted/limit values
        are shown on the live console, not saved.)"""
        cpp = _wsl_read(f"{WSL_SECURE_BOOT}/ComplianceParamGuard.cpp")
        # Callback signature wired through:
        assert "onViolation(const char *param_name, const char *details)" in cpp
        # The parameter name is written into evt.detail:
        assert "evt.detail" in cpp and "param_name" in cpp


# -- ADR-020 -- CAPPED/LOCKED kind split --

CANONICAL_KINDS = {
    "GF_MAX_VER_DIST": "CAPPED",
    "GF_MAX_HOR_DIST": "CAPPED",
    "MPC_XY_VEL_MAX":  "CAPPED",
    "SYS_AUTOSTART":   "LOCKED",
    "CA_AIRFRAME":     "LOCKED",
    "MAV_SIGN_CFG":    "LOCKED",
}


def _parse_table_kinds(content):
    """name -> CAPPED|LOCKED extracted from compliance_params.cpp."""
    cleaned = _strip_comments(content)
    out = {}
    pattern = r'\{\"(\w+)\",[^}]*COMPLIANCE_TYPE_\w+,\s*COMPLIANCE_KIND_(\w+),'
    for name, kind in re.findall(pattern, cleaned, re.DOTALL):
        out[name] = kind
    return out


class TestPAR001_KindFieldStructural:
    """compliance_params.h declares the kind enum; .cpp tags every row."""

    def test_PAR001_kind_enum_declared(self):
        h = _read_header()
        assert "compliance_kind_t" in h
        assert "COMPLIANCE_KIND_CAPPED" in h
        assert "COMPLIANCE_KIND_LOCKED" in h

    def test_PAR001_def_struct_has_kind_field(self):
        h = _read_header()
        m = re.search(r'typedef\s+struct\s*\{(.*?)\}\s*compliance_param_def_t', h, re.DOTALL)
        assert m, "compliance_param_def_t struct not found"
        body = m.group(1)
        assert "compliance_kind_t" in body and "kind" in body

    def test_PAR001_every_row_has_kind_tag(self):
        kinds = _parse_table_kinds(_read_table_source())
        for name in CANONICAL_KINDS:
            assert name in kinds, f"{name} row missing kind tag"
            assert kinds[name] in {"CAPPED", "LOCKED"}


class TestPAR001_CanonicalSixClassification:
    """Each of the canonical 6 has the kind ADR-020 specifies."""

    def test_PAR001_canonical_six_classification(self):
        kinds = _parse_table_kinds(_read_table_source())
        mismatches = []
        for name, expected in CANONICAL_KINDS.items():
            got = kinds.get(name)
            if got != expected:
                mismatches.append(f"{name}: expected {expected}, got {got}")
        assert not mismatches, "Kind classification wrong: " + "; ".join(mismatches)


class TestPAR001_LockedSemantics:
    """LOCKED rows behave as ADR-020 prescribes (source-level checks)."""

    def test_PAR001_within_cap_rejects_locked_mismatch_via_memcmp(self):
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        m = re.search(r'if\s*\(def->kind\s*==\s*COMPLIANCE_KIND_LOCKED\)\s*\{(.*?)\}\s*\n', cpp, re.DOTALL)
        assert m, "LOCKED branch in param_check_within_cap not found (ADR-020)"
        body = m.group(1)
        assert "memcmp" in body, "LOCKED match check must use memcmp (-Wfloat-equal)"

    def test_PAR001_first_unset_skips_locked(self):
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        m = re.search(r'const char \*param_compliance_first_unset\(void\)\s*\{(.*?)\n\}', cpp, re.DOTALL)
        assert m, "param_compliance_first_unset definition not found"
        body = m.group(1)
        assert "COMPLIANCE_KIND_LOCKED" in body and "continue" in body

    def test_PAR001_param_is_compliance_locked_exposed(self):
        h = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.h")
        assert "param_is_compliance_locked" in h

    def test_PAR001_lazy_zero_returns_registered_for_locked(self):
        cpp = _wsl_read(f"{WSL_PARAMETERS}/parameters.cpp")
        m = re.search(r'if\s*\(param_is_compliance_protected\(param\)\s*&&\s*!user_config\.contains\(param\)\)\s*\{(.*?)\}\s*\n\s*auto retrieve_value', cpp, re.DOTALL)
        assert m, "lazy-zero block in param_get not found"
        body = m.group(1)
        assert "param_is_compliance_locked" in body
        assert "param_get_compliance_ceiling" in body

    def test_PAR001_locked_seed_function_not_needed(self):
        h = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.h")
        cpp = _wsl_read(f"{WSL_PARAMETERS}/compliance_check.cpp")
        assert "param_seed_locked_at_boot" not in h, "ADR-020 uses lazy-zero, not boot-seed"
        assert "param_seed_locked_at_boot" not in cpp

