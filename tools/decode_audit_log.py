"""
tools/decode_audit_log.py

Human-readable decoder for a drone audit log (audit_log.bin).

There are two questions you can ask about an audit log:
  * "Is it authentic?"  -> tools/verify_audit_log.py (whole-file signature)
  * "What does it SAY?" -> this tool.

This renders every 316-byte binary entry as a plain-English line that an
operator or a DGCA auditor can read without knowing our requirement codes:
the Date + time is shown in IST (with UTC alongside), every event is described
in ordinary language, and each one is mapped to the security requirement it
provides evidence for.

Decoding needs no key material -- it is all local parsing plus the per-entry
CRC32 integrity check. Pass --key <manufacturer_private.pem> to ALSO run the
whole-file signature check (the same check verify_audit_log.py does) in one go.
The `cryptography` package is only imported when --key is supplied, so an
operator can read a log on a machine without it installed.

Usage:
    py tools/decode_audit_log.py Docs/audit_log.bin
    py tools/decode_audit_log.py Docs/audit_log.bin --key pki/manufacturer/private/manufacturer_private.pem

Exit code 0 if every entry is structurally valid (magic + CRC); 1 otherwise.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Binary layout - mirrors firmware/secure_boot/security_audit_entry.h ────────

AUDIT_ENTRY_MAGIC = 0x4C4F4701          # "LOG\x01" little-endian
AUDIT_DETAIL_LEN  = 32
AUDIT_ENTRY_SIZE  = 316

# magic(I) format_ver(B) event_type(B) event_result(B) detail_code(B)
# sequence_num(I) timestamp_us(Q) detail(32s) signature(256s) sig_len(H)
# reserved(2s) crc32(I)
ENTRY_STRUCT_FORMAT = "<IBBBBI Q 32s 256s H 2s I"
assert struct.calcsize(ENTRY_STRUCT_FORMAT) == AUDIT_ENTRY_SIZE

# ── Time handling ─────────────────────────────────────────────────────────────

# India Standard Time is a fixed UTC+05:30 offset (no daylight saving).
IST = timezone(timedelta(hours=5, minutes=30), name="IST")

# timestamp_us is "microseconds since the Unix epoch" once the flight
# controller's wall clock has been set (from GPS lock or a GCS time sync).
# Before that, format_ver 1 firmware wrote boot-relative microseconds and
# format_ver 2 firmware writes whatever the unsynced RTC reads (near 0). Any
# value that lands before 2020 cannot be a real flight date, so we treat it as
# "clock not synced" and show it as uptime instead of a bogus 1970 date.
_EPOCH_2020_US = 1_577_836_800 * 1_000_000  # 2020-01-01T00:00:00Z


def render_timestamp(timestamp_us: int) -> str:
    """Render a timestamp_us field as 'DD Mon YYYY, HH:MM:SS AM/PM IST (HH:MM:SS UTC)'.

    Falls back to an uptime string when the value predates 2020, which means
    the flight controller's wall clock was not synced when the entry was
    written (common in SITL before a GCS time sync, or on hardware pre-GPS-lock).
    """
    if timestamp_us >= _EPOCH_2020_US:
        dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=timestamp_us)
        dt_ist = dt_utc.astimezone(IST)
        # %I is zero-padded 12-hour; lstrip the leading zero for readability.
        ist_str = dt_ist.strftime("%d %b %Y, %I:%M:%S %p IST")
        return f"{ist_str} ({dt_utc.strftime('%H:%M:%S')} UTC)"

    seconds = timestamp_us / 1_000_000
    return f"uptime +{seconds:.3f}s (wall clock not synced)"


# ── Event vocabulary - mirrors msg/SecurityAuditEvent.msg ─────────────────────

EVENT_POST_RESULT         = 1
EVENT_UPDATE_ATTEMPT      = 2
EVENT_ARMING_BLOCKED      = 3
EVENT_PARAM_CHANGE        = 4
EVENT_UPDATE_APPLIED      = 5
EVENT_UPDATE_APPLY_FAILED = 6

RESULT_SUCCESS = 0
RESULT_FAILURE = 1

# Short human name + which DGCA Level-1 requirement the event provides
# evidence for. Kept here (not in the firmware) so auditors can read it.
EVENT_INFO = {
    EVENT_POST_RESULT:    ("Pre-operational self-test (POST)", "POST001/POST002/POST003"),
    EVENT_UPDATE_ATTEMPT: ("Firmware update",           "UPD001"),
    EVENT_ARMING_BLOCKED: ("Arming blocked",            "POST001 (arming gate)"),
    EVENT_PARAM_CHANGE:   ("Flight-parameter change",   "PAR001 / Gazette 7.1(c)"),
    EVENT_UPDATE_APPLIED:      ("Firmware update installed", "UPD001 / ADR-023"),
    EVENT_UPDATE_APPLY_FAILED: ("Firmware update refused on boot", "UPD001 / ADR-023"),
}

# detail_code on a POST_RESULT carries FirmwareIntegrityStatus.failure_reason.
POST_REASON = {
    0: "no fault",
    1: "no firmware manifest was found",
    2: "the firmware manifest is corrupt (CRC check failed)",
    3: "the firmware is not signed by the manufacturer (signature invalid)",
    4: "the firmware code has changed since it was signed (code hash mismatch)",
    5: "the certified flight parameters have changed (parameter hash mismatch)",
    6: "this firmware was built for a different board (board ID mismatch)",
}

# detail_code on an UPDATE_APPLY_FAILED carries the reject reason the
# first-boot promotion refused for — the firmware_update_authorization
# REASON_* codes, worded for the promotion context.
PROMOTE_FAIL_REASON = {
    1: "no update manifest accompanied the staged image",
    2: "the update manifest is corrupt (CRC check failed)",
    3: "the update manifest is not signed by the manufacturer",
    4: "the update was built for a different board",
    5: "the staged update image is missing or unreadable",
    6: "the firmware now running does not match the update manifest "
       "(the bootloader refused or did not complete the install)",
    7: "the staged update image is not signed by the manufacturer",
    8: "the update is OLDER than the firmware already installed (rollback refused)",
}


def _clean_detail(detail_bytes: bytes) -> str:
    """Decode the 32-byte detail field up to its first NUL into a printable str."""
    raw = detail_bytes.split(b"\x00", 1)[0]
    return raw.decode("ascii", errors="replace")


def describe_event(event_type: int, event_result: int, detail_code: int,
                   detail: str) -> str:
    """Return one plain-English sentence describing what happened.

    `detail` is the already-decoded detail string from the entry.
    """
    if event_type == EVENT_POST_RESULT:
        if event_result == RESULT_SUCCESS:
            return "Pre-operational self-test passed - firmware verified, arming allowed."
        reason = POST_REASON.get(detail_code, f"unknown reason code {detail_code}")
        return f"Pre-operational self-test FAILED - {reason}; arming is blocked."

    if event_type == EVENT_UPDATE_ATTEMPT:
        if event_result == RESULT_SUCCESS:
            return "Firmware update accepted - manufacturer signature verified."
        return ("Firmware update REJECTED - it is not a valid "
                "manufacturer-signed update.")

    if event_type == EVENT_PARAM_CHANGE:
        if event_result == RESULT_SUCCESS:
            # Emitted when a signed firmware update changes the certified
            # flight parameters (data_hash changed). detail == "FW update changed flight params".
            return ("Certified flight parameters were changed by a signed "
                    "firmware update.")
        # A rejected runtime write. detail is the parameter NAME only, e.g.
        # "GF_MAX_VER_DIST" -- the attempted/limit values are shown on the live
        # console, not persisted (see ComplianceParamGuard::onViolation).
        if detail:
            return f"Attempted to change {detail} - rejected (protected flight parameter)."
        return "A protected flight-parameter change was rejected."

    if event_type == EVENT_ARMING_BLOCKED:
        return "Arming was blocked by a security check."

    if event_type == EVENT_UPDATE_APPLIED:
        # detail == "PROMOTED <version>" written by the first-boot promotion.
        version = detail[len("PROMOTED "):] if detail.startswith("PROMOTED ") else ""
        if version:
            return (f"Firmware update {version} was installed and verified - "
                    "the new firmware is now the certified configuration.")
        return ("A firmware update was installed and verified - the new "
                "firmware is now the certified configuration.")

    if event_type == EVENT_UPDATE_APPLY_FAILED:
        reason = PROMOTE_FAIL_REASON.get(detail_code,
                                         f"unknown reason code {detail_code}")
        return (f"A staged firmware update was REFUSED on boot - {reason}; "
                "the update was quarantined and the previous certified "
                "configuration is kept.")

    return f"Unknown event (type={event_type}, result={event_result})."


# ── Parsing ───────────────────────────────────────────────────────────────────

@dataclass
class DecodedEntry:
    index: int
    magic_ok: bool
    crc_ok: bool
    format_ver: int = 0
    event_type: int = 0
    event_result: int = 0
    detail_code: int = 0
    sequence_num: int = 0
    timestamp_us: int = 0
    detail: str = ""
    requirement: str = ""
    headline: str = ""

    def render(self) -> str:
        """Multi-line, indented human-readable block for this entry."""
        if not self.magic_ok:
            return (f"#{self.index}  *** UNRECOGNISED ENTRY *** "
                    f"(bad magic - file may be truncated or not an audit log)")

        crc_note = "CRC OK" if self.crc_ok else "*** CRC BAD - entry tampered or corrupt ***"
        ver_note = "" if self.format_ver in (1, 2) else f"  [unexpected format_ver={self.format_ver}]"
        lines = [
            f"#{self.sequence_num}  {render_timestamp(self.timestamp_us)}",
            f"      {self.headline}   [{self.requirement}]",
        ]
        if self.detail:
            lines.append(f"      detail: \"{self.detail}\"")
        lines.append(f"      {crc_note}{ver_note}")
        return "\n".join(lines)


@dataclass
class DecodeResult:
    entries: list = field(default_factory=list)
    trailing_bytes: int = 0

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def magic_bad(self) -> int:
        return sum(1 for e in self.entries if not e.magic_ok)

    @property
    def crc_bad(self) -> int:
        return sum(1 for e in self.entries if e.magic_ok and not e.crc_ok)

    @property
    def all_valid(self) -> bool:
        return self.magic_bad == 0 and self.crc_bad == 0 and self.trailing_bytes == 0

    def coverage(self) -> dict:
        """Map event_type -> count, for the requirement-coverage summary."""
        counts: dict = {}
        for e in self.entries:
            if e.magic_ok:
                counts[e.event_type] = counts.get(e.event_type, 0) + 1
        return counts


def decode_bytes(data: bytes) -> DecodeResult:
    """Parse a whole audit_log.bin image into a DecodeResult."""
    result = DecodeResult()
    n_entries = len(data) // AUDIT_ENTRY_SIZE
    result.trailing_bytes = len(data) - n_entries * AUDIT_ENTRY_SIZE

    for i in range(n_entries):
        chunk = data[i * AUDIT_ENTRY_SIZE:(i + 1) * AUDIT_ENTRY_SIZE]
        (magic, format_ver, event_type, event_result, detail_code,
         sequence_num, timestamp_us, detail_raw, _signature, _sig_len,
         _reserved, stored_crc) = struct.unpack(ENTRY_STRUCT_FORMAT, chunk)

        magic_ok = (magic == AUDIT_ENTRY_MAGIC)
        computed_crc = zlib.crc32(chunk[:AUDIT_ENTRY_SIZE - 4]) & 0xFFFFFFFF
        crc_ok = (stored_crc == computed_crc)

        detail = _clean_detail(detail_raw)
        _name, requirement = EVENT_INFO.get(event_type, ("Unknown event", "-"))
        headline = describe_event(event_type, event_result, detail_code, detail)

        result.entries.append(DecodedEntry(
            index=i, magic_ok=magic_ok, crc_ok=crc_ok, format_ver=format_ver,
            event_type=event_type, event_result=event_result,
            detail_code=detail_code, sequence_num=sequence_num,
            timestamp_us=timestamp_us, detail=detail,
            requirement=requirement, headline=headline,
        ))

    return result


# ── Coverage / summary rendering ──────────────────────────────────────────────

# Requirement lines shown in the footer, in audit-narrative order.
_COVERAGE_ROWS = [
    (EVENT_POST_RESULT,    "POST001/002/003  pre-operational self-test on every boot"),
    (EVENT_UPDATE_ATTEMPT, "UPD001           only manufacturer-signed updates accepted"),
    (EVENT_UPDATE_APPLIED, "UPD001/ADR-023   verified updates promoted on first boot"),
    (EVENT_UPDATE_APPLY_FAILED,
                           "UPD001/ADR-023   unverified staged updates quarantined"),
    (EVENT_PARAM_CHANGE,   "PAR001 / 7.1(c)  certified flight parameters protected"),
    (EVENT_ARMING_BLOCKED, "POST001 gate     arming blocked on integrity failure"),
]


def render_summary(result: DecodeResult) -> str:
    counts = result.coverage()
    lines = ["", "Requirement coverage in this log:"]
    for event_type, label in _COVERAGE_ROWS:
        n = counts.get(event_type, 0)
        mark = f"{n} event(s)" if n else "no events recorded"
        lines.append(f"  {label}  ->  {mark}")
    lines.append("  LOG001           this log is itself the signed audit record "
                 "(verify with verify_audit_log.py)")

    lines.append("")
    lines.append(f"Entries: {result.total}   "
                 f"CRC failures: {result.crc_bad}   "
                 f"unrecognised: {result.magic_bad}")
    if result.trailing_bytes:
        lines.append(f"WARNING: {result.trailing_bytes} trailing byte(s) - "
                     f"file size is not a whole number of {AUDIT_ENTRY_SIZE}-byte entries.")
    lines.append("Status: " + ("OK - every entry parsed and passed CRC."
                               if result.all_valid else
                               "PROBLEM - see CRC/unrecognised counts above."))
    return "\n".join(lines)


# ── Optional whole-file signature check (mirrors verify_audit_log.py) ──────────

def verify_signature(log_path: Path, sig_path: Path, key_path: Path) -> bool:
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    sig_data = sig_path.read_bytes()
    if len(sig_data) != 256:
        print(f"  signature: FAIL - {len(sig_data)} bytes, expected 256 (RSA-2048)")
        return False

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    expected = hashlib.sha256(log_path.read_bytes()).digest()
    try:
        decrypted = private_key.decrypt(sig_data, padding.PKCS1v15())
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator verbatim
        print(f"  signature: FAIL - could not decrypt .sig ({exc})")
        return False

    if decrypted == expected:
        print("  signature: PASS - log is authentic and untampered.")
        return True
    print("  signature: FAIL - decrypted hash does not match SHA-256(log).")
    return False


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a drone audit_log.bin in plain English (IST + UTC).")
    parser.add_argument("log", type=Path, help="Path to audit_log.bin")
    parser.add_argument("--key", type=Path, default=None,
                        help="Manufacturer RSA-2048 private key (PEM) - also "
                             "runs the whole-file signature check")
    parser.add_argument("--sig", type=Path, default=None,
                        help="Path to audit_log.sig (defaults to <log>.sig "
                             "or audit_log.sig beside the log)")
    args = parser.parse_args(argv)

    if not args.log.is_file():
        print(f"ERROR: {args.log} not found", file=sys.stderr)
        return 2

    result = decode_bytes(args.log.read_bytes())

    print(f"Audit log: {args.log}  ({result.total} entries)")
    print("=" * 72)
    for entry in result.entries:
        print(entry.render())
        print("-" * 72)
    print(render_summary(result))

    if args.key:
        sig_path = args.sig or args.log.with_suffix(".sig")
        if not sig_path.is_file():
            sig_path = args.log.parent / "audit_log.sig"
        print("")
        if not sig_path.is_file():
            print(f"  signature: SKIPPED - no .sig found (looked for {sig_path})")
        else:
            verify_signature(args.log, sig_path, args.key)

    return 0 if result.all_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
