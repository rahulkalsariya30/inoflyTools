"""
tests/compliance/test_LOG001_decode_audit_log.py

Compliance tests for the human-readable audit-log decoder (tools/decode_audit_log.py).

Requirement: LOG001 — the signed audit log must be reviewable. An operator or
DGCA auditor has to be able to read what each event means, when it happened
(Date + IST/UTC time), and which requirement it provides evidence for —
without knowing our internal requirement codes.

These tests pin:
  - plain-English rendering for every event type (no raw "PAR001"-style codes)
  - IST + UTC timestamp conversion, and the "clock not synced" fallback
  - per-entry CRC tamper detection surfaced in the output
  - requirement-coverage summary
"""

import struct
import zlib
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.decode_audit_log import (  # noqa: E402
    AUDIT_ENTRY_MAGIC,
    AUDIT_ENTRY_SIZE,
    EVENT_POST_RESULT,
    EVENT_UPDATE_ATTEMPT,
    EVENT_PARAM_CHANGE,
    EVENT_UPDATE_APPLIED,
    EVENT_UPDATE_APPLY_FAILED,
    RESULT_SUCCESS,
    RESULT_FAILURE,
    decode_bytes,
    render_timestamp,
    render_summary,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_entry(*, format_ver=2, event_type=EVENT_POST_RESULT,
                 event_result=RESULT_SUCCESS, detail_code=0, sequence_num=0,
                 timestamp_us=1_000_000, detail=b"POST", good_crc=True):
    """Build one 316-byte audit entry (per-file mode: signature zeroed)."""
    detail_padded = detail.ljust(32, b"\x00")[:32]
    body = struct.pack(
        "<IBBBBI Q 32s",
        AUDIT_ENTRY_MAGIC, format_ver, event_type, event_result,
        detail_code, sequence_num, timestamp_us, detail_padded,
    )
    body += b"\x00" * 256          # signature
    body += struct.pack("<H 2s", 0, b"\x00\x00")  # sig_len + reserved
    assert len(body) == AUDIT_ENTRY_SIZE - 4
    crc = zlib.crc32(body) & 0xFFFFFFFF
    if not good_crc:
        crc ^= 0xFFFFFFFF          # deliberately wrong CRC
    return body + struct.pack("<I", crc)


# A known instant: 2026-05-17 08:44:05 UTC == 2026-05-17 14:14:05 IST.
_KNOWN_UTC_US = 1_779_007_445_000_000


# ── Timestamp rendering ───────────────────────────────────────────────────────

class TestDecodeTimestamp:
    def test_LOG001_decode_ist_and_utc(self):
        out = render_timestamp(_KNOWN_UTC_US)
        assert "17 May 2026" in out
        assert "02:14:05 PM IST" in out
        assert "08:44:05" in out and "UTC" in out

    def test_LOG001_decode_unsynced_clock_fallback(self):
        # A boot-relative value (a few seconds) cannot be a real date.
        out = render_timestamp(3_500_000)
        assert "not synced" in out
        assert "+3.500s" in out

    def test_LOG001_decode_ist_is_530_ahead_of_utc(self):
        # Midnight UTC -> 05:30 IST same day.
        midnight_utc_us = 1_779_926_400 * 1_000_000  # 2026-05-28 00:00:00 UTC
        out = render_timestamp(midnight_utc_us)
        assert "05:30:00 AM IST" in out
        assert "00:00:00" in out


# ── Plain-English event rendering ─────────────────────────────────────────────

class TestDecodeEventLanguage:
    def test_LOG001_decode_post_pass_plain_english(self):
        res = decode_bytes(_build_entry(event_type=EVENT_POST_RESULT,
                                        event_result=RESULT_SUCCESS))
        e = res.entries[0]
        assert "self-test passed" in e.headline.lower()
        assert e.requirement.startswith("POST")
        # No internal req-code leaks into the operator-facing headline.
        assert "POST001" not in e.headline

    def test_LOG001_decode_post_fail_reason_codehash(self):
        res = decode_bytes(_build_entry(event_type=EVENT_POST_RESULT,
                                        event_result=RESULT_FAILURE,
                                        detail_code=4))
        e = res.entries[0]
        assert "FAILED" in e.headline
        assert "code hash mismatch" in e.headline
        assert "blocked" in e.headline.lower()

    def test_LOG001_decode_post_fail_reason_datahash(self):
        res = decode_bytes(_build_entry(event_type=EVENT_POST_RESULT,
                                        event_result=RESULT_FAILURE,
                                        detail_code=5))
        assert "flight parameters have changed" in res.entries[0].headline

    def test_LOG001_decode_update_rejected(self):
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_ATTEMPT,
                                        event_result=RESULT_FAILURE,
                                        detail=b"FW_UPDATE"))
        e = res.entries[0]
        assert "REJECTED" in e.headline
        assert e.requirement == "UPD001"

    def test_LOG001_decode_update_accepted(self):
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_ATTEMPT,
                                        event_result=RESULT_SUCCESS,
                                        detail=b"FW_UPDATE"))
        assert "accepted" in res.entries[0].headline.lower()

    def test_LOG001_decode_param_violation_names_the_parameter(self):
        # Firmware persists the parameter NAME only (no values) -- it always
        # fits the 32-byte field, so nothing is truncated. The decoder renders
        # it as a readable sentence using the structured PARAM_CHANGE/FAILURE.
        res = decode_bytes(_build_entry(
            event_type=EVENT_PARAM_CHANGE, event_result=RESULT_FAILURE,
            detail=b"GF_MAX_VER_DIST"))
        e = res.entries[0]
        assert "Attempted to change" in e.headline
        assert "GF_MAX_VER_DIST" in e.headline
        assert "rejected" in e.headline.lower()
        assert "PAR001" in e.requirement
        # The stored name fits with room to spare -- never truncated.
        assert e.detail == "GF_MAX_VER_DIST"

    def test_LOG001_decode_handles_overlong_detail_gracefully(self):
        """Decoder robustness: if any producer ever wrote a string longer than
        the 32-byte field, the decoder shows exactly the stored bytes (no
        crash, no invention). Firmware no longer writes over-long details."""
        long_detail = b"GF_MAX_HOR_DIST: attempted=600 ceiling=500"
        res = decode_bytes(_build_entry(event_type=EVENT_PARAM_CHANGE,
                                        event_result=RESULT_FAILURE,
                                        detail=long_detail))
        assert res.entries[0].detail == long_detail[:32].decode()

    def test_LOG001_decode_param_change_on_signed_update(self):
        res = decode_bytes(_build_entry(
            event_type=EVENT_PARAM_CHANGE, event_result=RESULT_SUCCESS,
            detail=b"FW update changed flight params"))
        assert "changed by a signed firmware update" in res.entries[0].headline

    # ── ADR-023 A-6: first-boot promotion events (5/6) ────────────────────────

    def test_LOG001_decode_update_applied_names_version(self):
        # Firmware writes detail == "PROMOTED <version>" on a successful
        # first-boot promotion; the headline surfaces the version.
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_APPLIED,
                                        event_result=RESULT_SUCCESS,
                                        detail=b"PROMOTED v1.16.0-rc1"))
        e = res.entries[0]
        assert "installed" in e.headline.lower()
        assert "v1.16.0-rc1" in e.headline
        assert "ADR-023" in e.requirement

    def test_LOG001_decode_update_apply_failed_rollback(self):
        # detail_code carries the promotion reject reason (REASON_ROLLBACK=8).
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_APPLY_FAILED,
                                        event_result=RESULT_FAILURE,
                                        detail_code=8, detail=b"FW_PROMOTE"))
        e = res.entries[0]
        assert "REFUSED" in e.headline
        assert "rollback" in e.headline.lower()
        assert "quarantined" in e.headline.lower()

    def test_LOG001_decode_update_apply_failed_flash_mismatch(self):
        # REASON_IMAGE_HASH_MISMATCH=6: running flash != staged manifest,
        # i.e. the bootloader refused or never completed the install.
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_APPLY_FAILED,
                                        event_result=RESULT_FAILURE,
                                        detail_code=6, detail=b"FW_PROMOTE"))
        e = res.entries[0]
        assert "does not match" in e.headline
        assert "bootloader" in e.headline.lower()

    def test_LOG001_decode_update_apply_failed_unknown_reason(self):
        res = decode_bytes(_build_entry(event_type=EVENT_UPDATE_APPLY_FAILED,
                                        event_result=RESULT_FAILURE,
                                        detail_code=99, detail=b"FW_PROMOTE"))
        assert "unknown reason code 99" in res.entries[0].headline


# ── CRC / integrity surfacing ─────────────────────────────────────────────────

class TestDecodeIntegrity:
    def test_LOG001_decode_good_crc_marks_ok(self):
        res = decode_bytes(_build_entry(good_crc=True))
        assert res.entries[0].crc_ok
        assert res.all_valid
        assert "CRC OK" in res.entries[0].render()

    def test_LOG001_decode_bad_crc_flagged(self):
        res = decode_bytes(_build_entry(good_crc=False))
        assert not res.entries[0].crc_ok
        assert not res.all_valid
        assert res.crc_bad == 1
        assert "CRC BAD" in res.entries[0].render()

    def test_LOG001_decode_trailing_bytes_flagged(self):
        data = _build_entry() + b"\x99" * 10
        res = decode_bytes(data)
        assert res.trailing_bytes == 10
        assert not res.all_valid

    def test_LOG001_decode_bad_magic_flagged(self):
        entry = bytearray(_build_entry())
        entry[0] ^= 0xFF  # corrupt magic
        res = decode_bytes(bytes(entry))
        assert not res.entries[0].magic_ok
        assert res.magic_bad == 1


# ── Coverage summary ──────────────────────────────────────────────────────────

class TestDecodeCoverage:
    def test_LOG001_decode_coverage_counts_each_requirement(self):
        log = (
            _build_entry(event_type=EVENT_POST_RESULT, sequence_num=0)
            + _build_entry(event_type=EVENT_POST_RESULT, sequence_num=1)
            + _build_entry(event_type=EVENT_UPDATE_ATTEMPT, sequence_num=2,
                           detail=b"FW_UPDATE")
            + _build_entry(event_type=EVENT_PARAM_CHANGE, event_result=RESULT_FAILURE,
                           sequence_num=3, detail=b"MPC_XY_VEL_MAX: attempted=30 ceiling=15")
            + _build_entry(event_type=EVENT_UPDATE_APPLIED, sequence_num=4,
                           detail=b"PROMOTED v1.16.0")
        )
        res = decode_bytes(log)
        cov = res.coverage()
        assert cov[EVENT_POST_RESULT] == 2
        assert cov[EVENT_UPDATE_ATTEMPT] == 1
        assert cov[EVENT_PARAM_CHANGE] == 1
        assert cov[EVENT_UPDATE_APPLIED] == 1

        summary = render_summary(res)
        assert "POST001/002/003" in summary
        assert "UPD001" in summary
        assert "PAR001" in summary
        assert "LOG001" in summary
        assert "ADR-023" in summary
        assert "Entries: 5" in summary

    def test_LOG001_decode_empty_log(self):
        res = decode_bytes(b"")
        assert res.total == 0
        assert res.all_valid  # nothing wrong with an empty log
