"""
tests/compliance/test_H14H15_fixture_helpers.py

Unit tests for the HARDWARE_ACCEPTANCE H14/H15 fixture helpers:
  - tools/make_hash_mismatch_manifest.py   (H14 — POST reason=4/5)
  - tools/make_wrong_boardid_manifest.py   (H15 — UPD001 board_id reason=4)

These helpers produce manifests that are VALIDLY SIGNED but carry one wrong
field, so on-device the CRC (reason=2) and signature (reason=3) checks pass
and the failure lands on the field under test. The properties verified here
are exactly the bench's load-bearing assumptions:

  POST002/POST003 (H14): a wrong code_hash / data_hash must still verify under
    the manufacturer key (else POST stops at reason=3 and the hash-compute
    path is never exercised), and the *other* hash must be untouched (else
    reason=5 collapses to reason=4).
  UPD001 (H15): a wrong board_id must still verify under the manufacturer key,
    and must differ from the device board_id (else it would PASS, not reject).

A test keypair stands in for the (gitignored) manufacturer key, so these run
in CI without any private key present.
"""

import binascii
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.provisioning.export_manifest import (
    decode_binary_manifest,
    export_binary_manifest,
    verify_binary_manifest,
)
from tools.pki.keygen import generate_keypair
from tools.make_hash_mismatch_manifest import make_hash_mismatch_manifest
from tools.make_wrong_boardid_manifest import (
    make_wrong_boardid_manifest,
    DEVICE_BOARD_ID,
    DEFAULT_WRONG_BOARD_ID,
)


# ---------------------------------------------------------------------------
# Fixtures — a throwaway "manufacturer" keypair and a real, valid manifest
# whose board_id matches the device (so board_id mutation is meaningful).
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair(tmp_path):
    private_pem, public_pem = generate_keypair()
    priv = tmp_path / "private.pem"
    pub = tmp_path / "public.pem"
    priv.write_bytes(private_pem)
    pub.write_bytes(public_pem)
    return {"private": priv, "public": pub}


@pytest.fixture
def valid_manifest(keypair):
    """A 373-byte manifest validly signed by the test keypair, board_id=1063."""
    bundle = {
        "manifest": {
            "firmware_version": "1.14.0-h14h15-test",
            "board_id": DEVICE_BOARD_ID,
            "code_checksum": "11" * 32,
            "data_checksum": "22" * 32,
            "generated_at": "2026-05-30T00:00:00+00:00",
        }
    }
    return export_binary_manifest(bundle, private_key_path=keypair["private"])


def _fields(binary):
    return decode_binary_manifest(binary)["manifest"]


# ---------------------------------------------------------------------------
# H14 — make_hash_mismatch_manifest (POST002 code / POST003 data)
# ---------------------------------------------------------------------------

def test_POST002_code_hash_fixture_validly_signed_but_code_wrong(valid_manifest, keypair):
    real = _fields(valid_manifest)
    out = make_hash_mismatch_manifest(
        valid_manifest, "code",
        private_key_path=keypair["private"], public_key_path=keypair["public"])

    # Still validly signed -> POST reaches the hash check, not reason=3.
    assert verify_binary_manifest(out, keypair["public"])
    m = _fields(out)
    # Only code_hash changed -> POST reason=4.
    assert m["code_checksum"] != real["code_checksum"]
    assert m["data_checksum"] == real["data_checksum"]
    assert m["board_id"] == real["board_id"]


def test_POST003_data_hash_fixture_keeps_code_correct(valid_manifest, keypair):
    real = _fields(valid_manifest)
    out = make_hash_mismatch_manifest(
        valid_manifest, "data",
        private_key_path=keypair["private"], public_key_path=keypair["public"])

    assert verify_binary_manifest(out, keypair["public"])
    m = _fields(out)
    # code_hash MUST be untouched so reason=5 does not collapse to reason=4.
    assert m["code_checksum"] == real["code_checksum"]
    assert m["data_checksum"] != real["data_checksum"]


def test_POST002_rejects_unverifiable_input(valid_manifest, keypair):
    # Mutating a manifest that doesn't verify under our key is refused — the
    # operator must point the tool at the real provisioned manifest.
    other_priv, _ = generate_keypair()
    other_path = keypair["private"].parent / "other.pem"
    other_path.write_bytes(other_priv)
    foreign = export_binary_manifest(
        {"manifest": {"firmware_version": "x", "board_id": 1063,
                      "code_checksum": "11" * 32, "data_checksum": "22" * 32,
                      "generated_at": "2026-05-30T00:00:00+00:00"}},
        private_key_path=other_path)
    with pytest.raises(ValueError, match="does not verify"):
        make_hash_mismatch_manifest(
            foreign, "code",
            private_key_path=keypair["private"], public_key_path=keypair["public"])


def test_POST002_rejects_bad_mutate_arg(valid_manifest, keypair):
    with pytest.raises(ValueError, match="mutate must be"):
        make_hash_mismatch_manifest(
            valid_manifest, "boardid",
            private_key_path=keypair["private"], public_key_path=keypair["public"])


def test_POST002_wrong_hash_differs_from_live_flash(valid_manifest, keypair):
    # The first byte is flipped, guaranteeing the wrong hash can never
    # accidentally match the running flash (no false-pass on the bench).
    real = _fields(valid_manifest)
    out = _fields(make_hash_mismatch_manifest(
        valid_manifest, "code",
        private_key_path=keypair["private"], public_key_path=keypair["public"]))
    real_b = binascii.unhexlify(real["code_checksum"])
    out_b = binascii.unhexlify(out["code_checksum"])
    assert out_b[0] == real_b[0] ^ 0xFF
    assert out_b[1:] == real_b[1:]


# ---------------------------------------------------------------------------
# H15 — make_wrong_boardid_manifest (UPD001 board_id reason=4)
# ---------------------------------------------------------------------------

def test_UPD001_board_id_fixture_validly_signed_but_id_wrong(valid_manifest, keypair):
    real = _fields(valid_manifest)
    out = make_wrong_boardid_manifest(
        valid_manifest, DEFAULT_WRONG_BOARD_ID,
        private_key_path=keypair["private"], public_key_path=keypair["public"])

    assert verify_binary_manifest(out, keypair["public"])
    m = _fields(out)
    assert m["board_id"] == DEFAULT_WRONG_BOARD_ID
    assert m["board_id"] != DEVICE_BOARD_ID
    # Hashes untouched -> only the board_id gate fails (reason=4), not 2/3/5.
    assert m["code_checksum"] == real["code_checksum"]
    assert m["data_checksum"] == real["data_checksum"]


def test_UPD001_board_id_refuses_device_id(valid_manifest, keypair):
    # Refuse a board_id equal to the device's — that fixture would PASS.
    with pytest.raises(ValueError, match="equals the device board_id"):
        make_wrong_boardid_manifest(
            valid_manifest, DEVICE_BOARD_ID,
            private_key_path=keypair["private"], public_key_path=keypair["public"])


def test_UPD001_board_id_refuses_non_uint16(valid_manifest, keypair):
    with pytest.raises(ValueError, match="uint16"):
        make_wrong_boardid_manifest(
            valid_manifest, 70000,
            private_key_path=keypair["private"], public_key_path=keypair["public"])


def test_UPD001_board_id_custom_value(valid_manifest, keypair):
    out = make_wrong_boardid_manifest(
        valid_manifest, 9999,
        private_key_path=keypair["private"], public_key_path=keypair["public"])
    assert _fields(out)["board_id"] == 9999
    assert verify_binary_manifest(out, keypair["public"])


# ---------------------------------------------------------------------------
# decode_binary_manifest round-trip (shared backbone of both helpers)
# ---------------------------------------------------------------------------

def test_decode_binary_manifest_round_trips_fields(valid_manifest):
    m = _fields(valid_manifest)
    assert m["board_id"] == DEVICE_BOARD_ID
    assert m["code_checksum"] == "11" * 32
    assert m["data_checksum"] == "22" * 32
    assert m["firmware_version"] == "1.14.0-h14h15-test"


def test_decode_binary_manifest_rejects_bad_size():
    with pytest.raises(ValueError, match="must be 373 bytes"):
        decode_binary_manifest(b"\x00" * 100)


def test_decode_binary_manifest_rejects_bad_magic(valid_manifest):
    corrupt = b"BADMAGIC" + valid_manifest[8:]
    with pytest.raises(ValueError, match="bad magic"):
        decode_binary_manifest(corrupt)
