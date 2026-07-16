"""
tests/compliance/test_ADR023_sd_update.py

Compliance tests for the ADR-023 SD-staged firmware update chain (A-10).

Requirement: UPD001 apply path / ADR-023
  Three independent fail-closed gates stand between a staged UPDATE.BIN and
  running code:
    gate 1 (app)  — hash binding: staged image code/data digests must equal
                    the RSA-signed manifest's checksums before reboot-to-BL
    gate 2 (BL)   — RSA-PSS verify of the staged image BEFORE any erase
    gate 3 (BL)   — BOOT001 in-flash verify before jump

  The device implementations live in the PX4 fork (sd_update.c,
  FirmwareUpdateGatekeeper::applyUpdate). What THIS suite proves, on the host:
    - the reference TOC parse (tools/make_a10_fixtures.py) refuses every
      malformed-image class the bootloader refuses — same math, same rejects
      (bench-validated against real hardware in B9, 2026-07-09)
    - the signature gate refuses tampered / unsigned / wrong-key images while
      accepting the manufacturer-signed one (key slot PINNED, TOC bytes are
      attacker-controlled)
    - the streamed-digest offset math (device hashes 4 KB chunks, never the
      whole 1.8 MB image) is equivalent to whole-buffer hashing
    - the UPDATE.MTA sidecar is self-validating: a tampered region split that
      still satisfies every structural invariant is caught by the hash
      binding — the property ADR-023's "untrusted meta" design relies on
    - the A-8 bundler artifacts satisfy the device contract round-trip
      (image_size == signed_len + 256, code_len + data_len == signed_len)
    - the committed fixture generator produces fixtures that fail in exactly
      the intended way (a mislabeled negative fixture voids a bench run)

The synthetic images here mirror the cubeorangeplus layout (TOC at 0x2a8,
BOOT + SIG1 entries, 256-byte trailing signature) at ~4 KB scale, so the
matrix runs in CI without a 2 MB firmware fixture.
"""

import hashlib
import json
import struct
import sys
import zlib
import base64
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tools.pki.keygen import generate_keypair
from tools.checksum.checksum import generate_manifest
from tools.bundler.bundler import build_update_artifacts
from tools.make_a10_fixtures import (
    parse_staged_image,
    verify_staged_signature,
    region_digests,
    make_fixtures,
    StagedImageReject,
)
from tools.signer.toc_sign import (
    sign_image,
    verify_image,
    APP_LOAD_ADDRESS_DEFAULT,
    TOC_OFFSET_DEFAULT,
    TOC_START_MAGIC,
    TOC_END_MAGIC,
    TOC_ENTRY_SIZE,
    RSA_2048_SIG_LEN,
)

# Reuse the minimal-ELF builder from the CHK001 suite (same directory) — it
# already produces exactly what _read_elf_symbols/hash_flash_ranges consume.
from test_CHK001_checksum import _build_minimal_elf

ENTRIES_OFF = TOC_OFFSET_DEFAULT + 8

# Byte offsets of image_toc_entry_t fields within an entry (packed, 24 B).
_FIELD_OFF = {"start": 4, "end": 8, "sig_idx": 16, "sig_key": 17, "flags1": 19}


# ---------------------------------------------------------------------------
# Synthetic hardware build: signed image + matching ELF + .px4 wrapper
# ---------------------------------------------------------------------------

def build_unsigned_image(code_len: int = 0x1000, data_len: int = 0x100,
                         code_seed: int = 0x99) -> bytes:
    """
    Miniature cubeorangeplus-layout flash image:
      [0, code_len)               "code" — fake vectors, TOC at 0x2a8, filler
      [code_len, code_len+data_len)  "compliance params" data region
      [signed_len, +256)          zeroed signature placeholder
    BOOT TOC entry covers code+data (the signed range), SIG1 directly follows.
    code_seed varies the code bytes so two builds can differ (mismatch tests).
    """
    signed_len = code_len + data_len
    load = APP_LOAD_ADDRESS_DEFAULT
    b = bytearray(signed_len + RSA_2048_SIG_LEN)

    struct.pack_into("<I", b, 0, 0x20010000)  # plausible initial SP, not erased
    for i in range(4, TOC_OFFSET_DEFAULT):    # pretend vectors + bootdelay
        b[i] = (i * 7 + 0x42) & 0xFF
    struct.pack_into("<II", b, TOC_OFFSET_DEFAULT, TOC_START_MAGIC, 1)
    struct.pack_into("<4sIII4BI", b, ENTRIES_OFF,
                     b"BOOT", load, load + signed_len, 0, 1, 0, 0, 0x05, 0)
    struct.pack_into("<4sIII4BI", b, ENTRIES_OFF + TOC_ENTRY_SIZE,
                     b"SIG1", load + signed_len, load + signed_len + RSA_2048_SIG_LEN,
                     0, 0, 0, 0, 0, 0)
    struct.pack_into("<I", b, ENTRIES_OFF + 2 * TOC_ENTRY_SIZE, TOC_END_MAGIC)
    for i in range(ENTRIES_OFF + 2 * TOC_ENTRY_SIZE + 4, code_len):
        b[i] = (i * 13 + code_seed) & 0xFF
    for i in range(code_len, signed_len):     # data region, distinct pattern
        b[i] = (i * 11 + 0xA5) & 0xFF
    return bytes(b)


def wrap_px4(image: bytes, out_path: Path, board_id: int = 1063,
             version: str = "1.0.0-synth") -> Path:
    """Wrap a raw image into a .px4 the way px_mkfw does (zlib+base64)."""
    out_path.write_text(json.dumps({
        "magic": "PX4FWv1",
        "board_id": board_id,
        "version": version,
        "image_size": len(image),
        "image": base64.b64encode(zlib.compress(image, 9)).decode(),
    }))
    return out_path


def build_synthetic_setup(base_dir: Path, private_pem: bytes,
                          code_len: int = 0x1000, data_len: int = 0x100,
                          code_seed: int = 0x99, prefix: str = "synth") -> dict:
    """
    A complete synthetic "hardware build": BOOT001-signed image, the matching
    minimal ELF (segments = the image's code/data bytes, symbols = the region
    bounds), and signed/unsigned .px4 wrappers. Shared with the PKG001/PIPE
    extension tests.
    """
    unsigned = build_unsigned_image(code_len, data_len, code_seed)
    signed = sign_image(unsigned, private_pem)
    signed_len = code_len + data_len

    load = APP_LOAD_ADDRESS_DEFAULT
    elf_path = base_dir / f"{prefix}.elf"
    elf_path.write_bytes(_build_minimal_elf(
        segments=[
            (load, signed[:code_len]),
            (load + code_len, signed[code_len:signed_len]),
        ],
        symbols={
            "_stext": load,
            "_compliance_params_start": load + code_len,
            "_compliance_params_end": load + signed_len,
        },
    ))

    return {
        "code_len": code_len,
        "data_len": data_len,
        "signed_len": signed_len,
        "unsigned_image": unsigned,
        "signed_image": signed,
        "elf_path": elf_path,
        "unsigned_px4": wrap_px4(unsigned, base_dir / f"{prefix}_unsigned.px4"),
        "signed_px4": wrap_px4(signed, base_dir / f"{prefix}_signed.px4"),
    }


def mutate_toc_entry(image: bytes, entry_idx: int, field: str, value: int) -> bytes:
    """Return a copy of image with one TOC entry field overwritten."""
    out = bytearray(image)
    off = ENTRIES_OFF + entry_idx * TOC_ENTRY_SIZE + _FIELD_OFF[field]
    if field in ("start", "end"):
        struct.pack_into("<I", out, off, value)
    else:
        out[off] = value
    return bytes(out)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def manufacturer_keys(tmp_path_factory):
    priv_pem, pub_pem = generate_keypair()
    d = tmp_path_factory.mktemp("mfr_keys")
    priv, pub = d / "private.pem", d / "public.pem"
    priv.write_bytes(priv_pem)
    pub.write_bytes(pub_pem)
    return {"private_pem": priv_pem, "public_pem": pub_pem,
            "private_path": priv, "public_path": pub}


@pytest.fixture(scope="module")
def attacker_keys():
    priv_pem, pub_pem = generate_keypair()
    return {"private_pem": priv_pem, "public_pem": pub_pem}


@pytest.fixture(scope="module")
def setup(tmp_path_factory, manufacturer_keys):
    """Module-wide synthetic build — tests must NOT mutate it in place."""
    return build_synthetic_setup(
        tmp_path_factory.mktemp("synth_build"), manufacturer_keys["private_pem"]
    )


# ---------------------------------------------------------------------------
# Gate 2 layout checks — reference parse must refuse what sd_update.c refuses
# ---------------------------------------------------------------------------

class TestADR023_StagedTocParse:

    def test_ADR023_good_image_parses_with_expected_layout(self, setup):
        signed_len, image_size = parse_staged_image(setup["signed_image"])
        assert signed_len == setup["signed_len"]
        assert image_size == signed_len + RSA_2048_SIG_LEN
        assert image_size == len(setup["signed_image"])

    def test_ADR023_reject_bad_toc_magic(self, setup):
        img = bytearray(setup["signed_image"])
        img[TOC_OFFSET_DEFAULT] ^= 0xFF
        with pytest.raises(StagedImageReject, match="magic"):
            parse_staged_image(bytes(img))

    def test_ADR023_reject_erased_stack_pointer(self, setup):
        """First flash word erased (0xffffffff) means no bootable app — the
        BL refuses before doing any crypto work."""
        img = bytearray(setup["signed_image"])
        struct.pack_into("<I", img, 0, 0xFFFFFFFF)
        with pytest.raises(StagedImageReject, match="SP"):
            parse_staged_image(bytes(img))

    def test_ADR023_reject_boot_region_not_at_app_load_address(self, setup):
        img = mutate_toc_entry(setup["signed_image"], 0, "start",
                               APP_LOAD_ADDRESS_DEFAULT + 0x100)
        with pytest.raises(StagedImageReject, match="APP_LOAD"):
            parse_staged_image(img)

    def test_ADR023_reject_nonzero_signature_key_slot(self, setup):
        """The TOC is attacker-controlled bytes. If the device honored
        signature_key, a staged image could select its own trust anchor —
        the slot must be pinned to the manufacturer key (0)."""
        img = mutate_toc_entry(setup["signed_image"], 0, "sig_key", 1)
        with pytest.raises(StagedImageReject, match="manufacturer slot"):
            parse_staged_image(img)

    def test_ADR023_reject_signature_idx_out_of_range(self, setup):
        img = mutate_toc_entry(setup["signed_image"], 0, "sig_idx", 5)
        with pytest.raises(StagedImageReject, match="signature_idx"):
            parse_staged_image(img)

    def test_ADR023_reject_missing_check_signature_flag(self, setup):
        """An image whose TOC opts out of verification must not be accepted
        as 'nothing to check' — refusal is the fail-closed answer."""
        img = mutate_toc_entry(setup["signed_image"], 0, "flags1", 0)
        with pytest.raises(StagedImageReject, match="CHECK_SIGNATURE"):
            parse_staged_image(img)

    def test_ADR023_reject_sig_region_not_adjacent_to_boot(self, setup):
        img = mutate_toc_entry(
            setup["signed_image"], 1, "start",
            APP_LOAD_ADDRESS_DEFAULT + setup["signed_len"] + 4)
        with pytest.raises(StagedImageReject, match="directly follow"):
            parse_staged_image(img)

    def test_ADR023_reject_sig_region_wrong_size(self, setup):
        img = mutate_toc_entry(
            setup["signed_image"], 1, "end",
            APP_LOAD_ADDRESS_DEFAULT + setup["signed_len"] + RSA_2048_SIG_LEN + 4)
        with pytest.raises(StagedImageReject, match="256"):
            parse_staged_image(img)

    def test_ADR023_reject_truncated_file(self, setup):
        with pytest.raises(StagedImageReject, match="exceeds"):
            parse_staged_image(setup["signed_image"][:-512])

    def test_ADR023_reject_unaligned_signed_len(self, setup):
        """Flash is written word-by-word; unaligned lengths are refused.
        Shift BOOT end and the whole SIG region back 2 bytes so every other
        invariant still holds — alignment must be what trips the reject."""
        load = APP_LOAD_ADDRESS_DEFAULT
        end = load + setup["signed_len"] - 2
        img = mutate_toc_entry(setup["signed_image"], 0, "end", end)
        img = mutate_toc_entry(img, 1, "start", end)
        img = mutate_toc_entry(img, 1, "end", end + RSA_2048_SIG_LEN)
        with pytest.raises(StagedImageReject, match="word-aligned"):
            parse_staged_image(img)

    def test_ADR023_reject_toc_outside_signed_range(self, setup):
        """A signed range that ends before the TOC would mean the verified
        bytes don't cover the very metadata that located the signature."""
        load = APP_LOAD_ADDRESS_DEFAULT
        end = load + 0x200  # before the TOC END sentinel
        img = mutate_toc_entry(setup["signed_image"], 0, "end", end)
        img = mutate_toc_entry(img, 1, "start", end)
        img = mutate_toc_entry(img, 1, "end", end + RSA_2048_SIG_LEN)
        with pytest.raises(StagedImageReject, match="signed range"):
            parse_staged_image(img)

    def test_ADR023_reject_missing_end_magic(self, setup):
        img = bytearray(setup["signed_image"])
        struct.pack_into("<I", img, ENTRIES_OFF + 2 * TOC_ENTRY_SIZE, 0)
        with pytest.raises(StagedImageReject, match="END magic"):
            parse_staged_image(bytes(img))

    def test_ADR023_reject_tiny_file(self):
        with pytest.raises(StagedImageReject, match="too small"):
            parse_staged_image(b"\x00" * 64)


# ---------------------------------------------------------------------------
# Gate 2 signature checks — RSA-PSS verify-before-erase
# ---------------------------------------------------------------------------

class TestADR023_SignatureGate:

    def test_ADR023_manufacturer_signed_image_accepted(self, setup, manufacturer_keys):
        assert verify_staged_signature(
            setup["signed_image"], manufacturer_keys["public_pem"]) is True

    def test_ADR023_unsigned_placeholder_refused(self, setup, manufacturer_keys):
        """A normally-built (never-signed) image carries 256 zero bytes where
        the signature belongs — must be refused, not treated as 'no signature
        required'."""
        assert verify_staged_signature(
            setup["unsigned_image"], manufacturer_keys["public_pem"]) is False

    def test_ADR023_tampered_code_byte_refused(self, setup, manufacturer_keys):
        img = bytearray(setup["signed_image"])
        img[setup["code_len"] - 8] ^= 0x01
        assert verify_staged_signature(bytes(img), manufacturer_keys["public_pem"]) is False

    def test_ADR023_tampered_data_region_refused(self, setup, manufacturer_keys):
        """The compliance-params data region is INSIDE the signed range — a
        tampered registered value must invalidate the image signature."""
        img = bytearray(setup["signed_image"])
        img[setup["code_len"] + setup["data_len"] // 2] ^= 0x01
        assert verify_staged_signature(bytes(img), manufacturer_keys["public_pem"]) is False

    def test_ADR023_tampered_signature_byte_refused(self, setup, manufacturer_keys):
        img = bytearray(setup["signed_image"])
        img[setup["signed_len"] + 10] ^= 0x01
        assert verify_staged_signature(bytes(img), manufacturer_keys["public_pem"]) is False

    def test_ADR023_attacker_key_signature_refused(self, setup, manufacturer_keys,
                                                   attacker_keys):
        """Key pinning: an image with a VALID signature under a different
        RSA-2048 key must still be refused under the manufacturer key."""
        attacker_signed = sign_image(setup["unsigned_image"],
                                     attacker_keys["private_pem"])
        # Prove the negative is real: it verifies under the attacker's key...
        assert verify_image(attacker_signed, attacker_keys["public_pem"]) is True
        # ...and is refused under the manufacturer's.
        assert verify_staged_signature(
            attacker_signed, manufacturer_keys["public_pem"]) is False


# ---------------------------------------------------------------------------
# Gate 1 — streamed digest math (device hashes chunks, never the whole image)
# ---------------------------------------------------------------------------

class TestADR023_StreamedDigests:

    def test_ADR023_streamed_digests_match_whole_buffer(self, setup):
        raw = setup["signed_image"]
        code_len, data_len = setup["code_len"], setup["data_len"]
        code, data, signed = region_digests(raw, code_len, data_len)
        assert code == hashlib.sha256(raw[:code_len]).hexdigest()
        assert data == hashlib.sha256(raw[code_len:code_len + data_len]).hexdigest()
        assert signed == hashlib.sha256(raw[:code_len + data_len]).hexdigest()

    def test_ADR023_streamed_digests_chunk_size_invariant(self, setup):
        """Region boundaries must not depend on where chunk boundaries fall —
        including chunk sizes that straddle the code/data split mid-chunk."""
        raw = setup["signed_image"]
        code_len, data_len = setup["code_len"], setup["data_len"]
        reference = region_digests(raw, code_len, data_len, chunk_size=len(raw))
        for chunk_size in (1, 100, 512, 4096, 1 << 20):
            assert region_digests(raw, code_len, data_len, chunk_size) == reference, \
                f"digest mismatch at chunk_size={chunk_size}"

    def test_ADR023_signed_range_excludes_signature_bytes(self, setup):
        """The signature region must never be inside any hashed range, or
        signing would invalidate the very hash being signed."""
        raw = setup["signed_image"]
        unsigned = setup["unsigned_image"]
        # signed vs unsigned differ ONLY in the sig region...
        assert raw[:setup["signed_len"]] == unsigned[:setup["signed_len"]]
        # ...so all three digests must be identical across the two.
        assert (region_digests(raw, setup["code_len"], setup["data_len"])
                == region_digests(unsigned, setup["code_len"], setup["data_len"]))


# ---------------------------------------------------------------------------
# Gate 1 — UPDATE.MTA self-validation (untrusted sidecar, binding catches lies)
# ---------------------------------------------------------------------------

class TestADR023_MetaSelfValidation:

    def test_ADR023_true_split_reproduces_manifest_checksums(self, setup):
        """The binding the device enforces: region digests over the staged
        image == the RSA-signed manifest's checksums (manifest hashes are
        computed from the ELF — a different artifact — so this is a real
        cross-check, not a tautology)."""
        manifest = generate_manifest(setup["signed_px4"], elf_path=setup["elf_path"])
        code, data, _ = region_digests(
            setup["signed_image"], setup["code_len"], setup["data_len"])
        assert code == manifest["code_checksum"]
        assert data == manifest["data_checksum"]

    def test_ADR023_shifted_split_breaks_binding(self, setup):
        """A tampered meta that shifts one word from data to code satisfies
        every structural invariant (sum unchanged, both nonzero, aligned) —
        ONLY the hash binding can catch it. This is the self-validation
        property the untrusted-sidecar design stands on."""
        manifest = generate_manifest(setup["signed_px4"], elf_path=setup["elf_path"])
        lied_code_len = setup["code_len"] + 4
        lied_data_len = setup["data_len"] - 4
        assert lied_code_len + lied_data_len == setup["signed_len"]  # invariant holds
        code, data, _ = region_digests(setup["signed_image"], lied_code_len, lied_data_len)
        assert code != manifest["code_checksum"]
        assert data != manifest["data_checksum"]


# ---------------------------------------------------------------------------
# A-8 round trip — bundler artifacts satisfy the device contract
# ---------------------------------------------------------------------------

class TestADR023_BundlerRoundTrip:

    def test_ADR023_bundler_artifacts_satisfy_device_contract(self, setup):
        image, meta = build_update_artifacts(setup["signed_px4"], setup["elf_path"])
        signed_len, image_size = parse_staged_image(image)  # BL would accept the layout
        assert meta["image_size"] == len(image) == image_size
        assert image_size == signed_len + RSA_2048_SIG_LEN
        assert meta["code_len"] + meta["data_len"] == signed_len
        assert meta["code_len"] > 0 and meta["data_len"] > 0
        assert meta["sha256"] == hashlib.sha256(image).hexdigest()

    def test_ADR023_bundler_image_is_bit_exact_signed_image(self, setup):
        image, _ = build_update_artifacts(setup["signed_px4"], setup["elf_path"])
        assert image == setup["signed_image"]

    def test_ADR023_bundler_refuses_unsigned_px4(self, setup):
        """Packaging an UPDATE.BIN the bootloader is guaranteed to refuse
        must fail on the host, not on the bench."""
        with pytest.raises(ValueError, match="placeholder"):
            build_update_artifacts(setup["unsigned_px4"], setup["elf_path"])

    def test_ADR023_bundler_refuses_sitl_px4_without_toc(self, setup, tmp_path):
        sitl_px4 = wrap_px4(b"\x7fELF" + b"\x00" * 4096, tmp_path / "sitl.px4")
        with pytest.raises(ValueError, match="TOC"):
            build_update_artifacts(sitl_px4, setup["elf_path"])

    def test_ADR023_bundler_refuses_wrong_size_elf(self, setup, tmp_path,
                                                   manufacturer_keys):
        """ELF from a build with different region sizes — caught by the
        length invariant even before any hashing."""
        other = build_synthetic_setup(tmp_path, manufacturer_keys["private_pem"],
                                      code_len=0x1200, prefix="othersize")
        with pytest.raises(ValueError, match="ELF"):
            build_update_artifacts(setup["signed_px4"], other["elf_path"])

    def test_ADR023_bundler_refuses_mismatched_build_via_binding(self, setup, tmp_path,
                                                                 manufacturer_keys):
        """Same region sizes, different code bytes (a stale ELF next to a
        fresh .px4): only the hash binding vs the manifest can catch it —
        shipping that bundle would fail on-device with POST/apply refusals."""
        other = build_synthetic_setup(tmp_path, manufacturer_keys["private_pem"],
                                      code_seed=0x33, prefix="otherbuild")
        manifest = generate_manifest(setup["signed_px4"], elf_path=other["elf_path"])
        with pytest.raises(ValueError, match="different builds"):
            build_update_artifacts(setup["signed_px4"], other["elf_path"],
                                   manifest=manifest)


# ---------------------------------------------------------------------------
# Fixture generator — negatives must fail in exactly the intended way
# ---------------------------------------------------------------------------

class TestADR023_FixtureGenerator:

    @pytest.fixture(scope="class")
    def fixtures(self, tmp_path_factory, setup, manufacturer_keys, attacker_keys):
        out = tmp_path_factory.mktemp("a10_fixtures")
        written = make_fixtures(
            setup["signed_px4"], setup["elf_path"], out,
            public_key_path=manufacturer_keys["public_path"],
            attacker_private_pem=attacker_keys["private_pem"],
            log=lambda _m: None,
        )
        return written

    def test_ADR023_generator_produces_full_fixture_set(self, fixtures):
        expected = {"UPDATE.BIN", "UPDATE.MTA", "UPDATE_TAMPERED.BIN",
                    "UPDATE_BADSIG.BIN", "UPDATE_ATTACKER.BIN", "UPDATE_TRUNC.BIN",
                    "UPDATE_BADMETA.MTA", "attacker_public.pem"}
        assert set(fixtures.keys()) == expected
        for path in fixtures.values():
            assert path.exists()

    def test_ADR023_generator_good_fixture_accepted(self, fixtures, manufacturer_keys):
        raw = fixtures["UPDATE.BIN"].read_bytes()
        assert verify_staged_signature(raw, manufacturer_keys["public_pem"]) is True

    def test_ADR023_generator_meta_matches_image(self, fixtures):
        meta = json.loads(fixtures["UPDATE.MTA"].read_text())
        raw = fixtures["UPDATE.BIN"].read_bytes()
        assert meta["image_size"] == len(raw)
        assert meta["sha256"] == hashlib.sha256(raw).hexdigest()

    @pytest.mark.parametrize("name", ["UPDATE_TAMPERED.BIN", "UPDATE_BADSIG.BIN",
                                      "UPDATE_ATTACKER.BIN"])
    def test_ADR023_generator_negative_parses_but_fails_signature(
            self, fixtures, manufacturer_keys, name):
        raw = fixtures[name].read_bytes()
        parse_staged_image(raw)  # structurally fine — must not raise
        assert verify_staged_signature(raw, manufacturer_keys["public_pem"]) is False

    def test_ADR023_generator_attacker_fixture_is_really_signed(self, fixtures):
        """Guard against a vacuous wrong-key fixture: it must carry a VALID
        signature under the shipped attacker pubkey."""
        raw = fixtures["UPDATE_ATTACKER.BIN"].read_bytes()
        attacker_pub = fixtures["attacker_public.pem"].read_bytes()
        assert verify_image(raw, attacker_pub) is True

    def test_ADR023_generator_truncated_fixture_fails_parse(self, fixtures):
        with pytest.raises(StagedImageReject):
            parse_staged_image(fixtures["UPDATE_TRUNC.BIN"].read_bytes())

    def test_ADR023_generator_badmeta_keeps_invariants_but_breaks_binding(
            self, fixtures, setup):
        good = json.loads(fixtures["UPDATE.MTA"].read_text())
        bad = json.loads(fixtures["UPDATE_BADMETA.MTA"].read_text())
        raw = fixtures["UPDATE.BIN"].read_bytes()
        # Structural invariants all still hold...
        assert bad["image_size"] == len(raw)
        assert bad["code_len"] + bad["data_len"] == good["code_len"] + good["data_len"]
        assert bad["code_len"] > 0 and bad["data_len"] > 0
        # ...but the split lies, so the binding digests diverge.
        manifest = generate_manifest(setup["signed_px4"], elf_path=setup["elf_path"])
        code, data, _ = region_digests(raw, bad["code_len"], bad["data_len"])
        assert code != manifest["code_checksum"]
        assert data != manifest["data_checksum"]
