"""
tools/verify_audit_log.py

Offline verification of a drone-produced audit log.

The flight controller signs the audit log per the audited reference Section 8:
  1. FC writes 132-byte entries to audit_log.bin (signature field zero, CRC32 only).
  2. After each write, FC computes SHA-256 of the complete audit_log.bin.
  3. FC encrypts the 32-byte hash with the embedded RSA-2048 PUBLIC key
     (PKCS#1 v1.5) and writes 256 bytes to audit_log.sig.

Manufacturer verification is the inverse: decrypt audit_log.sig with the
PRIVATE key, then compare against SHA-256(audit_log.bin). If they match,
the log file is authentic and untampered.

Usage:
    py tools/verify_audit_log.py \
        --log Docs/audit_log.bin \
        --sig Docs/audit_log.sig \
        --key pki/manufacturer/private/manufacturer_private.pem

Exit code 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def verify(log_path: Path, sig_path: Path, key_path: Path) -> bool:
    log_data = log_path.read_bytes()
    sig_data = sig_path.read_bytes()
    key_pem = key_path.read_bytes()

    if len(sig_data) != 256:
        print(f"FAIL: signature is {len(sig_data)} bytes, expected 256 (RSA-2048)")
        return False

    private_key = serialization.load_pem_private_key(key_pem, password=None)

    expected = hashlib.sha256(log_data).digest()
    try:
        decrypted = private_key.decrypt(sig_data, padding.PKCS1v15())
    except Exception as exc:
        print(f"FAIL: could not decrypt .sig with private key — {exc}")
        return False

    print(f"  log file:        {log_path}  ({len(log_data)} bytes, "
          f"{len(log_data) // 132} entries)")
    print(f"  expected SHA-256: {expected.hex()}")
    print(f"  decrypted hash:   {decrypted.hex()}")

    if decrypted == expected:
        print("PASS: audit log signature is authentic")
        return True

    print("FAIL: decrypted hash does not match SHA-256(log)")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[2])
    parser.add_argument("--log", required=True, type=Path,
                        help="Path to audit_log.bin")
    parser.add_argument("--sig", required=True, type=Path,
                        help="Path to audit_log.sig (256 bytes)")
    parser.add_argument("--key", required=True, type=Path,
                        help="Manufacturer RSA-2048 private key (PEM)")
    args = parser.parse_args()

    for p in (args.log, args.sig, args.key):
        if not p.is_file():
            print(f"ERROR: {p} not found", file=sys.stderr)
            return 2

    return 0 if verify(args.log, args.sig, args.key) else 1


if __name__ == "__main__":
    raise SystemExit(main())
