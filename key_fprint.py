#!/usr/bin/env python3
"""Print SHA-256 fingerprints for OpenSSH public-key lines only."""

import argparse
import base64
import hashlib
import struct
import sys
from pathlib import Path


MAX_INPUT = 1024 * 1024


def parse_line(line):
    fields = line.split()
    if len(fields) < 2:
        raise ValueError("expected key type and base64 key blob")
    key_type, encoded = fields[:2]
    if not key_type.isascii() or not key_type.isprintable():
        raise ValueError("invalid key type")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise ValueError("invalid base64 key blob") from error
    if len(blob) < 4:
        raise ValueError("truncated key blob")
    name_size = struct.unpack(">I", blob[:4])[0]
    if name_size == 0 or 4 + name_size > len(blob):
        raise ValueError("invalid key type field in blob")
    try:
        blob_type = blob[4:4 + name_size].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII key type field in blob") from error
    if blob_type != key_type:
        raise ValueError("key type does not match blob")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return key_type, f"SHA256:{fingerprint}"


def read_input(path):
    if path == "-":
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
    else:
        with Path(path).open("rb") as source:
            data = source.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("input exceeds the 1 MiB limit")
    return data.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Show SHA-256 fingerprints for OpenSSH public-key lines.")
    parser.add_argument("input", help="public key file, or - to read standard input")
    args = parser.parse_args()
    try:
        lines = read_input(args.input).splitlines()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"key-fprint: {error}", file=sys.stderr)
        return 2

    valid = errors = 0
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            key_type, fingerprint = parse_line(line)
        except ValueError as error:
            print(f"key-fprint: line {number}: {error}", file=sys.stderr)
            errors += 1
            continue
        print(f"line {number}: {key_type} {fingerprint}")
        valid += 1

    if not valid:
        print("key-fprint: no valid public keys found", file=sys.stderr)
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
