#!/usr/bin/env python3
"""Generate prototype keys locally. Never overwrite an existing trust configuration."""
import argparse
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def public_bytes(key):
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def private_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )


def save_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.output_dir.resolve()
    local = root / ".local"
    targets = [root / "auth_keys.h", local / "issuer-private.pem",
               local / "door-private.pem", local / "trust-config.json"]
    if any(p.exists() for p in targets):
        parser.error("Keys already exist. Keep them to preserve phone/controller trust.")
    local.mkdir(parents=True, mode=0o700, exist_ok=True)
    issuer = ec.generate_private_key(ec.SECP256R1())
    door = ec.generate_private_key(ec.SECP256R1())
    issuer_public, door_public = public_bytes(issuer), public_bytes(door)
    door_scalar = door.private_numbers().private_value.to_bytes(32, "big")
    def array(data):
        return ",".join(f"0x{value:02x}" for value in data)
    header = ("#pragma once\n#include <stdint.h>\n"
              "// GENERATED LOCAL TEST KEYS. Never commit this file.\n"
              f"const uint8_t ISSUER_PUBLIC[65] = {{{array(issuer_public)}}};\n"
              f"const uint8_t DOOR_PRIVATE[32] = {{{array(door_scalar)}}};\n")
    save_private(local / "issuer-private.pem", private_pem(issuer))
    save_private(local / "door-private.pem", private_pem(door))
    save_private(root / "auth_keys.h", header.encode())
    trust = {"doorId": 12, "curve": "P-256",
             "publicKeyEncoding": "X9.63 uncompressed hex",
             "issuerPublic": issuer_public.hex(), "doorPublic": door_public.hex()}
    (local / "trust-config.json").write_text(json.dumps(trust, indent=2) + "\n")
    print("Created local prototype keys and .local/trust-config.json.")
    print("Configure the issuer service and mobile app with the matching keys.")
    print("Issuer private key belongs only on the issuer/PMS, never on the H2 or phone.")


if __name__ == "__main__":
    main()
