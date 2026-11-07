"""Offline Ed25519 license verification for SMB Sentinel.

Only the public verification key belongs in this application. Keep the
matching private signing key outside the repository and customer builds.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Paste the base64url raw public key produced by generate_signing_keys.py.
# Never put the private signing key in this file or in the public repository.
PUBLIC_KEY_B64 = ""
LICENSE_FILE = Path.home() / ".smb_sentinel_license.json"


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_key(key: str) -> bool:
    if not PUBLIC_KEY_B64 or not key:
        return False
    try:
        prefix, payload_text, signature_text = key.strip().split(".")
        if prefix != "MRCYBER":
            return False
        payload = _decode(payload_text)
        signature = _decode(signature_text)
        public_key = Ed25519PublicKey.from_public_bytes(_decode(PUBLIC_KEY_B64))
        public_key.verify(signature, payload)
        decoded = json.loads(payload.decode("utf-8"))
        return isinstance(decoded, dict) and bool(decoded.get("nonce"))
    except (ValueError, TypeError, UnicodeDecodeError, InvalidSignature):
        return False


def save_key(key: str) -> None:
    LICENSE_FILE.write_text(json.dumps({"key": key.strip()}), encoding="utf-8")


def load_saved_key() -> str:
    try:
        return json.loads(LICENSE_FILE.read_text(encoding="utf-8")).get("key", "")
    except (OSError, ValueError, TypeError):
        return ""


def is_premium() -> bool:
    return verify_key(load_saved_key())
