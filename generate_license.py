"""Generate a signed SMB Sentinel license using the publisher's private key."""
from __future__ import annotations
import argparse
import base64
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign an SMB Sentinel premium license.")
    parser.add_argument("customer_tag", nargs="?", default="")
    args = parser.parse_args()
    key_path = Path(os.environ.get("SMB_SENTINEL_PRIVATE_KEY", "smb_sentinel_private_key.pem"))
    if not key_path.is_file():
        parser.error("Private key not found. Generate it on the publisher machine first.")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    payload = json.dumps({
        "customer": args.customer_tag[:80],
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_urlsafe(18),
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(payload)
    print("Premium license key:")
    print(f"MRCYBER.{_encode(payload)}.{_encode(signature)}")
    print("Keep the private signing key offline; send only the license string to the customer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
