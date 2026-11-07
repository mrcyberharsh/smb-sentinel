"""Generate an Ed25519 key pair for SMB Sentinel licensing.

Run once on the publisher's trusted machine. Never commit or share the
private key. Copy the printed public key into license_manager.py.
"""
from __future__ import annotations
import argparse
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser(description="Create SMB Sentinel signing keys.")
    parser.add_argument("--force", action="store_true", help="Replace existing local key files.")
    args = parser.parse_args()
    private_path = Path("smb_sentinel_private_key.pem")
    public_path = Path("smb_sentinel_public_key.txt")
    if (private_path.exists() or public_path.exists()) and not args.force:
        parser.error("Key files already exist; use --force only if you intend to rotate the key pair.")
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path.write_bytes(private_bytes)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    public_b64 = base64.urlsafe_b64encode(public_bytes).decode("ascii").rstrip("=")
    public_path.write_text(public_b64 + "\n", encoding="ascii")
    print("Private key saved locally. Keep it offline and out of Git.")
    print(f"Public key (paste into PUBLIC_KEY_B64):\n{public_b64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
