"""
SMB Sentinel - License Manager
MR CYBER

Manual premium unlock system for the pre-payment-gateway phase.
Flow:
  1. User pays you directly (UPI/manual).
  2. You run `python generate_license.py <customer name>` yourself.
  3. You email the generated key to the customer.
  4. Customer pastes it into the app -> premium features unlock.

This is offline (no internet required to verify) and signature-based,
so it's harder to bypass than a plain "if key == X" check. It is not
unbreakable -- nothing client-side is -- but this is a reasonable
stopgap until you have an automated payment gateway with server-side
verification (see the note in README.md).
"""

import hashlib
import hmac
import os
import json

# This is your unique secret, generated for this project. Even though
# this file is public, this random string means only YOU (with this
# exact file) can generate keys that verify() will accept.
_SECRET = b"901cfbfb664cf813205a45c335ec318c0115101ee64af62d"

LICENSE_FILE = os.path.join(os.path.expanduser("~"), ".smb_sentinel_license.json")


def _sign(code: str) -> str:
    sig = hmac.new(_SECRET, code.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig[:8].upper()


def generate_key(customer_tag: str = "") -> str:
    """Generate a new premium license key. Run this yourself after a
    manual payment comes in."""
    raw = os.urandom(4).hex().upper()
    if customer_tag:
        tag = "".join(c for c in customer_tag.upper() if c.isalnum())[:6]
        raw = (tag + raw)[:8].ljust(8, "X")
    sig = _sign(raw)
    return f"MRCYBER-{raw}-{sig}"


def verify_key(key: str) -> bool:
    """Check if a key is structurally valid and correctly signed."""
    if not key:
        return False
    key = key.strip().upper()
    parts = key.split("-")
    if len(parts) != 3 or parts[0] != "MRCYBER":
        return False
    raw, sig = parts[1], parts[2]
    if len(raw) != 8 or len(sig) != 8:
        return False
    return hmac.compare_digest(_sign(raw), sig)


def save_key(key: str):
    with open(LICENSE_FILE, "w") as f:
        json.dump({"key": key}, f)


def load_saved_key() -> str:
    if not os.path.exists(LICENSE_FILE):
        return ""
    try:
        with open(LICENSE_FILE) as f:
            return json.load(f).get("key", "")
    except Exception:
        return ""


def is_premium() -> bool:
    return verify_key(load_saved_key())
