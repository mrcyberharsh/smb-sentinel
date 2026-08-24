"""
Run this YOURSELF (not the customer) after you manually confirm a payment.

Usage:
    python generate_license.py "Customer Name or Email"

It prints a license key -- copy/paste it into an email to the customer.
"""

import sys
from license_manager import generate_key

if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else ""
    key = generate_key(tag)
    print("\nGenerated Premium License Key:")
    print(f"  {key}\n")
    print("Send this to the customer. They paste it into:")
    print("  SMB Sentinel -> Settings -> Enter Premium License Key\n")
