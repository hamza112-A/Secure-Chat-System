#!/usr/bin/env python3
"""Test certificate validation"""

from crypto.pki import PKIManager, verify_certificate_chain
import sys

def test_valid_cert():
    print("\n=== Testing Valid Certificate ===")
    with open("certs/server-cert.pem", "r") as f:
        cert_pem = f.read()
    
    is_valid, cert, error = verify_certificate_chain(cert_pem)
    print(f"Valid: {is_valid}")
    if not is_valid:
        print(f"Error: {error}")
    return is_valid

def test_expired_cert():
    # Would need to generate an expired cert for this test
    print("\n=== Testing Expired Certificate ===")
    print("(Would need expired cert)")

def test_self_signed():
    print("\n=== Testing Self-Signed Certificate ===")
    print("(Would need self-signed cert)")

if __name__ == "__main__":
    test_valid_cert()