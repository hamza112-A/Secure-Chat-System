#!/usr/bin/env python3
"""
Generate server and client certificates signed by the CA
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca():
    """Load CA certificate and private key"""
    
    print("[*] Loading CA certificate and key...")
    
    # Load CA private key
    with open("certs/ca-key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open("certs/ca-cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_key, ca_cert

def generate_certificate(entity_type, common_name, ca_key, ca_cert):
    """
    Generate a certificate signed by the CA
    
    Args:
        entity_type: 'server' or 'client'
        common_name: CN for the certificate (e.g., 'localhost' for server)
        ca_key: CA private key
        ca_cert: CA certificate
    """
    
    print(f"\n[*] Generating {entity_type} private key...")
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print(f"[*] Creating {entity_type} certificate...")
    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hazro"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"SecureChat {entity_type.title()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valid for 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Add key usage extension
    if entity_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:  # client
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    
    # Sign the certificate with CA's private key
    cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Write private key
    key_filename = f"certs/{entity_type}-key.pem"
    print(f"[*] Writing {entity_type} private key to {key_filename}")
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    cert_filename = f"certs/{entity_type}-cert.pem"
    print(f"[*] Writing {entity_type} certificate to {cert_filename}")
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[✓] {entity_type.title()} certificate generated successfully!")
    
    return private_key, cert

if __name__ == "__main__":
    # Import here to avoid issues if not needed
    import ipaddress
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    # Check if CA exists
    if not os.path.exists("certs/ca-cert.pem") or not os.path.exists("certs/ca-key.pem"):
        print("[!] CA not found. Please run gen_ca.py first.")
        sys.exit(1)
    
    # Load CA
    ca_key, ca_cert = load_ca()
    
    # Generate server certificate
    print("\n" + "="*50)
    print("Generating Server Certificate")
    print("="*50)
    generate_certificate("server", "localhost", ca_key, ca_cert)
    
    # Generate client certificate
    print("\n" + "="*50)
    print("Generating Client Certificate")
    print("="*50)
    generate_certificate("client", "securechat-client", ca_key, ca_cert)
    
    print("\n" + "="*50)
    print("[✓] All certificates generated successfully!")
    print("="*50)
    print("\nGenerated files:")
    print("  - certs/server-cert.pem")
    print("  - certs/server-key.pem")
    print("  - certs/client-cert.pem")
    print("  - certs/client-key.pem")