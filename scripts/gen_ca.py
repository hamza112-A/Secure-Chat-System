#!/usr/bin/env python3
"""
Generate a self-signed Root Certificate Authority (CA)
This CA will be used to sign both server and client certificates
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_ca():
    """Generate a self-signed root CA certificate and private key"""
    
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    print("[*] Generating CA private key...")
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build the CA certificate
    print("[*] Creating self-signed CA certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hazro"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # Valid for 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write private key to file
    print("[*] Writing CA private key to certs/ca-key.pem")
    with open("certs/ca-key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate to file
    print("[*] Writing CA certificate to certs/ca-cert.pem")
    with open("certs/ca-cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] CA generated successfully!")
    print("    CA Certificate: certs/ca-cert.pem")
    print("    CA Private Key: certs/ca-key.pem")
    print("\n[!] Keep ca-key.pem secure and never commit it to version control!")
    
    return private_key, cert

if __name__ == "__main__":
    generate_ca()