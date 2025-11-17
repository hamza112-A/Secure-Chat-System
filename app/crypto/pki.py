#!/usr/bin/env python3
"""PKI operations: certificate loading, validation, and verification"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import hashlib

class PKIManager:
    """Manages PKI operations for certificate handling"""
    
    def __init__(self, ca_cert_path="certs/ca-cert.pem"):
        self.ca_cert = self.load_certificate(ca_cert_path)
    
    @staticmethod
    def load_certificate(cert_path):
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    
    @staticmethod
    def load_private_key(key_path):
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return private_key
    
    @staticmethod
    def certificate_to_pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    @staticmethod
    def pem_to_certificate(pem_str):
        return x509.load_pem_x509_certificate(
            pem_str.encode('utf-8'), default_backend()
        )
    
    def validate_certificate(self, cert, expected_cn=None):
        """Validate certificate against CA"""
        try:
            # Check validity period
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc:
                return False, "Certificate not yet valid"
            if now > cert.not_valid_after_utc:
                return False, "Certificate has expired"
            
            # Verify issuer matches CA
            if cert.issuer != self.ca_cert.subject:
                return False, "Certificate not issued by trusted CA"
            
            # Verify signature using CA's public key
            try:
                from cryptography.hazmat.primitives.asymmetric import padding
                
                # Get the signature algorithm used
                sig_algorithm = cert.signature_algorithm_oid
                
                # For RSA signatures with SHA256
                if 'sha256' in str(sig_algorithm).lower():
                    hash_algorithm = hashes.SHA256()
                elif 'sha384' in str(sig_algorithm).lower():
                    hash_algorithm = hashes.SHA384()
                elif 'sha512' in str(sig_algorithm).lower():
                    hash_algorithm = hashes.SHA512()
                else:
                    hash_algorithm = hashes.SHA256()  # default
                
                # Verify the signature
                self.ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
            except Exception as e:
                return False, f"Signature verification failed: {e}"
            
            # Check Common Name if specified
            if expected_cn:
                cert_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if not cert_cn or cert_cn[0].value != expected_cn:
                    return False, f"Common Name mismatch"
            
            return True, None
            
        except Exception as e:
            return False, f"Validation error: {e}"
    
    @staticmethod
    def get_certificate_fingerprint(cert):
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_der).hexdigest()
    
    @staticmethod
    def get_common_name(cert):
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn_attrs[0].value if cn_attrs else None

def verify_certificate_chain(cert_pem, ca_cert_path="certs/ca-cert.pem"):
    """Verify a certificate against the CA"""
    try:
        pki = PKIManager(ca_cert_path)
        cert = PKIManager.pem_to_certificate(cert_pem)
        is_valid, error = pki.validate_certificate(cert)
        return (True, cert, None) if is_valid else (False, None, error)
    except Exception as e:
        return False, None, f"Certificate parsing error: {e}"