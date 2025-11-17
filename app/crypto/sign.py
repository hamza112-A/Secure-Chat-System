
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import base64

class MessageSigner:
    """Handles RSA signing and verification of messages"""
    
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key
    
    def sign_message(self, seqno, timestamp, ciphertext):
        if not self.private_key:
            raise ValueError("Private key required for signing")
        digest = self._compute_digest(seqno, timestamp, ciphertext)
        signature = self.private_key.sign(
            digest, padding.PKCS1v15(), hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, seqno, timestamp, ciphertext, signature_b64):
        if not self.public_key:
            raise ValueError("Public key required for verification")
        try:
            digest = self._compute_digest(seqno, timestamp, ciphertext)
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature, digest, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def _compute_digest(seqno, timestamp, ciphertext):
        message = f"{seqno}||{timestamp}||{ciphertext}".encode('utf-8')
        return hashlib.sha256(message).digest()
    
    def sign_transcript(self, transcript_hash):
        if not self.private_key:
            raise ValueError("Private key required for signing")
        hash_bytes = bytes.fromhex(transcript_hash)
        signature = self.private_key.sign(
            hash_bytes, padding.PKCS1v15(), hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_transcript_signature(self, transcript_hash, signature_b64):
        if not self.public_key:
            raise ValueError("Public key required for verification")
        try:
            hash_bytes = bytes.fromhex(transcript_hash)
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature, hash_bytes, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except Exception:
            return False