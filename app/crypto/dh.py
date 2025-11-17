#!/usr/bin/env python3
"""
Diffie-Hellman key exchange implementation
"""

import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes

class DHKeyExchange:
    """Diffie-Hellman key exchange"""
    
    # Safe prime (2048-bit)
    DEFAULT_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    
    DEFAULT_G = 2
    
    def __init__(self, p=None, g=None):
        """Initialize DH with parameters p and g"""
        self.p = p if p else self.DEFAULT_P
        self.g = g if g else self.DEFAULT_G
        
        # Generate private key
        self.private_key = self._generate_private_key()
        
        # Compute public key: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
    
    def _generate_private_key(self):
        """Generate a random private key"""
        key_bytes = get_random_bytes(256)
        private_key = bytes_to_long(key_bytes) % (self.p - 2) + 2
        return private_key
    
    def get_public_params(self):
        """Get public DH parameters to send to peer"""
        return {
            'g': self.g,
            'p': self.p,
            'A': self.public_key
        }
    
    def compute_shared_secret(self, peer_public_key):
        """Compute shared secret from peer's public key"""
        if peer_public_key <= 1 or peer_public_key >= self.p - 1:
            raise ValueError("Invalid peer public key")
        
        shared_secret = pow(peer_public_key, self.private_key, self.p)
        return shared_secret
    
    @staticmethod
    def derive_aes_key(shared_secret):
        """Derive AES-128 key from shared secret"""
        secret_bytes = long_to_bytes(shared_secret)
        hash_obj = hashlib.sha256(secret_bytes)
        hash_digest = hash_obj.digest()
        aes_key = hash_digest[:16]
        return aes_key