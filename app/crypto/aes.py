#!/usr/bin/env python3
"""
AES-128 encryption/decryption with PKCS#7 padding
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AESCipher:
    """AES-128 encryption with PKCS#7 padding"""
    
    BLOCK_SIZE = 16  # AES block size in bytes
    
    def __init__(self, key):
        """
        Initialize AES cipher with a 16-byte key
        
        Args:
            key: 16-byte encryption key
        """
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        self.key = key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding
        
        Args:
            plaintext: String or bytes to encrypt
        
        Returns:
            bytes: IV + ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Apply PKCS#7 padding
        padded_data = self._pkcs7_pad(plaintext)
        
        # Generate random IV
        iv = get_random_bytes(self.BLOCK_SIZE)
        
        # Create cipher and encrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using AES-128 in CBC mode
        
        Args:
            ciphertext: bytes (IV + encrypted data)
        
        Returns:
            bytes: Decrypted plaintext
        """
        # Extract IV and ciphertext
        iv = ciphertext[:self.BLOCK_SIZE]
        encrypted_data = ciphertext[self.BLOCK_SIZE:]
        
        # Create cipher and decrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(encrypted_data)
        
        # Remove PKCS#7 padding
        plaintext = self._pkcs7_unpad(padded_plaintext)
        
        return plaintext
    
    def _pkcs7_pad(self, data):
        """
        Apply PKCS#7 padding
        
        Args:
            data: bytes to pad
        
        Returns:
            bytes: Padded data
        """
        padding_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padding = bytes([padding_len] * padding_len)
        return data + padding
    
    def _pkcs7_unpad(self, data):
        """
        Remove PKCS#7 padding
        
        Args:
            data: Padded bytes
        
        Returns:
            bytes: Unpadded data
        """
        if not data:
            raise ValueError("Cannot unpad empty data")
        
        padding_len = data[-1]
        
        # Validate padding
        if padding_len > self.BLOCK_SIZE or padding_len == 0:
            raise ValueError("Invalid padding")
        
        # Check all padding bytes
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Invalid padding bytes")
        
        return data[:-padding_len]

def encrypt_message(key, plaintext):
    """
    Helper function to encrypt a message
    
    Args:
        key: 16-byte AES key
        plaintext: Message to encrypt
    
    Returns:
        str: Base64-encoded ciphertext
    """
    cipher = AESCipher(key)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_message(key, ciphertext_b64):
    """
    Helper function to decrypt a message
    
    Args:
        key: 16-byte AES key
        ciphertext_b64: Base64-encoded ciphertext
    
    Returns:
        str: Decrypted plaintext
    """
    cipher = AESCipher(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')