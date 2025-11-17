#!/usr/bin/env python3
"""
Secure Chat Protocol Implementation
Handles message formatting, encryption, and protocol state management
"""

import json
import base64
import hashlib
import time
import os
from Crypto.Random import get_random_bytes

class ProtocolMessage:
    """Protocol message types and formatting"""
    
    @staticmethod
    def hello(client_cert_pem, nonce=None):
        """
        Create client hello message with certificate
        
        Args:
            client_cert_pem: PEM-encoded client certificate
            nonce: Random nonce (optional, will be generated if not provided)
        
        Returns:
            dict: Hello message
        """
        if nonce is None:
            nonce = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        
        return {
            "type": "hello",
            "client_cert": client_cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def server_hello(server_cert_pem, nonce=None):
        """
        Create server hello message with certificate
        
        Args:
            server_cert_pem: PEM-encoded server certificate
            nonce: Random nonce (optional, will be generated if not provided)
        
        Returns:
            dict: Server hello message
        """
        if nonce is None:
            nonce = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        
        return {
            "type": "server_hello",
            "server_cert": server_cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def register(email, username, password):
        """
        Create registration message with salted password hash
        
        Args:
            email: User email
            username: Username
            password: Plain password (will be hashed with salt)
        
        Returns:
            dict: Registration message with encrypted credentials
        """
        # Generate random salt
        salt = get_random_bytes(16)
        
        # Compute salted hash: SHA256(salt || password)
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        return {
            "type": "register",
            "email": email,
            "username": username,
            "pwd_hash": pwd_hash,
            "salt": base64.b64encode(salt).decode('utf-8')
        }
    
    @staticmethod
    def login(email, password, salt):
        """
        Create login message with salted password hash
        
        Args:
            email: User email
            password: Plain password
            salt: Salt from server (bytes)
        
        Returns:
            dict: Login message
        """
        # Compute salted hash: SHA256(salt || password)
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        nonce = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        
        return {
            "type": "login",
            "email": email,
            "pwd_hash": pwd_hash,
            "nonce": nonce
        }
    
    @staticmethod
    def dh_client(g, p, A):
        """
        Create DH client message with public parameters
        
        Args:
            g: Generator
            p: Prime modulus
            A: Client's public DH value
        
        Returns:
            dict: DH client message
        """
        return {
            "type": "dh_client",
            "g": g,
            "p": p,
            "A": A
        }
    
    @staticmethod
    def dh_server(B):
        """
        Create DH server response with public value
        
        Args:
            B: Server's public DH value
        
        Returns:
            dict: DH server message
        """
        return {
            "type": "dh_server",
            "B": B
        }
    
    @staticmethod
    def chat_message(seqno, timestamp, ciphertext_b64, signature_b64):
        """
        Create encrypted chat message with signature
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext_b64: Base64-encoded ciphertext
            signature_b64: Base64-encoded RSA signature
        
        Returns:
            dict: Chat message
        """
        return {
            "type": "msg",
            "seqno": seqno,
            "ts": timestamp,
            "ct": ciphertext_b64,
            "sig": signature_b64
        }
    
    @staticmethod
    def receipt(peer, first_seq, last_seq, transcript_hash, signature_b64):
        """
        Create session receipt for non-repudiation
        
        Args:
            peer: "client" or "server"
            first_seq: First sequence number in session
            last_seq: Last sequence number in session
            transcript_hash: Hex-encoded SHA-256 hash of transcript
            signature_b64: Base64-encoded signature over transcript hash
        
        Returns:
            dict: Session receipt
        """
        return {
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature_b64
        }
    
    @staticmethod
    def response(status, message, data=None):
        """
        Create generic response message
        
        Args:
            status: "success" or "error"
            message: Response message
            data: Optional data payload
        
        Returns:
            dict: Response message
        """
        resp = {
            "type": "response",
            "status": status,
            "message": message
        }
        if data:
            resp["data"] = data
        return resp
    
    @staticmethod
    def encode(message_dict):
        """
        Encode message dictionary to JSON bytes
        
        Args:
            message_dict: Message dictionary
        
        Returns:
            bytes: JSON-encoded message
        """
        return json.dumps(message_dict).encode('utf-8')
    
    @staticmethod
    def decode(message_bytes):
        """
        Decode JSON bytes to message dictionary
        
        Args:
            message_bytes: JSON-encoded message bytes
        
        Returns:
            dict: Message dictionary
        """
        return json.loads(message_bytes.decode('utf-8'))


class TranscriptManager:
    """Manages session transcript for non-repudiation"""
    
    def __init__(self, role, peer_cert_fingerprint):
        """
        Initialize transcript manager
        
        Args:
            role: "client" or "server"
            peer_cert_fingerprint: SHA-256 fingerprint of peer certificate
        """
        self.role = role
        self.peer_fingerprint = peer_cert_fingerprint
        self.transcript_lines = []
        self.first_seq = None
        self.last_seq = None
        
        # Create transcripts directory
        os.makedirs("transcripts", exist_ok=True)
        
        # Transcript file path
        timestamp = int(time.time())
        self.transcript_file = f"transcripts/{role}_session_{timestamp}.txt"
    
    def add_message(self, seqno, timestamp, ciphertext_b64, signature_b64, direction):
        """
        Add message to transcript
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp
            ciphertext_b64: Base64-encoded ciphertext
            signature_b64: Base64-encoded signature
            direction: "sent" or "received"
        """
        # Update sequence number range
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Create transcript line
        line = f"{seqno}|{timestamp}|{ciphertext_b64}|{signature_b64}|{self.peer_fingerprint}|{direction}\n"
        self.transcript_lines.append(line)
        
        # Append to file
        with open(self.transcript_file, "a") as f:
            f.write(line)
    
    def compute_transcript_hash(self):
        """
        Compute SHA-256 hash of entire transcript
        
        Returns:
            str: Hex-encoded transcript hash
        """
        transcript_str = "".join(self.transcript_lines)
        return hashlib.sha256(transcript_str.encode('utf-8')).hexdigest()
    
    def generate_receipt(self, signer):
        """
        Generate signed session receipt
        
        Args:
            signer: MessageSigner instance with private key
        
        Returns:
            dict: Session receipt message
        """
        transcript_hash = self.compute_transcript_hash()
        signature = signer.sign_transcript(transcript_hash)
        
        receipt = ProtocolMessage.receipt(
            self.role,
            self.first_seq,
            self.last_seq,
            transcript_hash,
            signature
        )
        
        # Save receipt to file
        receipt_file = self.transcript_file.replace(".txt", "_receipt.json")
        with open(receipt_file, "w") as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[✓] Session receipt saved to {receipt_file}")
        
        return receipt
    
    def verify_receipt(self, receipt, verifier):
        """
        Verify a session receipt
        
        Args:
            receipt: Receipt dictionary
            verifier: MessageSigner instance with public key
        
        Returns:
            bool: True if receipt is valid
        """
        # Recompute transcript hash
        computed_hash = self.compute_transcript_hash()
        
        # Check if hash matches
        if computed_hash != receipt["transcript_sha256"]:
            print(f"[!] Transcript hash mismatch")
            return False
        
        # Verify signature
        is_valid = verifier.verify_transcript_signature(
            receipt["transcript_sha256"],
            receipt["sig"]
        )
        
        return is_valid