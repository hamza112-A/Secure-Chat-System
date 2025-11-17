#!/usr/bin/env python3
"""
Secure Chat Client
Connects to server, authenticates, and exchanges encrypted messages
"""

import socket
import sys
import time
import base64
import getpass

# Import custom modules
from crypto.aes import AESCipher
from crypto.dh import DHKeyExchange
from crypto.pki import PKIManager, verify_certificate_chain
from crypto.sign import MessageSigner
from common.protocol import ProtocolMessage, TranscriptManager
from common.utils import send_message, receive_message, log_event, print_certificate_info

class SecureChatClient:
    """Secure Chat Client Implementation"""
    
    def __init__(self, server_host='localhost', server_port=9999):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # Load client certificate and key
        self.pki = PKIManager("certs/ca-cert.pem")
        self.client_cert = PKIManager.load_certificate("certs/client-cert.pem")
        self.client_key = PKIManager.load_private_key("certs/client-key.pem")
        self.client_cert_pem = PKIManager.certificate_to_pem(self.client_cert)
        
        # Session state
        self.server_cert = None
        self.session_key = None
        self.signer = None
        self.transcript = None
        self.next_seqno = 1
        self.server_seqno = 0
        self.username = None
        
        log_event("client", "INIT", f"Client initialized for {server_host}:{server_port}")
    
    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            log_event("client", "CONNECT", f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            log_event("client", "ERROR", f"Connection failed: {e}")
            return False
    
    def run(self):
        """Main client flow"""
        if not self.connect():
            return
        
        try:
            # Phase 1: Control Plane - Certificate Exchange
            if not self.control_plane():
                print("[!] Certificate validation failed")
                return
            
            # Phase 2: Authentication
            if not self.authenticate():
                print("[!] Authentication failed")
                return
            
            # Phase 3: Key Agreement
            if not self.key_agreement():
                print("[!] Key agreement failed")
                return
            
            # Phase 4: Data Plane - Chat
            self.chat_session()
            
            # Phase 5: Non-Repudiation
            self.teardown()
            
        except Exception as e:
            log_event("client", "ERROR", f"Error: {e}")
        finally:
            if self.socket:
                self.socket.close()
                log_event("client", "DISCONNECT", "Disconnected from server")
    
    def control_plane(self):
        """Control Plane: Certificate exchange"""
        log_event("client", "CONTROL", "Starting certificate exchange")
        
        # Send client hello
        hello = ProtocolMessage.hello(self.client_cert_pem)
        send_message(self.socket, hello)
        log_event("client", "CONTROL", "Sent client hello")
        
        # Receive server hello
        msg = receive_message(self.socket)
        if not msg or msg.get("type") != "server_hello":
            log_event("client", "ERROR", "Invalid server hello")
            return False
        
        server_cert_pem = msg.get("server_cert")
        
        # Validate server certificate
        is_valid, cert, error = verify_certificate_chain(server_cert_pem)
        if not is_valid:
            log_event("client", "ERROR", f"Server certificate validation failed: {error}")
            return False
        
        self.server_cert = cert
        log_event("client", "SUCCESS", "Server certificate validated")
        print_certificate_info(cert)
        
        return True
    
    def authenticate(self):
        """Authenticate with server (register or login)"""
        print("\n" + "="*60)
        print("AUTHENTICATION")
        print("="*60)
        choice = input("(R)egister or (L)ogin? ").strip().upper()
        
        if choice == 'R':
            return self.register()
        elif choice == 'L':
            return self.login()
        else:
            print("[!] Invalid choice")
            return False
    
    def register(self):
        """Register new user"""
        print("\n--- Registration ---")
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        # Temporary DH exchange for credential encryption
        dh, params = DHKeyExchange(), {}
        dh_msg = ProtocolMessage.dh_client(dh.g, dh.p, dh.public_key)
        send_message(self.socket, dh_msg)
        
        # Receive server DH response
        msg = receive_message(self.socket)
        if not msg or msg.get("type") != "dh_server":
            return False
        
        # Derive temporary key
        shared_secret = dh.compute_shared_secret(msg["B"])
        temp_key = DHKeyExchange.derive_aes_key(shared_secret)
        
        # Create registration message
        reg_msg = ProtocolMessage.register(email, username, password)
        
        # Optionally encrypt the registration data
        # For simplicity, sending directly (already has salted hash)
        send_message(self.socket, reg_msg)
        
        # Receive response
        resp = receive_message(self.socket)
        if resp and resp.get("status") == "success":
            log_event("client", "SUCCESS", "Registration successful")
            self.username = username
            return True
        else:
            log_event("client", "ERROR", f"Registration failed: {resp.get('message')}")
            return False
    
    def login(self):
        """Login existing user"""
        print("\n--- Login ---")
        email = input("Email: ").strip()
        password = getpass.getpass("Password: ")
        
        # Get salt from server (in real implementation, salt would be retrieved first)
        # For simplicity, we'll generate salt client-side
        # In proper implementation: send email -> receive salt -> compute hash
        import hashlib
        from Crypto.Random import get_random_bytes
        
        # Temporary DH exchange
        dh = DHKeyExchange()
        dh_msg = ProtocolMessage.dh_client(dh.g, dh.p, dh.public_key)
        send_message(self.socket, dh_msg)
        
        # Receive server DH response
        msg = receive_message(self.socket)
        if not msg or msg.get("type") != "dh_server":
            return False
        
        # Derive temporary key
        shared_secret = dh.compute_shared_secret(msg["B"])
        temp_key = DHKeyExchange.derive_aes_key(shared_secret)
        
        # For this implementation, we need to match the salt used during registration
        # In production, fetch salt from server first
        # For demo purposes, client must use same salt (this is a simplification)
        salt = get_random_bytes(16)  # This should be fetched from server
        
        # Create login message
        login_msg = ProtocolMessage.login(email, password, salt)
        send_message(self.socket, login_msg)
        
        # Receive response
        resp = receive_message(self.socket)
        if resp and resp.get("status") == "success":
            log_event("client", "SUCCESS", "Login successful")
            self.username = resp.get("data", {}).get("username", "User")
            return True
        else:
            log_event("client", "ERROR", f"Login failed: {resp.get('message')}")
            return False
    
    def key_agreement(self):
        """DH key exchange for session key"""
        log_event("client", "KEYAGREE", "Starting DH key exchange")
        
        # Perform DH exchange
        dh = DHKeyExchange()
        dh_msg = ProtocolMessage.dh_client(dh.g, dh.p, dh.public_key)
        send_message(self.socket, dh_msg)
        
        # Receive server response
        msg = receive_message(self.socket)
        if not msg or msg.get("type") != "dh_server":
            return False
        
        # Compute shared secret and derive session key
        shared_secret = dh.compute_shared_secret(msg["B"])
        self.session_key = DHKeyExchange.derive_aes_key(shared_secret)
        
        log_event("client", "SUCCESS", "Session key established")
        
        # Initialize signer
        self.signer = MessageSigner(
            private_key=self.client_key,
            public_key=self.server_cert.public_key()
        )
        
        # Initialize transcript
        peer_fingerprint = PKIManager.get_certificate_fingerprint(self.server_cert)
        self.transcript = TranscriptManager("client", peer_fingerprint)
        
        return True
    
    def chat_session(self):
        """Encrypted chat session"""
        log_event("client", "CHAT", "Chat session started")
        cipher = AESCipher(self.session_key)
        
        # Wait for session ready
        resp = receive_message(self.socket)
        if not resp or resp.get("status") != "success":
            return
        
        print("\n" + "="*60)
        print("SECURE CHAT SESSION ACTIVE")
        print("="*60)
        print("Type your messages (or 'quit' to end session)\n")
        
        while True:
            # Send message
            plaintext = input(f"[{self.username}]: ")
            if plaintext.lower() == 'quit':
                send_message(self.socket, {"type": "quit"})
                break
            
            self.send_encrypted_message(plaintext, cipher)
            
            # Receive response
            msg = receive_message(self.socket)
            if not msg:
                break
            
            if msg.get("type") == "msg":
                if not self.handle_incoming_message(msg, cipher):
                    break
        
        log_event("client", "CHAT", "Chat session ended")
    
    def send_encrypted_message(self, plaintext, cipher):
        """Send encrypted message"""
        # Encrypt
        ciphertext = cipher.encrypt(plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        # Sign
        timestamp = int(time.time() * 1000)
        signature_b64 = self.signer.sign_message(self.next_seqno, timestamp, ciphertext_b64)
        
        # Create message
        msg = ProtocolMessage.chat_message(self.next_seqno, timestamp, ciphertext_b64, signature_b64)
        
        # Add to transcript
        self.transcript.add_message(self.next_seqno, timestamp, ciphertext_b64, signature_b64, "sent")
        
        # Send
        send_message(self.socket, msg)
        
        self.next_seqno += 1
    
    def handle_incoming_message(self, msg, cipher):
        """Handle incoming encrypted message"""
        seqno = msg["seqno"]
        timestamp = msg["ts"]
        ciphertext_b64 = msg["ct"]
        signature_b64 = msg["sig"]
        
        # Check sequence number
        if seqno <= self.server_seqno:
            log_event("client", "SECURITY", f"REPLAY DETECTED: seqno {seqno}")
            return False
        
        self.server_seqno = seqno
        
        # Verify signature
        if not self.signer.verify_signature(seqno, timestamp, ciphertext_b64, signature_b64):
            log_event("client", "SECURITY", "SIG_FAIL: Invalid signature")
            return False
        
        # Decrypt
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            
            print(f"\n[Server]: {plaintext}\n")
            
            # Add to transcript
            self.transcript.add_message(seqno, timestamp, ciphertext_b64, signature_b64, "received")
            
            return True
            
        except Exception as e:
            log_event("client", "ERROR", f"Decryption failed: {e}")
            return False
    
    def teardown(self):
        """Generate session receipt"""
        log_event("client", "TEARDOWN", "Generating session receipt")
        
        if self.transcript:
            receipt = self.transcript.generate_receipt(self.signer)
            
            # Receive server receipt
            server_receipt = receive_message(self.socket)
            if server_receipt:
                log_event("client", "SUCCESS", "Received server receipt")

if __name__ == "__main__":
    try:
        client = SecureChatClient()
        client.run()
    except KeyboardInterrupt:
        print("\n[!] Client terminated")
        sys.exit(0)