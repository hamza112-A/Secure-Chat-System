#!/usr/bin/env python3
"""
Secure Chat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import sys
import time
import base64
from dotenv import load_dotenv

# Import custom modules
from storage.db import DatabaseManager
from crypto.aes import AESCipher
from crypto.dh import DHKeyExchange
from crypto.pki import PKIManager, verify_certificate_chain
from crypto.sign import MessageSigner
from common.protocol import ProtocolMessage, TranscriptManager
from common.utils import send_message, receive_message, log_event, print_certificate_info

load_dotenv()

class SecureChatServer:
    """Secure Chat Server Implementation"""
    
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        
        # Load server certificate and key
        self.pki = PKIManager("certs/ca-cert.pem")
        self.server_cert = PKIManager.load_certificate("certs/server-cert.pem")
        self.server_key = PKIManager.load_private_key("certs/server-key.pem")
        self.server_cert_pem = PKIManager.certificate_to_pem(self.server_cert)
        
        # Database manager
        self.db = DatabaseManager()
        
        # Session state
        self.client_cert = None
        self.session_key = None
        self.signer = None
        self.transcript = None
        self.next_seqno = 1
        self.client_seqno = 0
        
        log_event("server", "INIT", f"Server initialized on {host}:{port}")
    
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        
        print(f"\n[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for client connection...\n")
        
        while True:
            client_sock, client_addr = self.socket.accept()
            log_event("server", "CONNECT", f"Client connected from {client_addr}")
            
            try:
                self.handle_client(client_sock)
            except Exception as e:
                log_event("server", "ERROR", f"Error handling client: {e}")
            finally:
                client_sock.close()
                log_event("server", "DISCONNECT", "Client disconnected")
                # Reset session state
                self.reset_session()
    
    def reset_session(self):
        """Reset session state for new connection"""
        self.client_cert = None
        self.session_key = None
        self.signer = None
        self.transcript = None
        self.next_seqno = 1
        self.client_seqno = 0
    
    def handle_client(self, client_sock):
        """Handle client connection"""
        
        # Phase 1: Control Plane - Certificate Exchange
        if not self.control_plane(client_sock):
            send_message(client_sock, ProtocolMessage.response("error", "BAD_CERT"))
            return
        
        # Phase 2: Authentication (Register or Login)
        if not self.authenticate_client(client_sock):
            send_message(client_sock, ProtocolMessage.response("error", "AUTH_FAILED"))
            return
        
        # Phase 3: Key Agreement - DH Exchange for Session Key
        if not self.key_agreement(client_sock):
            send_message(client_sock, ProtocolMessage.response("error", "KEY_AGREEMENT_FAILED"))
            return
        
        # Phase 4: Data Plane - Encrypted Chat
        self.chat_session(client_sock)
        
        # Phase 5: Non-Repudiation - Session Receipt
        self.teardown(client_sock)
    
    def control_plane(self, client_sock):
        """
        Control Plane: Certificate exchange and validation
        
        Returns:
            bool: True if certificates are valid
        """
        log_event("server", "CONTROL", "Starting control plane - certificate exchange")
        
        # Receive client hello with certificate
        msg = receive_message(client_sock)
        if not msg or msg.get("type") != "hello":
            log_event("server", "ERROR", "Invalid hello message")
            return False
        
        client_cert_pem = msg.get("client_cert")
        client_nonce = msg.get("nonce")
        
        # Validate client certificate
        is_valid, cert, error = verify_certificate_chain(client_cert_pem)
        if not is_valid:
            log_event("server", "ERROR", f"Certificate validation failed: {error}")
            return False
        
        self.client_cert = cert
        log_event("server", "SUCCESS", "Client certificate validated")
        print_certificate_info(cert)
        
        # Send server hello with certificate
        server_hello = ProtocolMessage.server_hello(self.server_cert_pem)
        send_message(client_sock, server_hello)
        log_event("server", "CONTROL", "Sent server hello")
        
        return True
    
    def authenticate_client(self, client_sock):
        """
        Authenticate client (register or login)
        
        Returns:
            bool: True if authentication successful
        """
        log_event("server", "AUTH", "Awaiting authentication")
        
        # Perform temporary DH exchange for credential encryption
        msg = receive_message(client_sock)
        if not msg or msg.get("type") != "dh_client":
            return False
        
        # Server DH response
        dh = DHKeyExchange(p=msg["p"], g=msg["g"])
        dh_response = ProtocolMessage.dh_server(dh.public_key)
        send_message(client_sock, dh_response)
        
        # Compute temporary AES key
        shared_secret = dh.compute_shared_secret(msg["A"])
        temp_key = DHKeyExchange.derive_aes_key(shared_secret)
        temp_cipher = AESCipher(temp_key)
        
        log_event("server", "AUTH", "Temporary DH key established")
        
        # Receive encrypted auth message
        msg = receive_message(client_sock)
        if not msg:
            return False
        
        msg_type = msg.get("type")
        
        if msg_type == "register":
            return self.handle_registration(client_sock, msg, temp_cipher)
        elif msg_type == "login":
            return self.handle_login(client_sock, msg, temp_cipher)
        else:
            return False
    
    def handle_registration(self, client_sock, msg, cipher):
        """Handle user registration"""
        try:
            # Decrypt encrypted data if present
            if "encrypted" in msg:
                encrypted_data = base64.b64decode(msg["encrypted"])
                decrypted = cipher.decrypt(encrypted_data).decode('utf-8')
                import json
                msg = json.loads(decrypted)
            
            email = msg["email"]
            username = msg["username"]
            pwd_hash = msg["pwd_hash"]
            salt = base64.b64decode(msg["salt"])
            
            # Register user in database
            success, message = self.db.register_user(email, username, salt, pwd_hash)
            
            if success:
                log_event("server", "SUCCESS", f"User registered: {username}")
                send_message(client_sock, ProtocolMessage.response("success", "Registration successful"))
                return True
            else:
                log_event("server", "ERROR", f"Registration failed: {message}")
                send_message(client_sock, ProtocolMessage.response("error", message))
                return False
                
        except Exception as e:
            log_event("server", "ERROR", f"Registration error: {e}")
            send_message(client_sock, ProtocolMessage.response("error", "Registration failed"))
            return False
    
    def handle_login(self, client_sock, msg, cipher):
        """Handle user login"""
        try:
            # Decrypt encrypted data if present
            if "encrypted" in msg:
                encrypted_data = base64.b64decode(msg["encrypted"])
                decrypted = cipher.decrypt(encrypted_data).decode('utf-8')
                import json
                msg = json.loads(decrypted)
            
            email = msg["email"]
            pwd_hash = msg["pwd_hash"]
            
            # Verify credentials
            success, username = self.db.verify_login(email, pwd_hash)
            
            if success:
                log_event("server", "SUCCESS", f"User logged in: {username}")
                send_message(client_sock, ProtocolMessage.response("success", "Login successful", {"username": username}))
                return True
            else:
                log_event("server", "ERROR", "Invalid credentials")
                send_message(client_sock, ProtocolMessage.response("error", "Invalid credentials"))
                return False
                
        except Exception as e:
            log_event("server", "ERROR", f"Login error: {e}")
            send_message(client_sock, ProtocolMessage.response("error", "Login failed"))
            return False
    
    def key_agreement(self, client_sock):
        """
        Key Agreement: DH exchange for session key
        
        Returns:
            bool: True if key agreement successful
        """
        log_event("server", "KEYAGREE", "Starting DH key exchange for session")
        
        # Receive client DH parameters
        msg = receive_message(client_sock)
        if not msg or msg.get("type") != "dh_client":
            return False
        
        # Perform server DH
        dh = DHKeyExchange(p=msg["p"], g=msg["g"])
        dh_response = ProtocolMessage.dh_server(dh.public_key)
        send_message(client_sock, dh_response)
        
        # Compute shared secret and derive session key
        shared_secret = dh.compute_shared_secret(msg["A"])
        self.session_key = DHKeyExchange.derive_aes_key(shared_secret)
        
        log_event("server", "SUCCESS", "Session key established")
        
        # Initialize signer for message authentication
        self.signer = MessageSigner(
            private_key=self.server_key,
            public_key=self.client_cert.public_key()
        )
        
        # Initialize transcript
        peer_fingerprint = PKIManager.get_certificate_fingerprint(self.client_cert)
        self.transcript = TranscriptManager("server", peer_fingerprint)
        
        return True
    
    def chat_session(self, client_sock):
        """Handle encrypted chat session"""
        log_event("server", "CHAT", "Chat session started")
        cipher = AESCipher(self.session_key)
        
        send_message(client_sock, ProtocolMessage.response("success", "Chat session ready"))
        
        print("\n" + "="*60)
        print("SECURE CHAT SESSION ACTIVE")
        print("="*60)
        print("Type your messages (or 'quit' to end session)\n")
        
        while True:
            # Receive message from client
            msg = receive_message(client_sock)
            if not msg:
                break
            
            if msg.get("type") == "msg":
                if not self.handle_incoming_message(msg, cipher):
                    break
            elif msg.get("type") == "quit":
                log_event("server", "CHAT", "Client requested session end")
                break
        
        log_event("server", "CHAT", "Chat session ended")
    
    def handle_incoming_message(self, msg, cipher):
        """Handle incoming encrypted message"""
        seqno = msg["seqno"]
        timestamp = msg["ts"]
        ciphertext_b64 = msg["ct"]
        signature_b64 = msg["sig"]
        
        # Check sequence number (replay protection)
        if seqno <= self.client_seqno:
            log_event("server", "SECURITY", f"REPLAY DETECTED: seqno {seqno}")
            return False
        
        self.client_seqno = seqno
        
        # Verify signature
        if not self.signer.verify_signature(seqno, timestamp, ciphertext_b64, signature_b64):
            log_event("server", "SECURITY", "SIG_FAIL: Invalid signature")
            return False
        
        # Decrypt message
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            
            print(f"\n[Client]: {plaintext}")
            
            # Add to transcript
            self.transcript.add_message(seqno, timestamp, ciphertext_b64, signature_b64, "received")
            
            # Send response
            response_text = input("[Server]: ")
            if response_text.lower() == 'quit':
                return False
            
            self.send_encrypted_message(response_text, cipher)
            
            return True
            
        except Exception as e:
            log_event("server", "ERROR", f"Decryption failed: {e}")
            return False
    
    def send_encrypted_message(self, plaintext, cipher):
        """Send encrypted message to client"""
        # Encrypt message
        ciphertext = cipher.encrypt(plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        # Create signature
        timestamp = int(time.time() * 1000)
        signature_b64 = self.signer.sign_message(self.next_seqno, timestamp, ciphertext_b64)
        
        # Create message
        msg = ProtocolMessage.chat_message(self.next_seqno, timestamp, ciphertext_b64, signature_b64)
        
        # Add to transcript
        self.transcript.add_message(self.next_seqno, timestamp, ciphertext_b64, signature_b64, "sent")
        
        # Send
        send_message(self.socket, msg)
        
        self.next_seqno += 1
    
    def teardown(self, client_sock):
        """Generate and exchange session receipts"""
        log_event("server", "TEARDOWN", "Generating session receipt")
        
        if self.transcript:
            receipt = self.transcript.generate_receipt(self.signer)
            send_message(client_sock, receipt)
            log_event("server", "SUCCESS", "Session receipt sent")

if __name__ == "__main__":
    try:
        server = SecureChatServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
        sys.exit(0)