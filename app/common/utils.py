
import socket
import json
import struct

def send_message(sock, message_dict):
    """Send a message over socket with length prefix"""
    message_json = json.dumps(message_dict)
    message_bytes = message_json.encode('utf-8')
    length = struct.pack('>I', len(message_bytes))
    sock.sendall(length + message_bytes)

def receive_message(sock):
    """Receive a message from socket with length prefix"""
    length_bytes = receive_exact(sock, 4)
    if not length_bytes:
        return None
    message_length = struct.unpack('>I', length_bytes)[0]
    message_bytes = receive_exact(sock, message_length)
    if not message_bytes:
        return None
    message_dict = json.loads(message_bytes.decode('utf-8'))
    return message_dict

def receive_exact(sock, num_bytes):
    """Receive exact number of bytes from socket"""
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def print_certificate_info(cert):
    """Print certificate information"""
    from cryptography.x509.oid import NameOID
    
    print("\\n" + "="*60)
    print("Certificate Information")
    print("="*60)
    
    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    print(f"Subject CN:      {subject_cn[0].value if subject_cn else 'N/A'}")
    print(f"Subject Org:     {subject_org[0].value if subject_org else 'N/A'}")
    
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    print(f"Issuer CN:       {issuer_cn[0].value if issuer_cn else 'N/A'}")
    
    print(f"Not Before:      {cert.not_valid_before_utc}")
    print(f"Not After:       {cert.not_valid_after_utc}")
    print(f"Serial Number:   {cert.serial_number}")
    print("="*60 + "\\n")

def log_event(role, event_type, message):
    """Log an event with timestamp"""
    import time
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = f"[{timestamp}] [{role.upper()}] [{event_type}]"
    print(f"{prefix} {message}")