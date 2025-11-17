from app.common.utils import sha256_hex  # Assume this is implemented in Step 9
from app.crypto.sign import sign  # Assume this is implemented in Step 8
import base64

class Transcript:
    def __init__(self, file_path):
        self.file = open(file_path, "a")
        self.lines = []
    
    def append(self, seqno, ts, ct, sig, peer_cert_fingerprint):
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_cert_fingerprint}\n"
        self.file.write(line)
        self.lines.append(line.encode())
    
    def compute_hash(self):
        return sha256_hex(b"".join(self.lines))
    
    def generate_receipt(self, first_seq, last_seq, private_key):
        thash = self.compute_hash()
        sig = sign(thash.encode(), private_key)
        return {
            "type": "receipt",
            "peer": "client" if "client" in self.file.name else "server",
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": thash,
            "sig": base64.b64encode(sig).decode()
        }
    
    def close(self):
        self.file.close()

# Example usage (for testing)
if __name__ == "__main__":
    t = Transcript("test_transcript.txt")
    t.append(1, 1637040000000, "encrypted_msg", "sig_base64", "cert_fp")
    print(t.generate_receipt(1, 1, None))  # Replace None with actual private_key for real use
    t.close()