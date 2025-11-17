# SecureChat - Encrypted Chat System

A console-based secure chat system implementing end-to-end encryption with mutual authentication, demonstrating Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR).

## 🔗 Repository
[Your GitHub Fork URL Here]

## ✨ Features

- **PKI Infrastructure**: Self-signed CA with certificate-based mutual authentication
- **Secure Key Exchange**: Diffie-Hellman key agreement for session keys
- **Encrypted Communication**: AES-128 encryption with PKCS#7 padding
- **Message Authentication**: RSA digital signatures over SHA-256 digests
- **Replay Protection**: Sequence number validation
- **Non-Repudiation**: Signed session transcripts and receipts
- **Secure Credential Storage**: Salted SHA-256 password hashing in MySQL

## 📋 Requirements

- Python 3.8+
- MySQL 8.0+
- Docker (for MySQL container)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone [your-repo-url]
cd securechat-skeleton
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start MySQL Database

```bash
docker run -d \
  --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your database credentials
```

### 5. Generate PKI

```bash
# Generate CA
python scripts/gen_ca.py

# Generate server and client certificates
python scripts/gen_cert.py
```

### 6. Initialize Database

```bash
python storage/db.py
```

## 🎮 Usage

### Start Server

```bash
python server.py
```

Server will start on `localhost:9999`

### Start Client

In a separate terminal:

```bash
python client.py
```

### Workflow

1. **Certificate Exchange**: Client and server exchange and validate X.509 certificates
2. **Authentication**: 
   - Choose Register (R) for new users
   - Choose Login (L) for existing users
3. **Key Agreement**: Automatic Diffie-Hellman exchange establishes session key
4. **Secure Chat**: Send encrypted messages (type 'quit' to end)
5. **Session Receipt**: Non-repudiation receipts generated automatically

## 📁 Project Structure

```
securechat-skeleton/
├── app/
│   ├── common/
│   │   ├── protocol.py      # Protocol message formatting
│   │   └── utils.py         # Utility functions
│   └── crypto/
│       ├── aes.py           # AES-128 encryption
│       ├── dh.py            # Diffie-Hellman key exchange
│       ├── pki.py           # Certificate operations
│       └── sign.py          # RSA digital signatures
├── storage/
│   ├── db.py                # Database operations
│   └── schema.sql           # Database schema
├── scripts/
│   ├── gen_ca.py            # CA generation
│   └── gen_cert.py          # Certificate generation
├── certs/                   # Certificates (not in VCS)
├── transcripts/             # Session transcripts (not in VCS)
├── server.py                # Chat server
├── client.py                # Chat client
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔐 Security Features

### 1. PKI and Certificate Validation
- Self-signed root CA
- X.509 certificates for server and client
- Mutual certificate validation
- Expiry and signature chain verification

### 2. Secure Authentication
- Salted SHA-256 password hashing
- 16-byte random salt per user
- No plaintext credentials in transit
- MySQL storage with proper indexing

### 3. Key Agreement
- Diffie-Hellman exchange (2048-bit)
- Session key derivation: `K = Trunc_16(SHA256(K_s))`
- Unique key per session

### 4. Encrypted Communication
- AES-128 in CBC mode
- PKCS#7 padding
- Per-message digital signatures
- SHA-256 digest over `seqno || timestamp || ciphertext`

### 5. Non-Repudiation
- Append-only session transcripts
- Signed transcript hashes
- Session receipts with RSA signatures
- Offline verification support

## 🧪 Testing

### Test Certificate Validation

```bash
# View certificate details
openssl x509 -in certs/server-cert.pem -text -noout

# Run validation tests
python tests/test_cert_validation.py
```

### Test with Wireshark

1. Start Wireshark and capture on loopback interface
2. Apply filter: `tcp.port == 9999`
3. Start server and client
4. Observe encrypted payloads (no plaintext visible)

### Test Security Features

**Invalid Certificate Test:**
- Use expired/self-signed cert → Server rejects with `BAD_CERT`

**Tampering Test:**
- Modify ciphertext in transit → Signature verification fails → `SIG_FAIL`

**Replay Test:**
- Resend old message → Sequence number check fails → `REPLAY`

## 📊 Sample Input/Output

### Registration
```
(R)egister or (L)ogin? R

--- Registration ---
Email: alice@example.com
Username: alice
Password: ********

[✓] Registration successful
```

### Login
```
(R)egister or (L)ogin? L

--- Login ---
Email: alice@example.com
Password: ********

[✓] Login successful
```

### Chat Session
```
SECURE CHAT SESSION ACTIVE
Type your messages (or 'quit' to end session)

[alice]: Hello, secure world!
[Server]: Message received securely!

[alice]: quit
```

## 📝 Database Schema

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔍 Transcript Format

```
seqno|timestamp|ciphertext|signature|peer_fingerprint|direction
1|1699876543210|aGVsbG8gd29ybGQ=|c2lnbmF0dXJl...|abc123...|sent
```

## 📄 License

This project is for educational purposes as part of Information Security coursework at FAST-NUCES.

## 👥 Author

[Your Name] - [Roll Number]

## 🙏 Acknowledgments

- FAST-NUCES Information Security Course
- SEED Security Labs for PKI concepts
- Python Cryptography Library Documentation