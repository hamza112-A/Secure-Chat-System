#!/usr/bin/env python3
"""
Setup script to verify and create all required files
"""

import os
import sys

def create_file_structure():
    """Create the required directory structure"""
    
    directories = [
        "app",
        "app/common",
        "app/crypto",
        "scripts",
        "storage",
        "tests",
        "tests/manual",
        "certs",
        "transcripts"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"[✓] Created/verified directory: {directory}")
    
    # Create __init__.py files
    init_files = [
        "app/__init__.py",
        "app/common/__init__.py",
        "app/crypto/__init__.py",
        "storage/__init__.py"
    ]
    
    for init_file in init_files:
        if not os.path.exists(init_file):
            with open(init_file, "w") as f:
                f.write('"""Package initialization"""\n')
            print(f"[✓] Created: {init_file}")

def check_existing_files():
    """Check which files already exist"""
    
    required_files = {
        "app/crypto/aes.py": "AES encryption module",
        "app/crypto/dh.py": "Diffie-Hellman module",
        "app/crypto/pki.py": "PKI module",
        "app/crypto/sign.py": "RSA signature module",
        "app/common/protocol.py": "Protocol module",
        "app/common/utils.py": "Utilities module",
        "storage/db.py": "Database module",
        "app/server.py": "Server application",
        "app/client.py": "Client application",
        "scripts/gen_ca.py": "CA generator",
        "scripts/gen_cert.py": "Certificate generator"
    }
    
    print("\n" + "="*60)
    print("Checking required files:")
    print("="*60)
    
    missing_files = []
    for file_path, description in required_files.items():
        if os.path.exists(file_path):
            # Check if file has content
            size = os.path.getsize(file_path)
            if size > 100:  # At least 100 bytes
                print(f"[✓] {file_path}: {description} ({size} bytes)")
            else:
                print(f"[!] {file_path}: EXISTS BUT EMPTY/SMALL ({size} bytes)")
                missing_files.append((file_path, description))
        else:
            print(f"[✗] {file_path}: MISSING - {description}")
            missing_files.append((file_path, description))
    
    print("="*60)
    
    if missing_files:
        print(f"\n[!] Found {len(missing_files)} files that need content:")
        for file_path, description in missing_files:
            print(f"    - {file_path}")
        return False
    else:
        print("\n[✓] All required files exist with content!")
        return True

def show_next_steps():
    """Show next steps for the user"""
    
    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("="*60)
    
    print("""
I need to provide you with the actual file contents. Here's what to do:

1. I'll provide each file's content in separate code blocks
2. Copy each content and save it to the correct file path
3. After copying all files, run: python storage/db.py
4. Then try: python app/server.py

Let me know when you're ready, and I'll provide the files one by one.
OR, tell me which specific files are missing/empty and I'll provide them first.
""")

if __name__ == "__main__":
    print("SecureChat Setup Verification")
    print("="*60)
    
    create_file_structure()
    all_good = check_existing_files()
    
    if not all_good:
        show_next_steps()
    else:
        print("\n[✓] Setup complete! You can now run:")
        print("    python app/server.py")
        print("    python app/client.py")