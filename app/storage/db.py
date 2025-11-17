#!/usr/bin/env python3
"""
Database setup and operations for SecureChat
Handles user registration and credential storage
"""

import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseManager:
    """Manages database connections and user operations"""
    
    def __init__(self):
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'database': os.getenv('DB_NAME', 'securechat'),
            'user': os.getenv('DB_USER', 'scuser'),
            'password': os.getenv('DB_PASSWORD', 'scpass')
        }
    
    def get_connection(self):
        """Create and return a database connection"""
        return mysql.connector.connect(**self.config)
    
    def init_schema(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    username VARCHAR(255) NOT NULL UNIQUE,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email),
                    INDEX idx_username (username)
                )
            """)
            
            conn.commit()
            print("[✓] Database schema initialized successfully")
            
        except mysql.connector.Error as err:
            print(f"[!] Database error: {err}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    
    def register_user(self, email, username, salt, pwd_hash):
        """
        Register a new user
        
        Args:
            email: User email
            username: Username
            salt: 16-byte random salt (bytes)
            pwd_hash: Hex-encoded SHA256(salt||password)
        
        Returns:
            tuple: (success: bool, message: str)
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Check if user already exists
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE email = %s OR username = %s",
                (email, username)
            )
            
            if cursor.fetchone()[0] > 0:
                return False, "User already exists"
            
            # Insert new user
            cursor.execute(
                """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (email, username, salt, pwd_hash)
            )
            
            conn.commit()
            return True, "Registration successful"
            
        except mysql.connector.Error as err:
            print(f"[!] Database error: {err}")
            conn.rollback()
            return False, f"Database error: {err}"
        finally:
            cursor.close()
            conn.close()
    
    def verify_login(self, email, pwd_hash):
        """
        Verify user login credentials
        
        Args:
            email: User email
            pwd_hash: Hex-encoded SHA256(salt||password) to verify
        
        Returns:
            tuple: (success: bool, username: str or None)
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT username, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            
            result = cursor.fetchone()
            if not result:
                return False, None
            
            username, stored_hash = result
            
            # Constant-time comparison
            if self._constant_time_compare(pwd_hash, stored_hash):
                return True, username
            else:
                return False, None
                
        except mysql.connector.Error as err:
            print(f"[!] Database error: {err}")
            return False, None
        finally:
            cursor.close()
            conn.close()
    
    def get_user_salt(self, email):
        """
        Get salt for a user
        
        Args:
            email: User email
        
        Returns:
            bytes or None: Salt if user exists, None otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT salt FROM users WHERE email = %s",
                (email,)
            )
            
            result = cursor.fetchone()
            return result[0] if result else None
            
        except mysql.connector.Error as err:
            print(f"[!] Database error: {err}")
            return None
        finally:
            cursor.close()
            conn.close()
    
    @staticmethod
    def _constant_time_compare(a, b):
        """Constant-time string comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y) if isinstance(x, str) else x ^ y
        
        return result == 0

# Initialize schema on import (for convenience)
if __name__ == "__main__":
    db = DatabaseManager()
    db.init_schema()