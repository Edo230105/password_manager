import sqlite3
import json
import csv
import hashlib
import base64
import secrets
import time
import hmac
import struct
import os
import shutil
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import threading
import string
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import socketserver

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "0O1lI"
    
    def generate_password(self, length=12, use_lowercase=True, use_uppercase=True, 
                         use_digits=True, use_symbols=True, exclude_ambiguous=False):
        """Generate a secure password with specified criteria"""
        if length &lt; 4:
            raise ValueError("Password length must be at least 4 characters")
        
        charset = ""
        required_chars = []
        
        if use_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            required_chars.append(secrets.choice(chars))
        
        if use_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            required_chars.append(secrets.choice(chars))
        
        if use_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous)
            charset += chars
            required_chars.append(secrets.choice(chars))
        
        if use_symbols:
            charset += self.symbols
            required_chars.append(secrets.choice(self.symbols))
        
        if not charset:
            raise ValueError("At least one character type must be selected")
        
        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [secrets.choice(charset) for _ in range(remaining_length)]
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)

class WebServerHandler(BaseHTTPRequestHandler):
    def __init__(self, password_manager, *args, **kwargs):
        self.password_manager = password_manager
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Add CORS headers
        self.send_cors_headers()
        
        if path == '/status':
            self.handle_status()
        elif path == '/passwords':
            self.handle_get_passwords()
        elif path.startswith('/mfa/'):
            password_id = path.split('/')[-1]
            self.handle_get_mfa(password_id)
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Add CORS headers
        self.send_cors_headers()
        
        if path == '/generate-password':
            self.handle_generate_password()
        elif path == '/add-password':
            self.handle_add_password()
        else:
            self.send_error(404, "Not Found")
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS"""
        self.send_cors_headers()
        self.end_headers()
    
    def send_cors_headers(self):
        """Send CORS headers"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Content-Type', 'application/json')
    
    def handle_status(self):
        """Handle status check"""
        response = {
            'status': 'connected',
            'version': '1.0.0',
            'authenticated': self.password_manager.cipher_suite is not None
        }
        self.send_json_response(response)
    
    def handle_get_passwords(self):
        """Handle get passwords request"""
        if not self.password_manager.cipher_suite:
            self.send_error(401, "Not authenticated")
            return
        
        try:
            passwords = self.password_manager.get_all_passwords()
            # Remove sensitive data for web transmission
            safe_passwords = []
            for pwd in passwords:
                safe_passwords.append({
                    'id': pwd['id'],
                    'service': pwd['service'],
                    'username': pwd['username'],
                    'password': pwd['password'],
                    'mfa_secret': pwd['mfa_secret'] is not None,  # Only indicate presence
                    'notes': pwd['notes']
                })
            
            response = {'passwords': safe_passwords}
            self.send_json_response(response)
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def handle_get_mfa(self, password_id):
        """Handle get MFA code request"""
        if not self.password_manager.cipher_suite:
            self.send_error(401, "Not authenticated")
            return
        
        try:
            passwords = self.password_manager.get_all_passwords()
            password_entry = next((p for p in passwords if str(p['id']) == password_id), None)
            
            if not password_entry:
                self.send_error(404, "Password not found")
                return
            
            if not password_entry['mfa_secret']:
                self.send_error(404, "No MFA secret for this password")
                return
            
            mfa_code = self.password_manager.generate_totp_code(password_entry['mfa_secret'])
            time_left = 30 - (int(time.time()) % 30)
            
            response = {
                'code': mfa_code,
                'time_left': time_left
            }
            self.send_json_response(response)
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def handle_generate_password(self):
        """Handle password generation request"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8')) if post_data else {}
            
            length = data.get('length', 16)
            use_symbols = data.get('symbols', True)
            
            password = self.password_manager.password_generator.generate_password(
                length=length,
                use_lowercase=True,
                use_uppercase=True,
                use_digits=True,
                use_symbols=use_symbols,
                exclude_ambiguous=True
            )
            
            response = {'password': password}
            self.send_json_response(response)
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.end_headers()
        response = json.dumps(data).encode('utf-8')
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        """Override to reduce logging noise"""
        pass

class WebServer:
    def __init__(self, password_manager, port=8765):
        self.password_manager = password_manager
        self.port = port
        self.server = None
        self.server_thread = None
    
    def start(self):
        """Start the web server"""
        try:
            handler = lambda *args, **kwargs: WebServerHandler(self.password_manager, *args, **kwargs)
            self.server = HTTPServer(('localhost', self.port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            print(f"✓ Web server started on http://localhost:{self.port}")
            return True
        except Exception as e:
            print(f"❌ Failed to start web server: {e}")
            return False
    
    def stop(self):
        """Stop the web server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("✓ Web server stopped")

class EnhancedPasswordManager:
    def __init__(self):
        self.db_file = "passwords.db"
        self.master_key = None
        self.cipher_suite = None
        self.password_generator = PasswordGenerator()
        self.web_server = None
        self.setup_database()
        
    def setup_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                mfa_secret BLOB,
                notes BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create master password table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def derive_key(self, password, salt):
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def set_master_password(self, password):
        """Set or verify master password"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = cursor.fetchone()
        
        if result is None:
            # First time setup
            salt = secrets.token_bytes(32)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            cursor.execute("INSERT INTO master_password (id, password_hash, salt) VALUES (1, ?, ?)",
                         (password_hash.hex(), salt))
            conn.commit()
            self.master_key = self.derive_key(password, salt)
            self.cipher_suite = Fernet(self.master_key)
            conn.close()
            return True
        else:
            # Verify existing password
            stored_hash = bytes.fromhex(result[0])
            salt = result[1]
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            
            if hmac.compare_digest(stored_hash, password_hash):
                self.master_key = self.derive_key(password, salt)
                self.cipher_suite = Fernet(self.master_key)
                conn.close()
                return True
            else:
                conn.close()
                return False
    
    def encrypt_data(self, data):
        """Encrypt data using master key"""
        if self.cipher_suite is None:
            raise ValueError("Master password not set")
        return self.cipher_suite.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using master key"""
        if self.cipher_suite is None:
            raise ValueError("Master password not set")
        return self.cipher_suite.decrypt(encrypted_data).decode()
    
    def generate_totp_code(self, secret):
        """Generate TOTP code from secret"""
        if not secret:
            return None
            
        try:
            # Decode base32 secret
            key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
            
            # Get current time step (30 seconds)
            time_step = int(time.time()) // 30
            
            # Convert to bytes
            time_bytes = struct.pack('>Q', time_step)
            
            # Generate HMAC
            hmac_digest = hmac.new(key, time_bytes, hashlib.sha1).digest()
            
            # Dynamic truncation
            offset = hmac_digest[-1] & 0x0f
            code = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
            code &= 0x7fffffff
            code %= 1000000
            
            return f"{code:06d}"
        except Exception:
            return "Invalid"
    
    def add_password(self, service, username, password, mfa_secret=None, notes=None):
        """Add new password entry"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        encrypted_password = self.encrypt_data(password)
        encrypted_mfa = self.encrypt_data(mfa_secret) if mfa_secret else None
        encrypted_notes = self.encrypt_data(notes) if notes else None
        
        cursor.execute('''
            INSERT INTO passwords (service, username, password, mfa_secret, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (service, username, encrypted_password, encrypted_mfa, encrypted_notes))
        
        conn.commit()
        conn.close()
    
    def get_all_passwords(self):
        """Retrieve all password entries"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, service, username, password, mfa_secret, notes FROM passwords")
        results = cursor.fetchall()
        
        passwords = []
        for row in results:
            entry = {
                'id': row[0],
                'service': row[1],
                'username': row[2],
                'password': self.decrypt_data(row[3]),
                'mfa_secret': self.decrypt_data(row[4]) if row[4] else None,
                'notes': self.decrypt_data(row[5]) if row[5] else None
            }
            passwords.append(entry)
        
        conn.close()
        return passwords
    
    def search_passwords(self, query):
        """Search passwords by service or username"""
        all_passwords = self.get_all_passwords()
        query = query.lower()
        return [p for p in all_passwords if query in p['service'].lower() or query in p['username'].lower()]
    
    def delete_password(self, password_id):
        """Delete password entry"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        conn.commit()
        conn.close()
    
    def start_web_server(self, port=8765):
        """Start the web server for browser extension communication"""
        self.web_server = WebServer(self, port)
        return self.web_server.start()
    
    def stop_web_server(self):
        """Stop the web server"""
        if self.web_server:
            self.web_server.stop()

def main():
    """Main entry point for the application"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--enhanced':
        # Run enhanced version with web server
        from enhanced_password_manager import EnhancedPasswordManagerGUI
        app = EnhancedPasswordManagerGUI()
        app.run()
    else:
        # Run basic version
        from password_manager import PasswordManagerGUI
        app = PasswordManagerGUI()
        app.run()

if __name__ == "__main__":
    main()
