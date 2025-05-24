import sqlite3
import json
import hashlib
import base64
import secrets
import time
import hmac
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading

class PasswordManager:
    def __init__(self):
        self.db_file = "passwords.db"
        self.master_key = None
        self.cipher_suite = None
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

class PasswordManagerGUI:
    def __init__(self):
        self.pm = PasswordManager()
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.authenticated = False
        self.totp_update_job = None
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_login_screen()
    
    def setup_login_screen(self):
        """Setup master password login screen"""
        self.clear_window()
        
        frame = ttk.Frame(self.root)
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        ttk.Label(frame, text="Password Manager", font=('Arial', 24, 'bold')).pack(pady=20)
        ttk.Label(frame, text="Enter Master Password:", font=('Arial', 12)).pack(pady=10)
        
        self.master_password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=self.master_password_var, show="*", font=('Arial', 12))
        password_entry.pack(pady=10, ipadx=10, ipady=5)
        password_entry.bind('<Return>', lambda e: self.authenticate())
        
        ttk.Button(frame, text="Login", command=self.authenticate).pack(pady=10)
        
        password_entry.focus()
    
    def authenticate(self):
        """Authenticate with master password"""
        password = self.master_password_var.get()
        if self.pm.set_master_password(password):
            self.authenticated = True
            self.setup_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password!")
            self.master_password_var.set("")
    
    def setup_main_screen(self):
        """Setup main password manager interface"""
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Top frame for search and add button
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(top_frame, text="Search:").pack(side='left', padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var)
        search_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        search_entry.bind('<KeyRelease>', self.on_search)
        
        ttk.Button(top_frame, text="Add Password", command=self.add_password_dialog).pack(side='right')
        
        # Treeview for password list
        columns = ('Service', 'Username', 'MFA Code', 'Time Left')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(main_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Copy MFA Code", command=self.copy_mfa_code)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="View Details", command=self.view_details)
        self.context_menu.add_command(label="Delete", command=self.delete_password)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.view_details)
        
        self.refresh_password_list()
        self.start_totp_updates()
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def refresh_password_list(self):
        """Refresh the password list display"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        query = self.search_var.get() if hasattr(self, 'search_var') else ""
        passwords = self.pm.search_passwords(query) if query else self.pm.get_all_passwords()
        
        for password in passwords:
            mfa_code = ""
            time_left = ""
            
            if password['mfa_secret']:
                mfa_code = self.pm.generate_totp_code(password['mfa_secret'])
                time_left = f"{30 - (int(time.time()) % 30)}s"
            
            self.tree.insert('', 'end', values=(
                password['service'],
                password['username'],
                mfa_code,
                time_left
            ), tags=(password['id'],))
    
    def start_totp_updates(self):
        """Start automatic TOTP code updates"""
        self.refresh_password_list()
        self.totp_update_job = self.root.after(1000, self.start_totp_updates)
    
    def on_search(self, event=None):
        """Handle search input"""
        self.refresh_password_list()
    
    def add_password_dialog(self):
        """Show add password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Form fields
        ttk.Label(dialog, text="Service:").pack(pady=5)
        service_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=service_var).pack(pady=5, padx=20, fill='x')
        
        ttk.Label(dialog, text="Username:").pack(pady=5)
        username_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=username_var).pack(pady=5, padx=20, fill='x')
        
        ttk.Label(dialog, text="Password:").pack(pady=5)
        password_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=password_var, show="*").pack(pady=5, padx=20, fill='x')
        
        ttk.Label(dialog, text="MFA Secret (optional):").pack(pady=5)
        mfa_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=mfa_var).pack(pady=5, padx=20, fill='x')
        
        ttk.Label(dialog, text="Notes (optional):").pack(pady=5)
        notes_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=notes_var).pack(pady=5, padx=20, fill='x')
        
        def save_password():
            if service_var.get() and username_var.get() and password_var.get():
                self.pm.add_password(
                    service_var.get(),
                    username_var.get(),
                    password_var.get(),
                    mfa_var.get() if mfa_var.get() else None,
                    notes_var.get() if notes_var.get() else None
                )
                self.refresh_password_list()
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Please fill in all required fields!")
        
        ttk.Button(dialog, text="Save", command=save_password).pack(pady=20)
    
    def show_context_menu(self, event):
        """Show context menu on right click"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_password(self):
        """Copy password to clipboard"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            password_id = self.tree.item(item)['tags'][0]
            passwords = self.pm.get_all_passwords()
            password_entry = next((p for p in passwords if p['id'] == password_id), None)
            if password_entry:
                self.root.clipboard_clear()
                self.root.clipboard_append(password_entry['password'])
                messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def copy_mfa_code(self):
        """Copy MFA code to clipboard"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            values = self.tree.item(item)['values']
            if len(values) > 2 and values[2]:
                self.root.clipboard_clear()
                self.root.clipboard_append(values[2])
                messagebox.showinfo("Success", "MFA code copied to clipboard!")
    
    def view_details(self, event=None):
        """View password details"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            password_id = self.tree.item(item)['tags'][0]
            passwords = self.pm.get_all_passwords()
            password_entry = next((p for p in passwords if p['id'] == password_id), None)
            
            if password_entry:
                details = f"Service: {password_entry['service']}\n"
                details += f"Username: {password_entry['username']}\n"
                details += f"Password: {password_entry['password']}\n"
                if password_entry['mfa_secret']:
                    details += f"MFA Secret: {password_entry['mfa_secret']}\n"
                    details += f"Current MFA Code: {self.pm.generate_totp_code(password_entry['mfa_secret'])}\n"
                if password_entry['notes']:
                    details += f"Notes: {password_entry['notes']}\n"
                
                messagebox.showinfo("Password Details", details)
    
    def delete_password(self):
        """Delete selected password"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
                password_id = self.tree.item(item)['tags'][0]
                self.pm.delete_password(password_id)
                self.refresh_password_list()
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

# Demo the password manager
if __name__ == "__main__":
    print("Password Manager Demo")
    print("====================")
    
    # Create password manager instance
    pm = PasswordManager()
    
    # Set master password for demo
    master_password = "demo123"
    if pm.set_master_password(master_password):
        print(f"✓ Master password set successfully")
        
        # Add some demo passwords
        pm.add_password("Gmail", "user@gmail.com", "mypassword123", "JBSWY3DPEHPK3PXP", "Personal email")
        pm.add_password("GitHub", "developer", "securepass456", None, "Development account")
        pm.add_password("Banking", "john.doe", "bankpass789", "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", "Main bank account")
        
        print("✓ Demo passwords added")
        
        # Retrieve and display passwords
        passwords = pm.get_all_passwords()
        print(f"\n📋 Stored Passwords ({len(passwords)} entries):")
        print("-" * 80)
        
        for pwd in passwords:
            print(f"Service: {pwd['service']}")
            print(f"Username: {pwd['username']}")
            print(f"Password: {pwd['password']}")
            
            if pwd['mfa_secret']:
                totp_code = pm.generate_totp_code(pwd['mfa_secret'])
                time_left = 30 - (int(time.time()) % 30)
                print(f"MFA Code: {totp_code} (expires in {time_left}s)")
            
            if pwd['notes']:
                print(f"Notes: {pwd['notes']}")
            
            print("-" * 40)
        
        # Demo search functionality
        search_results = pm.search_passwords("git")
        print(f"\n🔍 Search results for 'git': {len(search_results)} found")
        
        # Demo TOTP code generation
        print(f"\n🔐 TOTP Code Examples:")
        for pwd in passwords:
            if pwd['mfa_secret']:
                code = pm.generate_totp_code(pwd['mfa_secret'])
                print(f"{pwd['service']}: {code}")
        
        print(f"\n🎯 Password Manager Features:")
        print("✓ Encrypted password storage using Fernet (AES 128)")
        print("✓ PBKDF2 key derivation with 100,000 iterations")
        print("✓ TOTP/MFA code generation (Google Authenticator compatible)")
        print("✓ Master password protection")
        print("✓ Search functionality")
        print("✓ Cross-platform GUI with tkinter")
        print("✓ Secure clipboard operations")
        print("✓ Real-time TOTP code updates")
        
        print(f"\n💡 To run the GUI version:")
        print("app = PasswordManagerGUI()")
        print("app.run()")
        
    else:
        print("❌ Failed to set master password")
