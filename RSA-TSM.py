from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
import time

class SecureDocumentTransfer:
    def __init__(self):
        self.sender_keys = self.load_or_generate_keys("sender")
        self.recipient_keys = self.load_or_generate_keys("recipient")
        
    def load_or_generate_keys(self, user_type):
        keys_file = f"{user_type}_keys.pem"
        
        if os.path.exists(keys_file):
            with open(keys_file, "rb") as f:
                key_data = f.read()
                keys = RSA.import_key(key_data)
        else:
            keys = RSA.generate(2048)
            with open(keys_file, "wb") as f:
                f.write(keys.export_key())
                
        return keys
    
    def encrypt_document(self, file_path):
        with open(file_path, "rb") as f:
            document_data = f.read()
        
        aes_key = get_random_bytes(16)  
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        encrypted_document, tag = cipher_aes.encrypt_and_digest(document_data)
        

        recipient_public_key = self.recipient_keys.publickey()
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        document_hash = SHA256.new(document_data)
        signature = pkcs1_15.new(self.sender_keys).sign(document_hash)
        
        package = {
            "encrypted_document": base64.b64encode(encrypted_document).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "original_filename": os.path.basename(file_path)
        }
        
        output_path = file_path + ".encrypted"
        with open(output_path, "w") as f:
            json.dump(package, f)
        
        return output_path
    
    def decrypt_document(self, encrypted_file_path):
        with open(encrypted_file_path, "r") as f:
            package = json.load(f)
        
        encrypted_document = base64.b64decode(package["encrypted_document"])
        tag = base64.b64decode(package["tag"])
        nonce = base64.b64decode(package["nonce"])
        encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
        signature = base64.b64decode(package["signature"])
        original_filename = package["original_filename"]
        
        cipher_rsa = PKCS1_OAEP.new(self.recipient_keys)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        document_data = cipher_aes.decrypt_and_verify(encrypted_document, tag)
        
        document_hash = SHA256.new(document_data)
        try:
            pkcs1_15.new(self.sender_keys.publickey()).verify(document_hash, signature)
            signature_valid = True
        except (ValueError, TypeError):
            signature_valid = False
        
        output_dir = os.path.dirname(encrypted_file_path)
        decrypted_file_path = os.path.join(output_dir, f"decrypted_{original_filename}")
        with open(decrypted_file_path, "wb") as f:
            f.write(document_data)
        
        return decrypted_file_path, signature_valid

class SecureDocumentTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Document Transfer System")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        self.secure_system = SecureDocumentTransfer()
        
        self.setup_ui()
        
    def setup_ui(self):
        self.tab_control = ttk.Notebook(self.root)
        
        self.sender_tab = ttk.Frame(self.tab_control)
        self.recipient_tab = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.sender_tab, text="Sender")
        self.tab_control.add(self.recipient_tab, text="Recipient")
        
        self.tab_control.pack(expand=1, fill="both")
        
        self.setup_sender_tab()
        
        self.setup_recipient_tab()
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def setup_sender_tab(self):
        sender_frame = ttk.LabelFrame(self.sender_tab, text="Encrypt and Send Document")
        sender_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        file_frame = ttk.Frame(sender_frame)
        file_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(file_frame, text="Select Document:").pack(side=tk.LEFT, padx=5)
        
        self.selected_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.selected_file_var, width=40).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(sender_frame, text="Encrypt & Prepare for Sending", 
                  command=self.encrypt_document).pack(pady=10)
        
        log_frame = ttk.LabelFrame(sender_frame, text="Encryption Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.sender_log = tk.Text(log_frame, height=15, width=70)
        scrollbar = ttk.Scrollbar(log_frame, command=self.sender_log.yview)
        self.sender_log.configure(yscrollcommand=scrollbar.set)
        
        self.sender_log.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
    def setup_recipient_tab(self):
        recipient_frame = ttk.LabelFrame(self.recipient_tab, text="Receive and Decrypt Document")
        recipient_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        file_frame = ttk.Frame(recipient_frame)
        file_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(file_frame, text="Select Encrypted File:").pack(side=tk.LEFT, padx=5)
        
        self.encrypted_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.encrypted_file_var, width=40).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_frame, text="Browse", command=self.browse_encrypted_file).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(recipient_frame, text="Decrypt Document", 
                  command=self.decrypt_document).pack(pady=10)
        
        log_frame = ttk.LabelFrame(recipient_frame, text="Decryption Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.recipient_log = tk.Text(log_frame, height=15, width=70)
        scrollbar = ttk.Scrollbar(log_frame, command=self.recipient_log.yview)
        self.recipient_log.configure(yscrollcommand=scrollbar.set)
        
        self.recipient_log.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.selected_file_var.set(file_path)
    
    def browse_encrypted_file(self):
        file_path = filedialog.askopenfilename(title="Select encrypted file", 
                                              filetypes=[("Encrypted Files", "*.encrypted")])
        if file_path:
            self.encrypted_file_var.set(file_path)
    
    def encrypt_document(self):
        file_path = self.selected_file_var.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        self.sender_log.delete(1.0, tk.END)
        self.status_var.set("Encrypting document...")
        
        try:
            self.log_sender("Starting encryption process...")
            self.log_sender(f"Selected file: {os.path.basename(file_path)}")
            self.root.update()
            
            self.log_sender("1. Generating random AES symmetric key...")
            time.sleep(0.5)  
            
            self.log_sender("2. Encrypting document with AES symmetric key...")
            time.sleep(0.5)
            
            self.log_sender("3. Encrypting AES key with recipient's public RSA key...")
            time.sleep(0.5)
            
            self.log_sender("4. Creating digital signature using sender's private key...")
            time.sleep(0.5)
            
            self.log_sender("5. Packaging encrypted document, encrypted key, and signature...")
            time.sleep(0.5)
            
            encrypted_file_path = self.secure_system.encrypt_document(file_path)
            
            self.log_sender(f"6. Encryption complete! File saved as: {encrypted_file_path}")
            self.log_sender("\nThe encrypted file can now be safely transferred to the recipient.")
            
            messagebox.showinfo("Success", "Document encrypted successfully!")
            self.status_var.set("Document encrypted successfully")
            
        except Exception as e:
            self.log_sender(f"Error during encryption: {str(e)}")
            messagebox.showerror("Error", f"Failed to encrypt document: {str(e)}")
            self.status_var.set("Encryption failed")
    
    def decrypt_document(self):
        encrypted_file_path = self.encrypted_file_var.get()
        if not encrypted_file_path:
            messagebox.showerror("Error", "Please select an encrypted file first")
            return
        
        self.recipient_log.delete(1.0, tk.END)
        self.status_var.set("Decrypting document...")
        
        try:
            self.log_recipient("Starting decryption process...")
            self.log_recipient(f"Selected encrypted file: {os.path.basename(encrypted_file_path)}")
            self.root.update()
            
            self.log_recipient("1. Extracting encrypted components from package...")
            time.sleep(0.5)  
            
            self.log_recipient("2. Decrypting AES key using recipient's private RSA key...")
            time.sleep(0.5)
            
            self.log_recipient("3. Decrypting document using AES key...")
            time.sleep(0.5)
            
            self.log_recipient("4. Verifying digital signature using sender's public key...")
            time.sleep(0.5)
            
            decrypted_file_path, signature_valid = self.secure_system.decrypt_document(encrypted_file_path)
            
            if signature_valid:
                self.log_recipient("✓ Digital signature verified successfully! Document integrity confirmed.")
            else:
                self.log_recipient("⚠ WARNING: Digital signature verification FAILED! Document may be tampered.")
                
            self.log_recipient(f"5. Decryption complete! File saved as: {decrypted_file_path}")
            
            messagebox.showinfo("Success", f"Document decrypted successfully! Signature valid: {signature_valid}")
            self.status_var.set("Document decrypted successfully")
            
        except Exception as e:
            self.log_recipient(f"Error during decryption: {str(e)}")
            messagebox.showerror("Error", f"Failed to decrypt document: {str(e)}")
            self.status_var.set("Decryption failed")
    
    def log_sender(self, message):
        self.sender_log.insert(tk.END, message + "\n")
        self.sender_log.see(tk.END)
        self.root.update()
    
    def log_recipient(self, message):
        self.recipient_log.insert(tk.END, message + "\n")
        self.recipient_log.see(tk.END)
        self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureDocumentTransferGUI(root)
    root.mainloop()
