import os
import base64
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Google Service Account JSON Path
GOOGLE_CREDENTIALS_PATH = "D:\\python\\OneDrive\\Desktop\\p2\\jsonfile.json"

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_name, key):
    try:
        with open(file_name, 'rb') as f:
            data = f.read()
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        enc_file_name = file_name + ".enc"
        
        with open(enc_file_name, 'wb') as f:
            f.write(encrypted_data)
        
        messagebox.showinfo("Success", f"File encrypted successfully! Saved as {enc_file_name}")
        return enc_file_name
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file(file_name, key):
    try:
        with open(file_name, 'rb') as f:
            encrypted_data = f.read()
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        dec_file_name = file_name.replace(".enc", "_decrypted.txt")
        with open(dec_file_name, 'wb') as f:
            f.write(decrypted_data)
        
        messagebox.showinfo("Success", f"File decrypted successfully! Saved as {dec_file_name}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def upload_to_google_drive(file_path):
    try:
        creds = service_account.Credentials.from_service_account_file(
            GOOGLE_CREDENTIALS_PATH, scopes=["https://www.googleapis.com/auth/drive.file"])
        service = build("drive", "v3", credentials=creds)
        
        file_metadata = {"name": os.path.basename(file_path)}
        media = MediaFileUpload(file_path, mimetype="application/octet-stream")
        
        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        messagebox.showinfo("Upload Success", f"File uploaded successfully! File ID: {uploaded_file.get('id')}")
    except Exception as e:
        messagebox.showerror("Upload Failed", f"Google Drive upload failed: {e}")

def browse_file():
    file_path = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, file_path)

def process_action(action):
    file_path = entry_file_path.get().strip()
    key_input = entry_key.get().strip()
    
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found! Check the path.")
        return
    
    if not key_input:
        key = generate_key()
        messagebox.showinfo("Key Generated", f"Generated Key (Save it!): {key.decode()}")
    else:
        try:
            key = base64.urlsafe_b64decode(key_input)
            key = base64.urlsafe_b64encode(key)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid key: {e}")
            return
    
    if action == 'encrypt':
        encrypted_file = encrypt_file(file_path, key)
        if var_upload.get() == 1 and encrypted_file:
            upload_to_google_drive(encrypted_file)
    elif action == 'decrypt':
        decrypt_file(file_path, key)

# GUI Setup
root = tk.Tk()
root.title("File Encryptor & Uploader")
root.geometry("500x400")

# File Selection
tk.Label(root, text="Select File:").pack(pady=5)
entry_file_path = tk.Entry(root, width=50)
entry_file_path.pack(pady=5)
tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

# Encryption Key
tk.Label(root, text="Enter Encryption Key (or leave blank to generate one):").pack(pady=5)
entry_key = tk.Entry(root, width=50, show="*")
entry_key.pack(pady=5)

# Upload Option
var_upload = tk.IntVar()
tk.Checkbutton(root, text="Upload encrypted file to Google Drive", variable=var_upload).pack(pady=5)

# Action Buttons
tk.Button(root, text="Encrypt File", command=lambda: process_action('encrypt')).pack(pady=10)
tk.Button(root, text="Decrypt File", command=lambda: process_action('decrypt')).pack(pady=10)

# Run GUI
root.mainloop()
