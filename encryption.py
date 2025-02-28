import os
import base64
import getpass
from cryptography.fernet import Fernet
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Path to Google Service Account JSON file
GOOGLE_CREDENTIALS_PATH = r"D:\python\OneDrive\Desktop\p2\jsonfile.json"

# Function to generate a new encryption key
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a file
def encrypt_file(file_name, key):
    try:
        with open(file_name, 'rb') as f:
            data = f.read()
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        enc_file_name = file_name + ".enc"
        with open(enc_file_name, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"File '{file_name}' encrypted successfully as '{enc_file_name}'!")
        return enc_file_name
    except Exception as e:
        print(f"Encryption failed: {e}")

# Function to decrypt a file
def decrypt_file(file_name, key):
    try:
        with open(file_name, 'rb') as f:
            encrypted_data = f.read()
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        dec_file_name = file_name.replace(".enc", "_decrypted.txt")
        with open(dec_file_name, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"File '{file_name}' decrypted successfully as '{dec_file_name}'!")
        return dec_file_name
    except Exception as e:
        print(f"Decryption failed: {e}")

# Function to upload file to Google Drive
def upload_to_google_drive(file_path):
    try:
        creds = service_account.Credentials.from_service_account_file(GOOGLE_CREDENTIALS_PATH, scopes=["https://www.googleapis.com/auth/drive.file"])
        service = build("drive", "v3", credentials=creds)

        file_metadata = {"name": os.path.basename(file_path)}
        media = MediaFileUpload(file_path, mimetype="application/octet-stream")
        
        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        
        print(f"File uploaded successfully! File ID: {uploaded_file.get('id')}")
        return uploaded_file.get('id')
    except Exception as e:
        print(f"Google Drive upload failed: {e}")

# Function to validate and process the encryption key
def process_key(input_key):
    if not input_key:
        key = generate_key()
        print(f"Generated new encryption key (save this!): {key.decode()}")
    else:
        try:
            key = base64.urlsafe_b64decode(input_key)
            key = base64.urlsafe_b64encode(key)
        except Exception as e:
            print(f"Invalid encryption key! {e}")
            return None
    return key

# Main function
def main():
    choice = input("Do you want to (e)ncrypt or (d)ecrypt a file? ").lower()

    if choice not in ['e', 'd']:
        print("Invalid choice! Please enter 'e' for encrypt or 'd' for decrypt.")
        return

    file_path = input("Enter the path of the file: ").strip().strip('"')

    if not os.path.exists(file_path):
        print("File not found! Please check the file path.")
        return

    key_input = getpass.getpass("Enter encryption key (or press Enter to generate a new one): ").strip()
    key = process_key(key_input)

    if not key:
        print("Encryption process stopped due to an invalid key.")
        return

    if choice == 'e':
        encrypted_file = encrypt_file(file_path, key)

        if encrypted_file:
            upload_choice = input("Do you want to upload the encrypted file to Google Drive? (y/n): ").lower()
            if upload_choice == 'y':
                upload_to_google_drive(encrypted_file)

    elif choice == 'd':
        decrypt_file(file_path, key)

if __name__ == "__main__":
    main()