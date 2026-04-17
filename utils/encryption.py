import os
from cryptography.fernet import Fernet

KEY_FILE = "data/secret.key" # Path where the encryption key will be stored

os.makedirs("data", exist_ok=True)
# Ensure the 'data' directory exists
# exist_ok=True prevents error if the directory already exists

# Load or generate encryption key
if os.path.exists(KEY_FILE): # If a key file already exists
    with open(KEY_FILE, "rb") as f:
        KEY = f.read() # Read the existing key as bytes
else: # If the key file does not exist
    KEY = Fernet.generate_key() # Generate a new random key
    with open(KEY_FILE, "wb") as f:
        f.write(KEY) # Save the new key to the file for future use

fernet = Fernet(KEY)

def encrypt_file(file_bytes): # Function to encrypt raw file bytes
    return fernet.encrypt(file_bytes) # Returns encrypted bytes using Fernet symmetric encryption

def decrypt_file(encrypted_bytes): # Function to decrypt previously encrypted bytes
    return fernet.decrypt(encrypted_bytes) # Returns original file bytes after decryption