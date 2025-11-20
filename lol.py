import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
PIN_TO_ENCRYPT = "Chef mc"
PASSWORD = "MySecure" # Your 8-letter string
password_bytes = PASSWORD.encode('utf-8')
pin_bytes = PIN_TO_ENCRYPT.encode('utf-8')

# --- 1. Derive Key ---
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    backend=default_backend()
)
key = kdf.derive(password_bytes)

# --- 2. Encrypt with AES-GCM (CORRECTED) ---
aesgcm = AESGCM(key)
iv = os.urandom(12) # GCM standard nonce size is 12 bytes

# The .encrypt() method returns *both* the ciphertext and the 16-byte auth tag
# concatenated at the end.
combined_data = aesgcm.encrypt(iv, pin_bytes, None)

# We must split them so Node.js can use the tag separately
# The authentication tag is *always* the last 16 bytes
auth_tag = combined_data[-16:]
ciphertext = combined_data[:-16]

# --- 3. Pack for Transport ---
# Pack in the same order Node.js expects: salt + iv + auth_tag + ciphertext
message_to_send = salt + iv + auth_tag + ciphertext
b64_message = base64.b64encode(message_to_send)

print(f"Original PIN: {PIN_TO_ENCRYPT}")
print(f"Password: {PASSWORD}\n")
print(f"--- Python (Encrypt) ---")
print(f"This is the single string to send to Node.js:\n{b64_message.decode('utf-8')}")