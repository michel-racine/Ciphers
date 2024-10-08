# Name:		encryptor_AES-GCM-256.py
# Purpose:	This program provides and encryptor and decryptor for AES-256 cipher in GCM mode
#		because I had problem in bash with OpenSSL 3.3.2
# Author:	Michael Root using ChatGPT
# Date:		2024.10.07
#

from Crypto.Cipher import AES
import os
import sys
import json

# AES-256-GCM Encryption
def encrypt_AES_GCM(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)  # Create new AES cipher in GCM mode
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Encrypt plaintext
    return ciphertext, cipher.nonce, tag  # Return ciphertext, nonce, tag

# AES-256-GCM Decryption
def decrypt_AES_GCM(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Create new AES cipher for decryption
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify tag

# Function to save key, nonce, and tag to JSON file
def save_key_metadata(key_file, key, nonce, tag):
    metadata = {
        'key': key.hex(),
        'nonce': nonce.hex(),
        'tag': tag.hex()
    }
    with open(key_file, 'w') as f:
        json.dump(metadata, f)

# Function to load key, nonce, and tag from JSON file
def load_key_metadata(key_file):
    with open(key_file, 'r') as f:
        metadata = json.load(f)
    key = bytes.fromhex(metadata['key'])
    nonce = bytes.fromhex(metadata['nonce'])
    tag = bytes.fromhex(metadata['tag'])
    return key, nonce, tag

# Main program
def main():
    mode = input("Choose mode (encrypt/decrypt): ").strip().lower()

    if mode == 'encrypt':
        input_file = input("File to encrypt: ")
        output_file = input("Output file: ")
        key_file = output_file + ".key"  # Key saved with .key extension

        # Read plaintext from input file
        try:
            with open(input_file, 'rb') as f:
                plaintext = f.read()
        except FileNotFoundError:
            print(f"Error: The file '{input_file}' was not found.")
            sys.exit(1)

        # Generate random 256-bit key
        key = os.urandom(32)

        # Encrypt the plaintext
        ciphertext, nonce, tag = encrypt_AES_GCM(plaintext, key)

        # Save encrypted data to output file
        with open(output_file, 'wb') as f:
            f.write(ciphertext)

        # Save key, nonce, and tag to key file
        save_key_metadata(key_file, key, nonce, tag)

        print(f"[ƒ] Encryption complete. Encrypted data saved to '{output_file}' and metadata to '{key_file}'.")

    elif mode == 'decrypt':
        input_file = input( "File to decrypt: ")
        output_file = input("Output file:     ")
        key_file = input(   "Key file:        ")

        # Read ciphertext from input file
        try:
            with open(input_file, 'rb') as g:
                ciphertext = g.read()
        except FileNotFoundError:
            print(f"Error: File '{input_file}' not found.")
            sys.exit(1)

        # Load key, nonce, and tag from key file
        try:
            key, nonce, tag = load_key_metadata(key_file)
        except FileNotFoundError:
            print(f"Error: Key file '{key_file}' not found.")
            sys.exit(1)

        # Decrypt the ciphertext
        try:
            decrypted_message = decrypt_AES_GCM(ciphertext, key, nonce, tag)
            # Save decrypted message to output file
            with open(output_file, 'wb') as f:  # Corrected 'rb' to 'wb'
                f.write(decrypted_message)  # No need to decode here since it's in bytes
        except ValueError:
            print("Decryption failed: The tag does not match. The ciphertext may be corrupted.")
    else:
        print("Invalid mode. Please choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()

