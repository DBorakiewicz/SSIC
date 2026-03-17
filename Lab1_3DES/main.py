import time
import hashlib
import os

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK_SIZE = 1024 * 1024 * 4  # 4 MB
INPUT_FILE = 'testfile.txt'
ENCRYPTED_FILE = 'encrypted_file.bin'
DECRYPTED_FILE = 'decrypted_file.txt'


def file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()



def encrypt_file(input_file, output_file, key, iv):
    """Encrypt a file using Triple DES."""
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    t0 = time.time()
    with open(input_file, 'rb') as in_f, open(output_file, 'wb') as out_f:
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = cipher.encrypt(chunk)
            out_f.write(encrypted_chunk)
    t1 = time.time()
    print(f"Encryption time: {t1 - t0:.3f} seconds")
    print(f"Encryption speed: {os.path.getsize(input_file) / (t1 - t0) / 1024**2:.3f} MB/s")
    return

def cryptography_encrypt_file(input_file, output_file, key, iv):
    """Encrypt a file using Triple DES with the cryptography library."""
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()
    t0 = time.time()
    with open(input_file, 'rb') as in_f, open(output_file, 'wb') as out_f:
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            out_f.write(encrypted_chunk)
        out_f.write(encryptor.finalize())

    t1 = time.time()
    print(f"Cryptography library encryption time: {t1 - t0:.3f} seconds")
    print(f"Cryptography library encryption speed: {os.path.getsize(input_file) / (t1 - t0) / 1024**2:.3f} MB/s")
    return

def decrypt_file(input_file, output_file, key, iv):
    """Decrypt a file using Triple DES."""
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    t0 = time.time()
    with open(input_file, 'rb') as in_f, open(output_file, 'wb') as out_f:
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
            decrypted_chunk = cipher.decrypt(chunk)
            out_f.write(decrypted_chunk)
    t1 = time.time()
    print(f"Decryption time: {t1 - t0:.2f} seconds")
    print(f"Decryption speed: {os.path.getsize(input_file) / (t1 - t0) / 1024**2:.3f} MB/s")
    return

def cryptography_decrypt_file(input_file, output_file, key, iv):
    """Decrypt a file using Triple DES with the cryptography library."""
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()
    t0 = time.time()
    with open(input_file, 'rb') as in_f, open(output_file, 'wb') as out_f:
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
            decrypted_chunk = decryptor.update(chunk)
            out_f.write(decrypted_chunk)
        out_f.write(decryptor.finalize())
    t1 = time.time()
    print(f"Cryptography library decryption time: {t1 - t0:.3f} seconds")
    print(f"Cryptography library decryption speed: {os.path.getsize(input_file) / (t1 - t0) / 1024**2:.3f} MB/s")
    return

def compare_files(file1, file2):
    """Compare two files and return True if they are identical."""
    hash1 = file_hash(file1)
    hash2 = file_hash(file2)
    return hash1 == hash2

def main():
    # Generate a random key and IV for Triple DES
    print("Generating random key")
    key = get_random_bytes(24)  # Triple DES key must be 24 bytes
    print("Generating random iv")
    iv = get_random_bytes(8)    # Triple DES block size is 8 bytes

    # Encrypt the file
    print("Encrypting file")
    encrypt_file(INPUT_FILE, ENCRYPTED_FILE, key, iv)

    # Decrypt the file
    print("Decrypting file")
    decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, key, iv)

    # Verify that the original and decrypted files are identical
    print("Comparing files")
    if compare_files(INPUT_FILE, DECRYPTED_FILE):
        print("Success: The original and decrypted files are identical.")
    else:
        print("Error: The original and decrypted files differ.")

    print("Encrypting file with cryptography library")
    cryptography_encrypt_file(INPUT_FILE, ENCRYPTED_FILE, key, iv)
    print("Decrypting file with cryptography library")
    cryptography_decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, key, iv)

    print("Comparing file with cryptography library")
    if compare_files(INPUT_FILE, DECRYPTED_FILE):
        print("Success: The original and decrypted files are identical.")
    else:
        print("Error: The original and decrypted files differ.")

if __name__ == "__main__":
    main()