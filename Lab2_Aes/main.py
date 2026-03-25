import os.path
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 1024 * 1024
INPUT_FILE = r'file_10gb.bin'
ENC_FILE = r'encrypted_file.bin'
DEC_FILE = r'decrypted_file.bin'

def file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def compare_files(file1, file2):
    """Compare two files and return True if they are identical."""
    hash1 = file_hash(file1)
    hash2 = file_hash(file2)
    return hash1 == hash2

def encrypt_file(input_file, output_file, key, nonce = None):
    if nonce is None:
        nonce = get_random_bytes(8)
    total_start = time.perf_counter()

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    encrypt_time = 0.0

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        fout.write(nonce)
        while chunk := fin.read(CHUNK_SIZE):
            t = time.perf_counter()
            encrypted = cipher.encrypt(chunk)

            encrypt_time += time.perf_counter() - t
            fout.write(encrypted)

    total_time = time.perf_counter() - total_start
    return total_time, encrypt_time

def decrypt_file(input_file, output_file, key):
    total_start = time.perf_counter()

    decrypt_time = 0.0

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        nonce = fin.read(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        while chunk := fin.read(CHUNK_SIZE):
            t = time.perf_counter()
            decrypted = cipher.decrypt(chunk)
            decrypt_time += time.perf_counter() - t
            fout.write(decrypted)

    total_time = time.perf_counter() - total_start
    return total_time, decrypt_time

def main():

    keys = [16, 24, 32]

    size = os.path.getsize(INPUT_FILE)

    for k in keys:
        print(f"Szyfrowanie AES-{k*8}")
        key = get_random_bytes(k)
        tot_t, enc_t = encrypt_file(INPUT_FILE, ENC_FILE, key)
        print(f"Całkowity czas : {tot_t:.3f}s, czas samego szyforwania: {enc_t:.3f}s")
        print(f"Prędkość całej operacji: {size/tot_t/1024**2:.3f} MB/s")
        print(f"Prędkość samego szyfrowania: {size/enc_t/1024**2:.3f} MB/s")
        print()
        print(f"Deszyfrowanie AES-{k*8}")
        tot_t, dec_t = decrypt_file(ENC_FILE, DEC_FILE, key)
        print(f"Całkowity czas : {tot_t:.3f}s, czas samego deszyfrowania: {dec_t:.3f}s")
        print(f"Prędkość całej operacji: {size / tot_t / 1024 ** 2:.3f} MB/s")
        print(f"Prędkość samego deszyfrowania: {size / dec_t / 1024 ** 2:.3f} MB/s")
        print()
        if compare_files(INPUT_FILE, DEC_FILE):
            print("✅ WERYFIKACJA: Pliki identyczne!")
        else:
            print("❌ BŁĄD: Pliki różnią się!")
        print()
        print(f"{100*'='}")

if __name__ == '__main__':
    main()