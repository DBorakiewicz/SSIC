import os
import time
import hashlib
import pyaes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ============================================================
# KONFIGURACJA - zmień rozmiar pliku tutaj
# ============================================================
FILE_SIZE_GB = 1         # rozmiar pliku testowego w GB
CHUNK_SIZE = 1024 * 1024  # 1MB na chunk
KEY_SIZE = 32              # 32 = AES-256, 16 = AES-128, 24 = AES-192

INPUT_FILE  = "test_input.bin"
ENC_PYCRYPTO = "enc_pycrypto.bin"
DEC_PYCRYPTO = "dec_pycrypto.bin"
ENC_PYAES    = "enc_aesniF.bin"
DEC_PYAES    = "dec_aesniF.bin"

# ============================================================
# GENEROWANIE PLIKU TESTOWEGO
# ============================================================
def generate_test_file(path, size_gb):
    size_bytes = size_gb * 1024 ** 3
    print(f"Generowanie pliku testowego ({size_gb} GB)...")
    written = 0
    with open(path, "wb") as f:
        while written < size_bytes:
            chunk = os.urandom(min(CHUNK_SIZE, size_bytes - written))
            f.write(chunk)
            written += len(chunk)
    print(f"  Plik wygenerowany: {path}")

# ============================================================
# SHA-256
# ============================================================
def file_hash(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def verify(original, decrypted, label):
    print(f"  Weryfikacja {label}...", end=" ")
    if file_hash(original) == file_hash(decrypted):
        print("OK - pliki identyczne")
    else:
        print("BLAD - pliki roznia sie!")

# ============================================================
# PYCRYPTODOME - szyfrowanie
# ============================================================
def encrypt_pycryptodome(input_file, output_file, key, aesni=True):
    nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, use_aesni=aesni)
    io_time = 0.0
    enc_time = 0.0
    total_start = time.perf_counter()

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        t = time.perf_counter()
        fout.write(nonce)
        io_time += time.perf_counter() - t

        while chunk := fin.read(CHUNK_SIZE):
            t = time.perf_counter()
            encrypted = cipher.encrypt(chunk)
            enc_time += time.perf_counter() - t

            t = time.perf_counter()
            fout.write(encrypted)
            io_time += time.perf_counter() - t

    total_time = time.perf_counter() - total_start
    return total_time, enc_time, io_time

# ============================================================
# PYCRYPTODOME - deszyfrowanie
# ============================================================
def decrypt_pycryptodome(input_file, output_file, key, aesni=True):
    dec_time = 0.0
    io_time = 0.0
    total_start = time.perf_counter()

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        nonce = fin.read(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, use_aesni=aesni)

        while chunk := fin.read(CHUNK_SIZE):
            t = time.perf_counter()
            decrypted = cipher.decrypt(chunk)
            dec_time += time.perf_counter() - t

            t = time.perf_counter()
            fout.write(decrypted)
            io_time += time.perf_counter() - t

    total_time = time.perf_counter() - total_start
    return total_time, dec_time, io_time

# ============================================================
# WYDRUK WYNIKÓW
# ============================================================
def print_results(label, operation, total, crypto, io, size_bytes):
    size_mb = size_bytes / 1024 ** 2
    print(f"  [{label}] {operation}")
    print(f"    Czas całkowity:       {total:.3f} s")
    print(f"    Czas kryptografii:    {crypto:.3f} s")
    print(f"    Czas I/O:             {io:.3f} s")
    print(f"    Przepustowość całk.:  {size_mb / total:.2f} MB/s")
    print(f"    Przepustowość krypt.: {size_mb / crypto:.2f} MB/s")

# ============================================================
# MAIN
# ============================================================
def main():
    size_bytes = FILE_SIZE_GB * 1024 ** 3
    key = get_random_bytes(KEY_SIZE)

    print("=" * 60)
    print(f"Porównanie pycryptodome AES-NI vs bez AES-NI")
    print(f"Rozmiar pliku: {FILE_SIZE_GB} GB | Klucz: AES-{KEY_SIZE * 8}")
    print("=" * 60)

    # Generuj plik jeśli nie istnieje
    if not os.path.exists(INPUT_FILE):
        generate_test_file(INPUT_FILE, FILE_SIZE_GB)
    else:
        print(f"Plik testowy już istnieje: {INPUT_FILE}")

    print()

    # --- PYCRYPTODOME ---
    print(">>> PYCRYPTODOME (z AES-NI)")
    print("  Szyfrowanie...")
    tot, enc, io = encrypt_pycryptodome(INPUT_FILE, ENC_PYCRYPTO, key)
    print_results("pycryptodome", "Szyfrowanie", tot, enc, io, size_bytes)

    print("  Deszyfrowanie...")
    tot, dec, io = decrypt_pycryptodome(ENC_PYCRYPTO, DEC_PYCRYPTO, key)
    print_results("pycryptodome", "Deszyfrowanie", tot, dec, io, size_bytes)
    verify(INPUT_FILE, DEC_PYCRYPTO, "pycryptodome")

    print()

    # --- PYAES ---
    print(">>> PyCryptoDome (bez AES-NI)")
    print("  Szyfrowanie...")
    tot, enc, io = encrypt_pycryptodome(INPUT_FILE, ENC_PYAES, key, False)
    print_results("pycrptodome (aesni=Flase)", "Szyfrowanie", tot, enc, io, size_bytes)

    print("  Deszyfrowanie...")
    tot, dec, io = decrypt_pycryptodome(ENC_PYAES, DEC_PYAES, key, False)
    print_results("pycryptodome (aesni=False)", "Deszyfrowanie", tot, dec, io, size_bytes)
    verify(INPUT_FILE, DEC_PYAES, "pycrptodome (aesni=False)")

    print()
    print("=" * 60)
    print("Gotowe!")

if __name__ == "__main__":
    main()