#!/usr/bin/env python3
"""
Generowanie pliku zer i szyfrowanie AES / 3DES w trybach ECB i CTR.

NIST SP 800-22 wymaga:
  - n = 1 000 000 bitów na bitstream
  - m = 1 000 bitstreamów
  - razem: 1 000 000 000 bitów = 125 000 000 bajtów

125 000 000 jest podzielne przez 16 (blok AES) i przez 8 (blok 3DES),
więc padding NIE jest potrzebny.

Wymagana biblioteka: pip install pycryptodome
"""

import os
import secrets
from Crypto.Cipher import AES, DES3

# ── parametry ──────────────────────────────────────────────────
BITS_PER_STREAM = 1_000_000
NUM_STREAMS     = 1_000
TOTAL_BITS      = BITS_PER_STREAM * NUM_STREAMS   # 1 000 000 000
TOTAL_BYTES     = TOTAL_BITS // 8                  # 125 000 000

assert TOTAL_BYTES % 16 == 0, "Nie jest wielokrotnością bloku AES (16 B)"
assert TOTAL_BYTES %  8 == 0, "Nie jest wielokrotnością bloku 3DES (8 B)"

# ── klucze (wspólne dla ECB i CTR danego algorytmu) ────────────
aes_key   = secrets.token_bytes(32)        # AES-256: 32 bajty
tdes_key  = DES3.adjust_key_parity(secrets.token_bytes(24))  # 3DES: 24 bajty (3-key)

# ── IV / nonce dla trybu CTR ───────────────────────────────────
aes_nonce  = secrets.token_bytes(8)        # AES CTR: 8-bajtowy nonce (reszta to licznik)
tdes_nonce = secrets.token_bytes(4)        # 3DES CTR: 4-bajtowy nonce (reszta to licznik)

# ── wypisz klucze i nonce ──────────────────────────────────────
print("=" * 70)
print("KLUCZE I PARAMETRY")
print("=" * 70)
print(f"AES-256 klucz  : {aes_key.hex()}")
print(f"AES CTR nonce  : {aes_nonce.hex()}")
print(f"3DES klucz     : {tdes_key.hex()}")
print(f"3DES CTR nonce : {tdes_nonce.hex()}")
print(f"Rozmiar pliku  : {TOTAL_BYTES:,} bajtów ({TOTAL_BITS:,} bitów)")
print(f"Bitstreamy     : {NUM_STREAMS} × {BITS_PER_STREAM:,} bitów")
print("=" * 70)

# ── generowanie pliku zerowego ─────────────────────────────────
ZERO_FILE = "output/zeros.bin"
CHUNK = 1_000_000  # piszemy po 1 MB żeby nie zjadać RAM-u

print(f"\n[1/5] Generowanie pliku zerowego: {ZERO_FILE}")
with open(ZERO_FILE, "wb") as f:
    written = 0
    while written < TOTAL_BYTES:
        size = min(CHUNK, TOTAL_BYTES - written)
        f.write(b"\x00" * size)
        written += size
print(f"      Gotowe ({os.path.getsize(ZERO_FILE):,} B)")

# ── funkcje szyfrujące (strumieniowo, po kawałku) ─────────────
def encrypt_file_ecb(in_path, out_path, cipher_factory, block_size, label):
    """Szyfruje plik w trybie ECB, blok po bloku."""
    print(f"[{label}] {in_path} -> {out_path}")
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        cipher = cipher_factory()
        while True:
            chunk = fin.read(block_size * 4096)  # wiele bloków naraz
            if not chunk:
                break
            fout.write(cipher.encrypt(chunk))
    print(f"      Gotowe ({os.path.getsize(out_path):,} B)")


def encrypt_file_ctr(in_path, out_path, cipher_factory, label):
    """Szyfruje plik w trybie CTR (strumieniowy, brak wymagań na blok)."""
    print(f"[{label}] {in_path} -> {out_path}")
    cipher = cipher_factory()
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            fout.write(cipher.encrypt(chunk))
    print(f"      Gotowe ({os.path.getsize(out_path):,} B)")


# ── szyfrowanie ────────────────────────────────────────────────

# AES-256 ECB
encrypt_file_ecb(
    ZERO_FILE, "output/zeros_aes256_ecb.bin",
    lambda: AES.new(aes_key, AES.MODE_ECB),
    AES.block_size, "2/5"
)

# AES-256 CTR
encrypt_file_ctr(
    ZERO_FILE, "output/zeros_aes256_ctr.bin",
    lambda: AES.new(aes_key, AES.MODE_CTR, nonce=aes_nonce),
    "3/5"
)

# 3DES ECB
encrypt_file_ecb(
    ZERO_FILE, "output/zeros_3des_ecb.bin",
    lambda: DES3.new(tdes_key, DES3.MODE_ECB),
    DES3.block_size, "4/5"
)

# 3DES CTR
encrypt_file_ctr(
    ZERO_FILE, "output/zeros_3des_ctr.bin",
    lambda: DES3.new(tdes_key, DES3.MODE_CTR, nonce=tdes_nonce),
    "5/5"
)

print("\n✓ Wszystkie pliki wygenerowane:")
for fname in ["zeros.bin", "zeros_aes256_ecb.bin", "zeros_aes256_ctr.bin",
              "zeros_3des_ecb.bin", "zeros_3des_ctr.bin"]:
    print(f"  {fname:30s} {os.path.getsize(fname):>15,} B")