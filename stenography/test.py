"""
Steganografia w pliku losowym metodą matrix encoding (Hamming syndrome coding).
Parametry: k=6, N=63 -> 6 bitów danych na 63 bity nośnika, średnio 1 flip na blok.

Klucz: seed PRNG generujący permutację pozycji w każdym bloku
       (grupa ćwiczeniowa może to zastąpić własnym kluczem).
"""

import numpy as np
import sys

# === Parametry ===
K = 3                    # liczba bitów syndromu = bitów danych na blok
N = (1 << K) - 1         # 63 bity nośnika na blok
TEST_SIZE_BITS = 12_800_000  # 12.8 Mb = obszar testowany przez NIST (10^7 bitów dla single sequence; tu trzymamy się treści zadania: 12.8 MB)
# UWAGA: Zadanie mówi "pierwsze 12.8 MB". Jeden blok NIST = 1 Mb = 10^6 bitów.
# 12.8 MB = 12.8 * 8 * 10^6 bitów = 1.024 * 10^8 bitów. Tak interpretuję.
TEST_SIZE_BITS = 12_800_000 * 8

KEY_SEED = 0xDEADBEEF     # "klucz" - seed dla permutacji pozycji w blokach


def build_hamming_H(k):
    """
    Macierz parity-check H o wymiarach k x (2^k - 1).
    Kolumna i (1-indeksowana) = binarna reprezentacja liczby i.
    Dzięki temu jeśli syndrom != target, XOR wskazuje numer kolumny = pozycję bitu do flipa.
    """
    n = (1 << k) - 1
    H = np.zeros((k, n), dtype=np.uint8)
    for col in range(1, n + 1):
        for row in range(k):
            H[row, col - 1] = (col >> row) & 1
    return H


H = build_hamming_H(K)


def syndrome(block_bits, perm):
    """Liczy k-bitowy syndrom bloku po permutacji pozycji."""
    permuted = block_bits[perm]
    s = (H @ permuted) % 2
    return s


def syndrome_to_index(s):
    """Zamienia syndrom (k bitów) na liczbę 0..N. 0 = brak flipa."""
    idx = 0
    for row in range(K):
        idx |= int(s[row]) << row
    return idx


def get_perm(block_idx):
    """Permutacja pozycji w bloku - klucz steganograficzny."""
    rng = np.random.default_rng(KEY_SEED + block_idx)
    return rng.permutation(N)


# === Kodowanie ===

def encode(carrier_bits, data_bits):
    """
    carrier_bits: ndarray uint8 z 0/1, długość >= TEST_SIZE_BITS
    data_bits:    ndarray uint8 z 0/1 (dane do ukrycia)
    Zwraca: zmodyfikowany ndarray + faktyczna liczba ukrytych bitów + liczba flipów.
    """
    out = carrier_bits.copy()
    # Operujemy tylko w obszarze testowanym przez NIST
    usable_bits = TEST_SIZE_BITS
    n_blocks_capacity = usable_bits // N
    max_data_bits = n_blocks_capacity * K

    n_data = min(len(data_bits), max_data_bits)
    n_blocks = (n_data + K - 1) // K  # tyle bloków faktycznie używamy

    flips = 0
    embedded = 0

    for b in range(n_blocks):
        start = b * N
        end = start + N
        block = out[start:end]

        # Pobierz K bitów danych dla tego bloku (ostatni blok może być krótszy)
        d_start = b * K
        d_end = min(d_start + K, n_data)
        data_chunk = data_bits[d_start:d_end]
        # Jeśli ostatni blok ma mniej niż K bitów danych, dopełniamy zerami
        if len(data_chunk) < K:
            data_chunk = np.concatenate([data_chunk, np.zeros(K - len(data_chunk), dtype=np.uint8)])

        perm = get_perm(b)

        s = syndrome(block, perm)
        diff = (s ^ data_chunk).astype(np.uint8)
        idx = syndrome_to_index(diff)

        if idx != 0:
            # Flip pozycji (idx-1) w przestrzeni PO permutacji -> czyli pozycja perm[idx-1] w bloku
            real_pos = perm[idx - 1]
            out[start + real_pos] ^= 1
            flips += 1

        embedded += (d_end - d_start)

    return out, embedded, flips, n_blocks


# === Dekodowanie ===

def decode(stego_bits, n_data_bits):
    """
    Odzyskuje n_data_bits bitów danych z pliku stego.
    Wymaga znajomości tylko: K, N, KEY_SEED, n_data_bits.
    """
    n_blocks = (n_data_bits + K - 1) // K
    recovered = np.zeros(n_blocks * K, dtype=np.uint8)

    for b in range(n_blocks):
        start = b * N
        end = start + N
        block = stego_bits[start:end]
        perm = get_perm(b)
        s = syndrome(block, perm)
        recovered[b * K:(b + 1) * K] = s

    return recovered[:n_data_bits]


# === Pomocnicze: ładowanie / zapis pliku jako bity ===

def load_bits(path):
    raw = np.fromfile(path, dtype=np.uint8)
    bits = np.unpackbits(raw)
    return bits


def save_bits(bits, path):
    # padding do wielokrotności 8
    pad = (-len(bits)) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    raw = np.packbits(bits)
    raw.tofile(path)


# === Główna funkcja demo ===

def main(carrier_path, output_path):
    print(f"Wczytuję plik nośnika: {carrier_path}")
    carrier = load_bits(carrier_path)
    print(f"  - długość: {len(carrier)} bitów = {len(carrier) // 8} bajtów")

    if len(carrier) < TEST_SIZE_BITS:
        print(f"BŁĄD: plik za krótki, potrzeba minimum {TEST_SIZE_BITS} bitów.")
        sys.exit(1)

    # Pojemność
    n_blocks_capacity = TEST_SIZE_BITS // N
    max_data_bits = n_blocks_capacity * K
    print(f"\nObszar testowany przez NIST: {TEST_SIZE_BITS} bitów ({TEST_SIZE_BITS // 8} bajtów = {TEST_SIZE_BITS / 8 / 1024 / 1024:.2f} MB)")
    print(f"Liczba bloków po N={N} bitów: {n_blocks_capacity}")
    print(f"Maksymalna pojemność: {max_data_bits} bitów = {max_data_bits / 8 / 1024 / 1024:.3f} MB")

    # Dane do ukrycia: same jedynki (najtrudniejszy przypadek - skrajnie deterministyczne)
    data = np.ones(max_data_bits, dtype=np.uint8)
    print(f"\nDane do ukrycia: ciąg {len(data)} jedynek")

    # Kodowanie
    print(f"\nKoduję...")
    stego, embedded, flips, n_blocks_used = encode(carrier, data)

    print(f"\n=== WYNIKI KODOWANIA ===")
    print(f"Bloków użytych:           {n_blocks_used}")
    print(f"Bitów danych ukrytych:    {embedded}")
    print(f"Bajtów danych ukrytych:   {embedded / 8:.2f}")
    print(f"Megabajtów ukrytych:      {embedded / 8 / 1024 / 1024:.4f} MB")
    print(f"Bitów zmienionych (flipów): {flips}")
    print(f"Gęstość modyfikacji:      {100 * flips / TEST_SIZE_BITS:.4f}% bitów obszaru testowego")
    print(f"Efektywność:              {embedded / max(flips, 1):.3f} bitów danych / 1 flip")
    print(f"Procent pliku ukryty:     {100 * embedded / TEST_SIZE_BITS:.3f}% obszaru testowego")
    print(f"                          {100 * embedded / len(carrier):.3f}% całego pliku")

    # Zapis
    save_bits(stego, output_path)
    print(f"\nZapisano plik stego: {output_path}")

    # === Weryfikacja: dekodowanie ===
    print(f"\nWeryfikuję - dekoduję plik stego...")
    stego_loaded = load_bits(output_path)
    recovered = decode(stego_loaded, embedded)

    if np.array_equal(recovered, data[:embedded]):
        print(f"OK: odzyskano wszystkie {embedded} bitów danych poprawnie.")
    else:
        n_errors = np.sum(recovered != data[:embedded])
        print(f"BŁĄD: {n_errors} bitów się nie zgadza!")

    # Sanity check: ile bajtów w stego różni się od oryginału
    diff_bits = np.sum(carrier != stego)
    print(f"\nLiczba bitów różniących stego od oryginału: {diff_bits} (= {flips} flipów - powinno być równe)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Użycie: python hamming_stego.py <plik_nosnika.bit> <plik_wyjsciowy.bit>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])