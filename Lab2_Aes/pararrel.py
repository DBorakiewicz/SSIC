import os
import time
import hashlib
import tempfile
import multiprocessing as mp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

CHUNK_SIZE = 1024 * 1024  # 1 MB
INPUT_FILE = r'file_10gb.bin'
ENC_FILE_SEQ = r'encrypted_seq.bin'
DEC_FILE_SEQ = r'decrypted_seq.bin'
ENC_FILE_PAR = r'encrypted_par.bin'
DEC_FILE_PAR = r'decrypted_par.bin'

KEY_SIZE = 24  # AES-192
AES_BLOCK_SIZE = 16


def file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()


def compare_files(file1, file2):
    return file_hash(file1) == file_hash(file2)


# =============================================================================
# SEQUENTIAL
# =============================================================================

def encrypt_file_sequential(input_file, output_file, key):
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
    return total_time, encrypt_time, nonce


def decrypt_file_sequential(input_file, output_file, key):
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


# =============================================================================
# PARALLEL — workers write to temp files to avoid memory issues
# =============================================================================

def _encrypt_worker(args):
    """
    Each worker reads its segment from the input file in small chunks,
    encrypts them, and writes to a temporary file.
    Returns (chunk_index, temp_file_path, crypto_time).
    """
    key, nonce, chunk_index, file_offset, segment_size, input_file, temp_dir = args

    # Calculate CTR starting block for this segment
    block_counter_start = file_offset // AES_BLOCK_SIZE
    ctr = Counter.new(64, prefix=nonce, initial_value=block_counter_start)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    temp_path = os.path.join(temp_dir, f"enc_part_{chunk_index:04d}.bin")
    crypto_time = 0.0
    bytes_left = segment_size

    with open(input_file, "rb") as fin, open(temp_path, "wb") as fout:
        fin.seek(file_offset)
        while bytes_left > 0:
            read_size = min(CHUNK_SIZE, bytes_left)
            data = fin.read(read_size)
            if not data:
                break

            t = time.perf_counter()
            encrypted = cipher.encrypt(data)
            crypto_time += time.perf_counter() - t

            fout.write(encrypted)
            bytes_left -= len(data)

    return chunk_index, temp_path, crypto_time


def _decrypt_worker(args):
    """
    Each worker reads its segment from the encrypted file in small chunks,
    decrypts them, and writes to a temporary file.
    """
    key, nonce, chunk_index, file_offset, segment_size, enc_file, data_start_offset, temp_dir = args

    block_counter_start = file_offset // AES_BLOCK_SIZE
    ctr = Counter.new(64, prefix=nonce, initial_value=block_counter_start)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    temp_path = os.path.join(temp_dir, f"dec_part_{chunk_index:04d}.bin")
    crypto_time = 0.0
    bytes_left = segment_size

    with open(enc_file, "rb") as fin, open(temp_path, "wb") as fout:
        fin.seek(data_start_offset + file_offset)  # skip nonce
        while bytes_left > 0:
            read_size = min(CHUNK_SIZE, bytes_left)
            data = fin.read(read_size)
            if not data:
                break

            t = time.perf_counter()
            decrypted = cipher.decrypt(data)
            crypto_time += time.perf_counter() - t

            fout.write(decrypted)
            bytes_left -= len(data)

    return chunk_index, temp_path, crypto_time


def _build_segments(file_size, num_workers):
    """Divide file into block-aligned segments."""
    base_segment = file_size // num_workers
    base_segment = (base_segment // AES_BLOCK_SIZE) * AES_BLOCK_SIZE

    segments = []
    offset = 0
    for i in range(num_workers):
        if i == num_workers - 1:
            seg_size = file_size - offset
        else:
            seg_size = base_segment
        segments.append((i, offset, seg_size))
        offset += seg_size
    return segments


def _merge_temp_files(results, output_file, nonce=None):
    """Merge temp files into final output, optionally prepending nonce."""
    results.sort(key=lambda x: x[0])
    with open(output_file, "wb") as fout:
        if nonce:
            fout.write(nonce)
        for _, temp_path, _ in results:
            with open(temp_path, "rb") as fin:
                while chunk := fin.read(CHUNK_SIZE):
                    fout.write(chunk)
            os.remove(temp_path)


def encrypt_file_parallel(input_file, output_file, key, num_workers=None):
    if num_workers is None:
        num_workers = mp.cpu_count()

    nonce = get_random_bytes(8)
    file_size = os.path.getsize(input_file)
    segments = _build_segments(file_size, num_workers)

    temp_dir = tempfile.mkdtemp(prefix="aes_enc_")

    worker_args = [
        (key, nonce, idx, offset, size, input_file, temp_dir)
        for idx, offset, size in segments
    ]

    total_start = time.perf_counter()

    with mp.Pool(processes=num_workers) as pool:
        results = pool.map(_encrypt_worker, worker_args)

    crypto_times = [r[2] for r in results]

    _merge_temp_files(results, output_file, nonce=nonce)

    total_time = time.perf_counter() - total_start

    os.rmdir(temp_dir)

    return total_time, sum(crypto_times), max(crypto_times), nonce, num_workers


def decrypt_file_parallel(input_file, output_file, key, num_workers=None):
    if num_workers is None:
        num_workers = mp.cpu_count()

    with open(input_file, "rb") as f:
        nonce = f.read(8)

    file_size = os.path.getsize(input_file) - 8
    data_start_offset = 8
    segments = _build_segments(file_size, num_workers)

    temp_dir = tempfile.mkdtemp(prefix="aes_dec_")

    worker_args = [
        (key, nonce, idx, offset, size, input_file, data_start_offset, temp_dir)
        for idx, offset, size in segments
    ]

    total_start = time.perf_counter()

    with mp.Pool(processes=num_workers) as pool:
        results = pool.map(_decrypt_worker, worker_args)

    crypto_times = [r[2] for r in results]

    _merge_temp_files(results, output_file)

    total_time = time.perf_counter() - total_start

    os.rmdir(temp_dir)

    return total_time, sum(crypto_times), max(crypto_times), num_workers


# =============================================================================
# MAIN
# =============================================================================

def main():
    file_size = os.path.getsize(INPUT_FILE)
    size_gb = file_size / (1024 ** 3)
    size_mb = file_size / (1024 ** 2)
    num_cores = mp.cpu_count()

    print(f"Plik: {INPUT_FILE} ({size_gb:.2f} GB)")
    print(f"Algorytm: AES-192 (CTR)")
    print(f"Dostępne rdzenie CPU: {num_cores}")
    print(f"{'=' * 80}")

    key = get_random_bytes(KEY_SIZE)

    # ---- SEQUENTIAL ----
    print("\n>>> SZYFROWANIE SEKWENCYJNE")
    seq_enc_total, seq_enc_crypto, nonce = encrypt_file_sequential(
        INPUT_FILE, ENC_FILE_SEQ, key
    )
    print(f"  Całkowity czas:        {seq_enc_total:.3f} s")
    print(f"  Czas szyfrowania:      {seq_enc_crypto:.3f} s")
    print(f"  Prędkość całkowita:    {size_mb / seq_enc_total:.1f} MB/s")
    print(f"  Prędkość szyfrowania:  {size_mb / seq_enc_crypto:.1f} MB/s")

    print("\n>>> DESZYFROWANIE SEKWENCYJNE")
    seq_dec_total, seq_dec_crypto = decrypt_file_sequential(
        ENC_FILE_SEQ, DEC_FILE_SEQ, key
    )
    print(f"  Całkowity czas:        {seq_dec_total:.3f} s")
    print(f"  Czas deszyfrowania:    {seq_dec_crypto:.3f} s")
    print(f"  Prędkość całkowita:    {size_mb / seq_dec_total:.1f} MB/s")
    print(f"  Prędkość deszyfrowania:{size_mb / seq_dec_crypto:.1f} MB/s")

    print("\n  Weryfikacja: ", end="")
    if compare_files(INPUT_FILE, DEC_FILE_SEQ):
        print("OK - pliki identyczne")
    else:
        print("BŁĄD - pliki różne!")

    print(f"\n{'=' * 80}")

    # ---- PARALLEL ----
    print(f"\n>>> SZYFROWANIE RÓWNOLEGŁE ({num_cores} procesów)")
    par_enc_total, par_enc_crypto_sum, par_enc_crypto_max, _, nw = \
        encrypt_file_parallel(INPUT_FILE, ENC_FILE_PAR, key)
    print(f"  Całkowity czas:        {par_enc_total:.3f} s")
    print(f"  Suma czasów crypto:    {par_enc_crypto_sum:.3f} s (we wszystkich procesach)")
    print(f"  Max czas crypto:       {par_enc_crypto_max:.3f} s (najwolniejszy worker)")
    print(f"  Prędkość całkowita:    {size_mb / par_enc_total:.1f} MB/s")

    print(f"\n>>> DESZYFROWANIE RÓWNOLEGŁE ({num_cores} procesów)")
    par_dec_total, par_dec_crypto_sum, par_dec_crypto_max, _ = \
        decrypt_file_parallel(ENC_FILE_PAR, DEC_FILE_PAR, key)
    print(f"  Całkowity czas:        {par_dec_total:.3f} s")
    print(f"  Suma czasów crypto:    {par_dec_crypto_sum:.3f} s")
    print(f"  Max czas crypto:       {par_dec_crypto_max:.3f} s")
    print(f"  Prędkość całkowita:    {size_mb / par_dec_total:.1f} MB/s")

    print("\n  Weryfikacja: ", end="")
    if compare_files(INPUT_FILE, DEC_FILE_PAR):
        print("OK - pliki identyczne")
    else:
        print("BŁĄD - pliki różne!")

    print(f"\n{'=' * 80}")
    print("\n>>> PORÓWNANIE")
    print(f"  {'Operacja':<30} {'Sekwencyjne':>12} {'Równoległe':>12} {'Przyspieszenie':>15}")
    print(f"  {'-' * 69}")

    speedup_enc = seq_enc_total / par_enc_total
    print(f"  {'Szyfrowanie (total)':<30} {seq_enc_total:>11.3f}s {par_enc_total:>11.3f}s {speedup_enc:>14.2f}x")

    speedup_dec = seq_dec_total / par_dec_total
    print(f"  {'Deszyfrowanie (total)':<30} {seq_dec_total:>11.3f}s {par_dec_total:>11.3f}s {speedup_dec:>14.2f}x")

    print(f"\n  Teoretyczne max przyspieszenie (liczba rdzeni): {num_cores}x")
    print(f"  Efektywność szyfrowania:   {speedup_enc / num_cores * 100:.1f}%")
    print(f"  Efektywność deszyfrowania: {speedup_dec / num_cores * 100:.1f}%")


if __name__ == '__main__':
    main()