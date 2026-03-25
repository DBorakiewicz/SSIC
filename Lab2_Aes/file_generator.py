import os
import time

OUTPUT_FILE = "file_10gb.bin"
TARGET_SIZE = 10 * 1024**3  # 10 GB
CHUNK_SIZE = 64 * 1024**2  # 64 MB

def main():
    print(f"Target: {TARGET_SIZE / (1024 ** 3):.1f} GB")
    print(f"Chunk:  {CHUNK_SIZE / (1024 ** 2):.0f} MB")
    print(f"Output: {OUTPUT_FILE}")
    print()

    chunk = b'\x00' * CHUNK_SIZE

    start = time.time()
    written = 0

    with open(OUTPUT_FILE, 'wb') as f:
        while written < TARGET_SIZE:
            remaining = TARGET_SIZE - written
            if remaining < CHUNK_SIZE:
                f.write(chunk[:remaining])
                written += remaining
            else:
                f.write(chunk)
                written += CHUNK_SIZE

            # Progress every ~512 MB
            if written % (512 * 1024 * 1024) == 0 or written >= TARGET_SIZE:
                elapsed = time.time() - start
                gb_done = written / (1024 ** 3)
                speed = gb_done / elapsed if elapsed > 0 else 0
                print(f"  {gb_done:6.2f} GB  |  {elapsed:6.1f}s  |  {speed:.2f} GB/s")
    elapsed = time.time() - start
    actual = os.path.getsize(OUTPUT_FILE)
    print(f"\nDone! File size: {actual / (1024 ** 3):.2f} GB  |  Time: {elapsed:.1f}s")

if __name__ == "__main__":
    main()

