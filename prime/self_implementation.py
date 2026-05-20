import sys
import time
from concurrent.futures import ProcessPoolExecutor
from bpsw import is_prime_bpsw
from bpsw_gmpy import is_prime_bpsw as is_prime_bpsw_gmpy
from bpsw_fast import is_prime_bpsw as is_prime_bpsw_fast


BLOCK_SIZE = 256   # 2048 bitów = 256 bajtów

def check_block(block: bytes) -> bool:
    """Konwertuje blok bajtów na liczbę i zwraca True jeśli (prawdopodobnie) pierwsza."""
    num = int.from_bytes(block, byteorder="big")
    return is_prime_bpsw_fast(num)

def main():
    if len(sys.argv) != 2:
        print(f"Użycie: {sys.argv[0]} <plik.bit>")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Nie znaleziono pliku: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"Błąd odczytu pliku: {e}")
        sys.exit(1)

    # Pełne 256-bajtowe bloki (ostatni niepełny pomijamy)
    blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data) - BLOCK_SIZE + 1, BLOCK_SIZE)]
    total = len(blocks)
    print(f"Wczytano {total} bloków po {BLOCK_SIZE} bajtów (2048 bitów).")
    print("Rozpoczynanie równoległego testowania...")

    start = time.time()

    # ProcessPoolExecutor domyślnie używa tylu procesów, ile rdzeni (os.cpu_count())
    with ProcessPoolExecutor() as executor:
        # map() zwraca iterator wyników w tej samej kolejności co bloki
        results = executor.map(check_block, blocks, chunksize=1000)

        # Sumujemy True (1) aby policzyć znalezione liczby pierwsze
        primes_found = sum(results)

    elapsed = time.time() - start
    print(f"Znalezionych (prawdopodobnie) pierwszych: {primes_found}")
    print(f"Czas testu: {elapsed:.3f} s")

if __name__ == "__main__":
    main()