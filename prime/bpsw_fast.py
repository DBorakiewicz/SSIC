"""
BPSW Primality Test — gmpy2-accelerated
========================================
Własna implementacja algorytmu BPSW, ale z arytmetyką GMP (via gmpy2)
zamiast natywnych Pythonowych intów. Daje ~5-10× speedup na 2048-bitach.

gmpy2.mpz operuje na libgmp, która:
  - Używa algorytmu Karatsuby / Toom-Cook / FFT do mnożenia dużych liczb
  - Ma zoptymalizowane modular exponentiation z Montgomery reduction
  - Operuje bezpośrednio na pamięci (nie tworzy obiektów Pythona przy każdej operacji)

Jeśli gmpy2 nie jest dostępne, automatycznie fallbackuje na czysty Python.
"""

try:
    import gmpy2
    from gmpy2 import mpz, jacobi as _gmp_jacobi, is_strong_prp
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False

import math
import sys


# ─── Małe liczby pierwsze + primoriale ───

def _sieve(limit: int) -> list[int]:
    sieve = bytearray(b'\x01') * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = b'\x00' * len(sieve[i*i::i])
    return [i for i, v in enumerate(sieve) if v]

SMALL_PRIMES = _sieve(100000)
_SMALL_PRIME_SET = frozenset(SMALL_PRIMES)

# Primoriale w kawałkach do GCD
_PRIMORIAL_CHUNKS: list[int] = []
_chunk = 1
for _p in SMALL_PRIMES:
    _chunk *= _p
    if _chunk.bit_length() > 4096:
        _PRIMORIAL_CHUNKS.append(_chunk // _p)
        _chunk = _p
if _chunk > 1:
    _PRIMORIAL_CHUNKS.append(_chunk)

if HAS_GMPY2:
    _PRIMORIAL_CHUNKS_MPZ = [mpz(c) for c in _PRIMORIAL_CHUNKS]


# ─── Próbne dzielenie ───

def _trial_division(n) -> bool | None:
    if HAS_GMPY2:
        for chunk in _PRIMORIAL_CHUNKS_MPZ:
            g = gmpy2.gcd(n, chunk)
            if g > 1:
                if g == n:
                    return int(n) in _SMALL_PRIME_SET
                return False
    else:
        for chunk in _PRIMORIAL_CHUNKS:
            g = math.gcd(int(n), chunk)
            if g > 1:
                if g == n:
                    return int(n) in _SMALL_PRIME_SET
                return False
    return None


# ─── Miller-Rabin baza 2 ───

def _miller_rabin_base2(n, d, r: int) -> bool:
    if HAS_GMPY2:
        x = gmpy2.powmod(mpz(2), d, n)
    else:
        x = pow(int(2), int(d), int(n))

    nm1 = n - 1
    if x == 1 or x == nm1:
        return True

    for _ in range(r - 1):
        if HAS_GMPY2:
            x = gmpy2.powmod(x, mpz(2), n)
        else:
            x = x * x % n
        if x == nm1:
            return True

    return False


# ─── Symbol Jacobiego ───

def _jacobi(a, n) -> int:
    if HAS_GMPY2:
        return int(_gmp_jacobi(a, n))

    # Fallback: binarny Jacobi (czysty Python)
    a = a % n
    result = 1
    while a:
        t = 0
        while not (a & 1):
            a >>= 1
            t += 1
        if t & 1:
            n8 = n & 7
            if n8 == 3 or n8 == 5:
                result = -result
        if a & n & 2:
            result = -result
        a, n = n % a, a
    return result if n == 1 else 0


# ─── Parametr D Selfridge'a ───

def _find_d_parameter(n) -> int:
    d = 5
    sign = 1
    while True:
        D = sign * d
        j = _jacobi(D, n)
        if j == -1:
            return int(D)
        if j == 0:
            if HAS_GMPY2:
                g = int(gmpy2.gcd(mpz(d), n))
            else:
                g = math.gcd(d, int(n))
            if 1 < g < int(n):
                return 0
        d += 2
        sign = -sign
        if d > 256:
            if HAS_GMPY2:
                s = gmpy2.isqrt(n)
            else:
                s = math.isqrt(int(n))
            if s * s == n:
                return 0


# ─── Silny test Lucasa ───

def _strong_lucas(n) -> bool:
    D = _find_d_parameter(n)
    if D == 0:
        return False

    Q = (1 - D) >> 2

    np1 = n + 1
    np1_int = int(np1)
    s = (np1_int & -np1_int).bit_length() - 1
    d = np1 >> s

    if HAS_GMPY2:
        n = mpz(n)
        D_m = mpz(D)
        Q_m = mpz(Q) % n
        U = mpz(1)
        V = mpz(1)
        Qk = Q_m
        TWO = mpz(2)
    else:
        D_m = D
        Q_m = Q % int(n)
        U = 1
        V = 1
        Qk = Q_m

    d_int = int(d)
    bit_len = d_int.bit_length()

    for i in range(bit_len - 2, -1, -1):
        U = U * V % n
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n

        if (d_int >> i) & 1:
            U_new = U + V
            if int(U_new) & 1:
                U_new += n
            U_new >>= 1

            V_new = D_m * U + V
            if int(V_new) & 1:
                V_new += n
            V_new >>= 1

            U = U_new % n
            V = V_new % n
            Qk = Qk * Q_m % n

    if U % n == 0 or V % n == 0:
        return True

    for _ in range(s - 1):
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if V == 0:
            return True

    return False


# ─── Główna funkcja BPSW ───

def is_prime_bpsw(n: int) -> bool:
    """
    Test pierwszości BPSW. Używa gmpy2 jeśli dostępne, inaczej czysty Python.

    Parametry
    ---------
    n : int
        Liczba do przetestowania.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n & 1 == 0:
        return False

    if HAS_GMPY2:
        n = mpz(n)

    # Próbne dzielenie
    td = _trial_division(n)
    if td is not None:
        return td

    # Kwadrat doskonały
    if HAS_GMPY2:
        if gmpy2.is_square(n):
            return False
    else:
        r16 = int(n) & 15
        if r16 in (1, 9):
            r9 = int(n) % 9
            if r9 in (0, 1, 4, 7):
                s = math.isqrt(int(n))
                if s * s == int(n):
                    return False

    # Rozkład n-1 = d * 2^r
    nm1 = n - 1
    nm1_int = int(nm1)
    r = (nm1_int & -nm1_int).bit_length() - 1
    d = nm1 >> r

    # Miller-Rabin baza 2
    if not _miller_rabin_base2(n, d, r):
        return False

    # Silny test Lucasa
    if not _strong_lucas(n):
        return False

    return True


# ─── Demo / Benchmark ───

if __name__ == "__main__":
    import time
    import secrets

    print("=" * 60)
    print("  BPSW Primality Test — gmpy2 accelerated")
    print(f"  gmpy2 available: {HAS_GMPY2}")
    print("=" * 60)

    # Poprawność
    known_primes = [
        2, 3, 5, 7, 11, 13, 104729, 15485863,
        2**61 - 1, 2**89 - 1, 2**107 - 1, 2**127 - 1,
        2**521 - 1, 2**607 - 1, 2**1279 - 1, 2**2203 - 1,
    ]
    known_composites = [
        4, 6, 9, 15, 25, 561, 1105, 2**67 - 1,
        (2**31 - 1) * (2**61 - 1),
    ]

    print("\n[1] Poprawność:")
    all_ok = True
    for p in known_primes:
        if not is_prime_bpsw(p):
            print(f"  ✗ BŁĄD na {p.bit_length()}-bit pierwszej")
            all_ok = False
    for c in known_composites:
        if is_prime_bpsw(c):
            print(f"  ✗ BŁĄD na {c}")
            all_ok = False
    print(f"  ✓ Wszystko OK ({len(known_primes) + len(known_composites)} testów)" if all_ok else "  ✗ Są błędy!")

    # Benchmark: pojedynczy test 2048-bit
    print("\n[2] Szukanie 2048-bitowej liczby pierwszej...")
    t0 = time.perf_counter()
    attempts = 0
    while True:
        candidate = secrets.randbits(2048) | (1 << 2047) | 1
        attempts += 1
        if is_prime_bpsw(candidate):
            break
    dt = time.perf_counter() - t0
    print(f"  Znaleziono po {attempts} próbach w {dt:.2f} s")
    print(f"  Śr. czas/kandydata: {dt/attempts*1000:.3f} ms")

    # Benchmark: 100× test na znalezionej pierwszej
    print(f"\n[3] Benchmark: 100× test BPSW na {candidate.bit_length()}-bit pierwszej")
    times = []
    for _ in range(100):
        t0 = time.perf_counter()
        is_prime_bpsw(candidate)
        times.append(time.perf_counter() - t0)
    avg = sum(times) / len(times) * 1000
    best = min(times) * 1000
    print(f"  Średnia: {avg:.2f} ms")
    print(f"  Najlep.: {best:.2f} ms")

    # Porównanie z oryginałem
    try:
        from bpsw import is_prime_bpsw as old_bpsw
        print(f"\n[4] Porównanie z oryginałem (100× na tej samej liczbie):")
        times_old = []
        for _ in range(100):
            t0 = time.perf_counter()
            old_bpsw(candidate)
            times_old.append(time.perf_counter() - t0)
        avg_old = sum(times_old) / len(times_old) * 1000
        print(f"  Oryginał (czysty Python): {avg_old:.2f} ms")
        print(f"  Nowa (gmpy2):             {avg:.2f} ms")
        print(f"  Speedup:                  {avg_old / avg:.1f}×")
    except ImportError:
        pass

    print("\n" + "=" * 60)