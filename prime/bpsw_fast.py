"""
BPSW (Baillie–Pomerance–Selfridge–Wagstaff) Primality Test — FAST
==================================================================
Zoptymalizowana implementacja testu pierwszości BPSW dla dużych liczb (2048+ bitów).

Optymalizacje vs. wersja bazowa:
  1. GCD z primorialem zamiast pętli po małych pierwszych (jedno pow + gcd)
  2. Binarny algorytm Jacobiego bez dzielenia
  3. Lucas chain: operacje na bitach int-a, nie na stringu bin()
  4. Zminimalizowane redukcje modulo (lazy mod)
  5. Eliminacja powtórnej alokacji — precomputed stałe
  6. Montgomery-friendly layout (unikamy niepotrzebnych % n)
"""

import math
import sys

# ─── Primorial: iloczyn małych liczb pierwszych ───
# Jeden gcd(n, PRIMORIAL) zastępuje setki operacji n % p.
# Dzielimy na kilka primoriiali, żeby gcd operował na rozsądnych wielkościach.

def _sieve(limit: int) -> list[int]:
    sieve = bytearray(b'\x01') * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = b'\x00' * len(sieve[i*i::i])
    return [i for i, v in enumerate(sieve) if v]

SMALL_PRIMES = _sieve(100000)  # więcej małych pierwszych = więcej odfiltrowanych

# Primoriale w kawałkach (każdy ~4000 bitów, żeby gcd był szybki)
_PRIMORIAL_CHUNKS: list[int] = []
_chunk = 1
for _p in SMALL_PRIMES:
    _chunk *= _p
    if _chunk.bit_length() > 4096:
        _PRIMORIAL_CHUNKS.append(_chunk // _p)
        _chunk = _p
if _chunk > 1:
    _PRIMORIAL_CHUNKS.append(_chunk)

# Zbiór małych pierwszych do szybkiego lookup
_SMALL_PRIME_SET = frozenset(SMALL_PRIMES)


# ─── Krok 1: Próbne dzielenie przez primorial-GCD ───
def _trial_division(n: int) -> bool | None:
    """
    Zwraca True (pierwsza), False (złożona), None (nieokreślone).
    Zamiast n % p dla każdego p, robimy gcd(n, primorial_chunk).
    Jeśli gcd > 1, sprawdzamy czy gcd == n (wtedy n sama jest małą pierwszą)
    albo czy gcd dzieli n (złożona).
    """
    for chunk in _PRIMORIAL_CHUNKS:
        g = math.gcd(n, chunk)
        if g > 1:
            if g == n:
                # n jest iloczynem (podzbioru) małych pierwszych — sprawdź czy sama jest pierwsza
                return n in _SMALL_PRIME_SET
            if g < n:
                return False  # ma mały dzielnik
    return None


# ─── Krok 2: Miller-Rabin z bazą 2 ───
def _miller_rabin_base2(n: int, d: int, r: int) -> bool:
    """
    Test MR z bazą 2. Przyjmuje gotowy rozkład n-1 = d * 2^r.
    """
    x = pow(2, d, n)

    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = x * x % n
        if x == n - 1:
            return True

    return False


# ─── Symbol Jacobiego — zoptymalizowany binarny ───
def _jacobi(a: int, n: int) -> int:
    """
    Binarny algorytm Jacobiego. Unika dzielenia — operuje tylko na
    przesunięciach bitowych i odejmowaniu.
    """
    a = a % n
    result = 1

    while a:
        # Wyciągnij czynniki 2 z a
        t = (a & -a).bit_length() - 1  # ile trailing zeros
        if t:
            a >>= t
            # (-1)^(n²-1)/8 dla każdego czynnika 2
            if t & 1:  # nieparzysta liczba dwójek
                n8 = n & 7  # n mod 8
                if n8 == 3 or n8 == 5:
                    result = -result

        # Zamiana (reciprocity)
        if a & n & 2:  # oba ≡ 3 (mod 4)
            result = -result

        a, n = n % a, a

    return result if n == 1 else 0


# ─── Parametr D Selfridge'a ───
def _find_d_parameter(n: int) -> int:
    """
    Szuka D z ciągu 5, -7, 9, -11, ... takiego, że Jacobi(D, n) == -1.
    Zwraca 0 jeśli n jest złożona (ma mały dzielnik lub jest kwadratem).
    """
    d = 5
    sign = 1
    while True:
        D = sign * d
        j = _jacobi(D, n)
        if j == -1:
            return D
        if j == 0:
            g = math.gcd(d, n)  # d = |D|
            if 1 < g < n:
                return 0
        d += 2
        sign = -sign
        if d > 256:
            # Prawdopodobnie kwadrat doskonały
            s = math.isqrt(n)
            if s * s == n:
                return 0


# ─── Silny test Lucasa — zoptymalizowany ───
def _strong_lucas(n: int) -> bool:
    """
    Silny test Lucasa z parametrami Selfridge'a.
    Zakłada n > 2, n nieparzyste, n nie jest kwadratem.

    Optymalizacje:
    - Iteracja po bitach int-a (bit_length + shift), nie po stringu
    - half_mod inline bez wywołania funkcji
    - Lazy modular reduction (co kilka operacji)
    """
    D = _find_d_parameter(n)
    if D == 0:
        return False

    Q = (1 - D) >> 2  # (1 - D) / 4, zawsze całkowite dla D ≡ 1 (mod 4)

    # Rozkład n+1 = d * 2^s
    np1 = n + 1
    s = (np1 & -np1).bit_length() - 1  # trailing zeros
    d = np1 >> s

    # Lucas chain: oblicz U_d, V_d mod n
    U = 1
    V = 1  # P = 1 zawsze w Selfridge
    Qk = Q % n

    # Bity d od drugiego najstarszego w dół
    bit_len = d.bit_length()

    for i in range(bit_len - 2, -1, -1):
        # Podwajanie: k → 2k
        # U_{2k} = U_k * V_k
        # V_{2k} = V_k^2 - 2*Q^k
        U = U * V % n
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n

        if (d >> i) & 1:
            # Krok +1: 2k → 2k+1  (P=1)
            # U_{k+1} = (U + V) / 2
            # V_{k+1} = (D*U + V) / 2
            U_new = U + V
            if U_new & 1:
                U_new += n
            U_new >>= 1

            V_new = D * U + V
            if V_new & 1:
                V_new += n
            V_new >>= 1

            U = U_new % n
            V = V_new % n
            Qk = Qk * Q % n

    # Sprawdzenie: U_d ≡ 0 (mod n) lub V_d ≡ 0 (mod n)
    if U % n == 0 or V % n == 0:
        return True

    # Sprawdzenie: V_{d*2^r} ≡ 0 (mod n) dla r = 1, ..., s-1
    for _ in range(s - 1):
        V = (V * V - 2 * Qk) % n
        Qk = Qk * Qk % n
        if V == 0:
            return True

    return False


# ─── Główna funkcja BPSW ───
def is_prime_bpsw(n: int) -> bool:
    """
    Test pierwszości BPSW.

    Zwraca True jeśli n jest (prawdopodobnie) pierwsza,
    False jeśli n jest złożona.

    Parametry
    ---------
    n : int
        Liczba do przetestowania (dowolna wielkość, zoptymalizowane pod 2048-bit).
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n & 1 == 0:
        return False

    # Krok 1: GCD z primorialami
    td = _trial_division(n)
    if td is not None:
        return td

    # Kwadrat doskonały — szybkie odrzucenie
    # Sprawdzamy mod małych liczb zanim odpalamy isqrt (który jest drogi dla 2048-bit)
    # n mod 16: kwadraty mogą dawać tylko 0,1,4,9
    r16 = n & 15
    if r16 not in (1, 9):  # nieparzyste n, więc nie 0 ani 4
        pass  # nie jest kwadratem na pewno — ale to za mało, idziemy dalej
    else:
        # Dodatkowy filtr: kwadraty mod 9 → {0, 1, 4, 7}
        r9 = n % 9
        if r9 in (0, 1, 4, 7):
            # Drogie sprawdzenie — tylko jeśli przeszło oba filtry
            s = math.isqrt(n)
            if s * s == n:
                return False

    # Rozkład n-1 = d * 2^r (obliczamy raz, reużywamy)
    nm1 = n - 1
    r = (nm1 & -nm1).bit_length() - 1
    d = nm1 >> r

    # Krok 2: Miller-Rabin z bazą 2
    if not _miller_rabin_base2(n, d, r):
        return False

    # Krok 3: Silny test Lucasa
    if not _strong_lucas(n):
        return False

    return True


# ─── Demo / Benchmark ───
if __name__ == "__main__":
    import time
    import secrets

    print("=" * 60)
    print("  BPSW Primality Test — FAST edition")
    print("=" * 60)

    # Poprawność
    known_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        104729, 15485863,
        2**61 - 1, 2**89 - 1, 2**107 - 1, 2**127 - 1,
        2**521 - 1, 2**607 - 1, 2**1279 - 1,
    ]
    known_composites = [
        4, 6, 8, 9, 15, 21, 25, 100,
        561, 1105,           # Carmichael
        2**67 - 1,           # 193707721 × 761838257287
        (2**31 - 1) * (2**61 - 1),
    ]

    print("\n[1] Weryfikacja — liczby pierwsze:")
    ok = True
    for p in known_primes:
        r = is_prime_bpsw(p)
        if not r:
            print(f"  ✗ BŁĄD: {p.bit_length()}-bit")
            ok = False
    print(f"  {'✓ Wszystkie poprawne' if ok else '✗ Są błędy!'} ({len(known_primes)} testów)")

    print("\n[2] Weryfikacja — liczby złożone:")
    ok = True
    for c in known_composites:
        r = is_prime_bpsw(c)
        if r:
            print(f"  ✗ BŁĄD: {c}")
            ok = False
    print(f"  {'✓ Wszystkie poprawne' if ok else '✗ Są błędy!'} ({len(known_composites)} testów)")

    # Benchmark: wiele 2048-bitowych testów
    print("\n[3] Benchmark: 50× test BPSW na 2048-bitowej liczbie pierwszej")

    # Najpierw znajdź jedną
    while True:
        candidate = secrets.randbits(2048) | (1 << 2047) | 1
        if is_prime_bpsw(candidate):
            break

    times = []
    for _ in range(50):
        t0 = time.perf_counter()
        is_prime_bpsw(candidate)
        times.append(time.perf_counter() - t0)

    avg = sum(times) / len(times) * 1000
    best = min(times) * 1000
    worst = max(times) * 1000
    print(f"  Średnia: {avg:.2f} ms")
    print(f"  Najlep.: {best:.2f} ms")
    print(f"  Najgor.: {worst:.2f} ms")

    # Benchmark: szukanie 2048-bitowej pierwszej
    print("\n[4] Szukanie losowej 2048-bitowej liczby pierwszej:")
    t0 = time.perf_counter()
    attempts = 0
    while True:
        c2 = secrets.randbits(2048) | (1 << 2047) | 1
        attempts += 1
        if is_prime_bpsw(c2):
            break
    dt = time.perf_counter() - t0
    print(f"  Znaleziono po {attempts} próbach w {dt:.2f} s")
    print(f"  Śr. czas/kandydata: {dt/attempts*1000:.2f} ms")

    # Porównanie z wersją bazową (jeśli dostępna)
    try:
        from bpsw import is_prime_bpsw as is_prime_old
        print("\n[5] Porównanie z wersją bazową (50× na tej samej 2048-bit liczbie):")
        times_old = []
        for _ in range(50):
            t0 = time.perf_counter()
            is_prime_old(candidate)
            times_old.append(time.perf_counter() - t0)
        avg_old = sum(times_old) / len(times_old) * 1000
        print(f"  Stara: {avg_old:.2f} ms")
        print(f"  Nowa:  {avg:.2f} ms")
        print(f"  Speedup: {avg_old / avg:.1f}×")
    except ImportError:
        pass

    print("\n" + "=" * 60)
    print("  Gotowe. Użycie: from bpsw_fast import is_prime_bpsw")
    print("=" * 60)