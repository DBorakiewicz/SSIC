"""
BPSW (Baillie–Pomerance–Selfridge–Wagstaff) Primality Test
===========================================================
Implementacja testu pierwszości BPSW dla dużych liczb (do 2048+ bitów).

Algorytm składa się z trzech kroków:
  1. Próbne dzielenie przez małe liczby pierwsze
  2. Test Millera-Rabina z bazą 2
  3. Silny test Lucasa (strong Lucas probable prime test)

Jeśli liczba przejdzie wszystkie trzy etapy, jest uznawana za prawdopodobnie
pierwszą. Nie znaleziono dotąd kontrprzykładu dla testu BPSW.
"""

import math
import sys


# --- Małe liczby pierwsze do próbnego dzielenia ---
# Sito Eratostenesa do wygenerowania małych liczb pierwszych
def _small_primes(limit: int = 10000) -> list[int]:
    sieve = bytearray(b'\x01') * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = b'\x00' * len(sieve[i*i::i])
    return [i for i, v in enumerate(sieve) if v]

SMALL_PRIMES = _small_primes(10000)


# --- Krok 1: Próbne dzielenie ---
def _trial_division(n: int) -> bool | None:
    """
    Sprawdza podzielność n przez małe liczby pierwsze.
    Zwraca:
      True  – n jest jedną z małych liczb pierwszych
      False – n jest podzielne przez małą liczbę pierwszą (złożona)
      None  – nie udało się rozstrzygnąć (przejdź do dalszych testów)
    """
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return None


# --- Krok 2: Test Millera-Rabina z bazą 2 ---
def _miller_rabin_base2(n: int) -> bool:
    """
    Deterministyczny test Millera-Rabina z pojedynczą bazą a=2.
    Zakłada n > 3 i n nieparzyste.
    """
    # Rozkład n-1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d >>= 1
        r += 1

    # x = 2^d mod n
    x = pow(2, d, n)

    if x == 1 or x == n - 1:
        return True  # prawdopodobnie pierwsza

    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True  # prawdopodobnie pierwsza

    return False  # złożona


# --- Krok 3: Silny test Lucasa ---
def _jacobi_symbol(a: int, n: int) -> int:
    """Oblicza symbol Jacobiego (a/n). Wymaga n > 0, n nieparzyste."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n musi być dodatnie i nieparzyste")

    a = a % n
    result = 1

    while a != 0:
        while a % 2 == 0:
            a >>= 1
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n

    return result if n == 1 else 0


def _find_d_parameter(n: int) -> int:
    """
    Metoda Selfridge'a: szukamy pierwszego D z ciągu 5, -7, 9, -11, 13, ...
    takiego, że symbol Jacobiego (D/n) == -1.
    Jeśli po drodze trafimy na (D/n) == 0 i gcd(|D|, n) != {1, n},
    to n jest złożona (zwracamy 0).
    """
    d = 5
    sign = 1
    while True:
        D = sign * d
        j = _jacobi_symbol(D, n)
        if j == -1:
            return D
        if j == 0:
            # gcd(|D|, n) dzieli n, ale nie jest n → n złożona
            g = math.gcd(abs(D), n)
            if 1 < g < n:
                return 0  # sygnał: n jest złożona
        d += 2
        sign = -sign

        # Zabezpieczenie: jeśli n jest kwadratem doskonałym,
        # pętla mogłaby się nie skończyć — sprawdzamy raz.
        if d == 5 + 2:  # po pierwszej iteracji
            pass
        if d > 1000:
            # Dodatkowe sprawdzenie: czy n jest kwadratem doskonałym
            s = math.isqrt(n)
            if s * s == n:
                return 0  # n jest kwadratem → złożona


def _strong_lucas_test(n: int) -> bool:
    """
    Silny test Lucasa (strong Lucas probable prime test) z parametrami Selfridge'a.
    Zakłada n > 2, n nieparzyste, n nie jest kwadratem doskonałym.
    """
    D = _find_d_parameter(n)
    if D == 0:
        return False  # n jest złożona (znaleziono dzielnik lub jest kwadratem)

    P = 1
    Q = (1 - D) // 4

    # Rozkład n+1 = d * 2^s
    d = n + 1
    s = 0
    while d % 2 == 0:
        d >>= 1
        s += 1

    # Obliczamy U_d, V_d, Q^d mod n za pomocą podwajania indeksu (Lucas chain)
    # Używamy schematu:
    #   U_{2k} = U_k * V_k (mod n)
    #   V_{2k} = V_k^2 - 2*Q^k (mod n)
    #   U_{2k+1} = (P*U_{2k} + V_{2k}) / 2 (mod n)
    #   V_{2k+1} = (D*U_{2k} + P*V_{2k}) / 2 (mod n)

    # Dzielenie przez 2 mod n: mnożymy przez odwrotność 2 mod n
    # Ale łatwiej: jeśli x nieparzyste, to (x + n) / 2 (bo n nieparzyste → x+n parzyste)
    def half_mod(x: int) -> int:
        if x & 1:
            x += n
        return (x >> 1) % n

    U = 1
    V = P
    Qk = Q  # Q^k mod n — śledzi Q podniesione do aktualnego indeksu k
    Qk %= n

    # Iteracja po bitach d (od drugiego najstarszego w dół)
    bits = bin(d)[2:]  # binarnie

    for bit in bits[1:]:  # pomijamy pierwszy bit (zawsze 1)
        # Podwajanie: k → 2k
        U = (U * V) % n
        V = (V * V - 2 * Qk) % n
        Qk = (Qk * Qk) % n

        if bit == '1':
            # Krok +1: 2k → 2k+1
            U_new = half_mod(P * U + V)
            V_new = half_mod(D * U + P * V)
            U = U_new % n
            V = V_new % n
            Qk = (Qk * Q) % n

    # Teraz mamy U_d, V_d mod n
    # Silny test Lucasa: n jest slpsp jeśli
    #   U_d ≡ 0 (mod n)  LUB  V_{d·2^r} ≡ 0 (mod n) dla jakiegoś r ∈ {0, 1, ..., s-1}

    if U % n == 0 or V % n == 0:
        return True

    for _ in range(1, s):
        # V_{2k} = V_k^2 - 2*Q^k
        V = (V * V - 2 * Qk) % n
        Qk = (Qk * Qk) % n
        if V == 0:
            return True

    return False


# --- Główna funkcja BPSW ---
def is_prime_bpsw(n: int) -> bool:
    """
    Test pierwszości BPSW.

    Zwraca True jeśli n jest (prawdopodobnie) pierwsza,
    False jeśli n jest złożona.

    Nie znaleziono dotąd kontrprzykładu — test jest uważany za
    deterministyczny w praktyce dla wszystkich liczb < 2^64,
    a silnie wiarygodny dla dowolnie dużych.

    Parametry
    ---------
    n : int
        Liczba do przetestowania. Obsługuje liczby dowolnej wielkości,
        zoptymalizowany pod 2048-bitowe.
    """
    # Przypadki brzegowe
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Krok 1: Próbne dzielenie
    td = _trial_division(n)
    if td is not None:
        return td

    # Sprawdzenie czy n nie jest kwadratem doskonałym
    # (silny test Lucasa nie radzi sobie z kwadratami)
    s = math.isqrt(n)
    if s * s == n:
        return False

    # Krok 2: Miller-Rabin z bazą 2
    if not _miller_rabin_base2(n):
        return False

    # Krok 3: Silny test Lucasa
    if not _strong_lucas_test(n):
        return False

    return True


# --- Demo / CLI ---
if __name__ == "__main__":
    import time
    import secrets

    print("=" * 60)
    print("  BPSW Primality Test — demo")
    print("=" * 60)

    # Test na znanych liczbach pierwszych
    known_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        104729,           # 10000-ta liczba pierwsza
        15485863,         # 1000000-ta liczba pierwsza
        2**61 - 1,        # Mersenne prime M61
        2**89 - 1,        # Mersenne prime M89
        2**107 - 1,       # Mersenne prime M107
        2**127 - 1,       # Mersenne prime M127
        2**521 - 1,       # Mersenne prime M521
        2**607 - 1,       # Mersenne prime M607
    ]

    print("\n[1] Weryfikacja znanych liczb pierwszych:")
    for p in known_primes:
        t0 = time.perf_counter()
        result = is_prime_bpsw(p)
        dt = time.perf_counter() - t0
        bits = p.bit_length()
        status = "✓ PIERWSZA" if result else "✗ BŁĄD!"
        print(f"  {status}  {bits:>4}-bit  ({dt*1000:.2f} ms)")

    # Test na znanych liczbach złożonych
    known_composites = [
        4, 6, 8, 9, 15, 21, 25, 100,
        561,              # liczba Carmichaela
        1105,             # liczba Carmichaela
        2**67 - 1,        # = 147573952589676412927 = 193707721 × 761838257287
        (2**31 - 1) * (2**61 - 1),  # iloczyn dwóch Mersenne'ów
    ]

    print("\n[2] Weryfikacja znanych liczb złożonych:")
    for c in known_composites:
        t0 = time.perf_counter()
        result = is_prime_bpsw(c)
        dt = time.perf_counter() - t0
        bits = c.bit_length()
        status = "✓ ZŁOŻONA" if not result else "✗ BŁĄD!"
        print(f"  {status}  {bits:>4}-bit  ({dt*1000:.2f} ms)")

    # Test wydajności na 2048-bitowej liczbie pierwszej
    print("\n[3] Generowanie i testowanie 2048-bitowej liczby pierwszej...")
    print("    (szukam losowej 2048-bitowej prawdopodobnie pierwszej...)")

    t0 = time.perf_counter()
    attempts = 0
    while True:
        # Generuj losową 2048-bitową liczbę nieparzystą z ustawionym najstarszym bitem
        candidate = secrets.randbits(2048) | (1 << 2047) | 1
        attempts += 1
        if is_prime_bpsw(candidate):
            break
    dt_total = time.perf_counter() - t0

    print(f"    Znaleziono po {attempts} próbach ({dt_total:.2f} s)")
    print(f"    Bity: {candidate.bit_length()}")
    print(f"    Liczba (hex, pierwsze 64 znaki): {hex(candidate)[:66]}...")

    # Zmierz sam test na znalezionej liczbie
    t0 = time.perf_counter()
    result = is_prime_bpsw(candidate)
    dt = time.perf_counter() - t0
    print(f"    Ponowny test BPSW: {'PIERWSZA' if result else 'ZŁOŻONA'} ({dt*1000:.2f} ms)")

    # Porównanie z wbudowanym Pythona (3.x ma sympy-niezależny is_prime w pewnych wersjach)
    print("\n[4] Porównanie z pow() + Fermata (szybki sanity check):")
    fermat_ok = pow(2, candidate - 1, candidate) == 1
    print(f"    Fermat base-2: {'przeszedł' if fermat_ok else 'nie przeszedł'}")

    print("\n" + "=" * 60)
    print("  Gotowe. Użycie: from bpsw import is_prime_bpsw")
    print("=" * 60)