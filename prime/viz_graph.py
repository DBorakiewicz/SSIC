"""
Wizualizacja rozkładu odstępów (gapów) między liczbami pierwszymi
w blokach 2048-bitowych z pliku binarnego.

Użycie:
    python viz_gaps.py <plik.bin>

Wymaga: matplotlib, numpy
Opcjonalnie: seaborn (ładniejszy styl), gmpy2 (szybszy test)
"""

import sys
import time
import math
import numpy as np
import matplotlib.pyplot as plt
from concurrent.futures import ProcessPoolExecutor

try:
    import seaborn as sns
    sns.set_theme(style="whitegrid", palette="muted")
    HAS_SNS = True
except ImportError:
    HAS_SNS = False

# Import testu BPSW — preferuj wersję z gmpy2
try:
    from bpsw_gmpy2 import is_prime_bpsw
    BACKEND = "BPSW (gmpy2)"
except ImportError:
    try:
        from bpsw_gmpy import is_prime_bpsw
        BACKEND = "BPSW (fast)"
    except ImportError:
        from bpsw import is_prime_bpsw
        BACKEND = "BPSW (pure Python)"


BLOCK_SIZE = 256  # 2048 bitów = 256 bajtów


def check_block(args):
    """Testuje blok i zwraca (indeks, czy_pierwsza)."""
    idx, block = args
    num = int.from_bytes(block, byteorder="big")
    return (idx, is_prime_bpsw(num))


def main():
    if len(sys.argv) != 2:
        print(f"Użycie: {sys.argv[0]} <plik.bin>")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, "rb") as f:
        data = f.read()

    blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data) - BLOCK_SIZE + 1, BLOCK_SIZE)]
    total = len(blocks)
    print(f"Wczytano {total} bloków ({total * BLOCK_SIZE} B) — backend: {BACKEND}")
    print("Testuję pierwszość...")

    t0 = time.time()
    with ProcessPoolExecutor() as pool:
        results = list(pool.map(check_block, enumerate(blocks), chunksize=500))
    elapsed = time.time() - t0

    # Indeksy bloków które są pierwsze
    prime_indices = sorted(idx for idx, is_p in results if is_p)
    n_primes = len(prime_indices)
    print(f"Znaleziono {n_primes} liczb pierwszych w {elapsed:.1f} s")

    if n_primes < 2:
        print("Za mało liczb pierwszych do analizy gapów. Użyj większego pliku.")
        sys.exit(1)

    # ── Obliczanie gapów ──
    gaps = np.array([prime_indices[i+1] - prime_indices[i] - 1 for i in range(n_primes - 1)])

    # ── Statystyki ──
    p_theor = 1.0 / (2048 * math.log(2))  # 1 / ln(2^2048)
    mean_theor = (1 - p_theor) / p_theor
    mean_emp = gaps.mean()
    median_emp = np.median(gaps)
    freq_emp = n_primes / total  # empiryczna częstość pierwszych

    print(f"\n{'─'*45}")
    print(f"  Bloków ogółem:         {total}")
    print(f"  Liczb pierwszych:      {n_primes}")
    print(f"  Częstość empiryczna:   1/{total/n_primes:.0f}")
    print(f"  Częstość teoretyczna:  1/{1/p_theor:.0f}")
    print(f"  Średni gap (emp.):     {mean_emp:.1f}")
    print(f"  Średni gap (teor.):    {mean_theor:.1f}")
    print(f"  Mediana gap:           {median_emp:.0f}")
    print(f"  Max gap:               {gaps.max()}")
    print(f"{'─'*45}\n")

    # ── Wykres ──
    fig, ax = plt.subplots(figsize=(10, 5.5))
    fig.suptitle(
        f"Rozkład odstępów między liczbami pierwszymi w blokach 2048-bit",
        fontsize=13, fontweight="bold", y=0.97
    )

    max_gap = int(gaps.max())
    bin_width = 200
    bin_edges = np.arange(0, max_gap + bin_width + 1, bin_width)

    # Histogram — gęstość (density), żeby porównać z PMF
    ax.hist(gaps, bins=bin_edges, density=True, alpha=0.7,
            color="#e8572a", edgecolor="white", linewidth=0.3, label="empiryczny")

    # Krzywa teoretyczna: Geom(p)
    k_range = np.arange(0, max_gap + 1)
    geom_pmf = (1 - p_theor) ** k_range * p_theor
    ax.plot(k_range, geom_pmf, color="#2ec4b6", linewidth=2.2, label=f"Geom(1/{1/p_theor:.0f})")

    ax.set_xlabel("Gap (bloków złożonych między kolejnymi pierwszymi)", fontsize=10)
    ax.set_ylabel("Gęstość prawdopodobieństwa", fontsize=10)
    ax.legend(fontsize=10, framealpha=0.9)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    # Adnotacja ze statystykami
    stats_text = (
        f"n = {total}  |  pierwszych = {n_primes}\n"
        f"śr. gap: {mean_emp:.0f} (teor. {mean_theor:.0f})\n"
        f"mediana: {median_emp:.0f}  |  max: {gaps.max()}"
    )
    ax.text(0.97, 0.95, stats_text, transform=ax.transAxes,
            fontsize=8.5, verticalalignment="top", horizontalalignment="right",
            bbox=dict(boxstyle="round,pad=0.4", facecolor="white", alpha=0.85, edgecolor="#ccc"),
            family="monospace")

    plt.tight_layout()

    out_path = filename.rsplit(".", 1)[0] + "_gap_distribution.png"
    fig.savefig(out_path, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"Wykres zapisany: {out_path}")
    plt.show()


if __name__ == "__main__":
    main()