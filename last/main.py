import os
import time
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def save_key_to_file(filename, key_bytes):
    with open(filename, "wb") as f:
        f.write(key_bytes)
    return os.path.getsize(filename)


def benchmark_operation(operation, n=100):
    """Run operation n times and return average time in seconds."""
    times_ns = []
    for _ in range(n):
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()
        times_ns.append(end - start)
    avg_ns = statistics.mean(times_ns)
    return avg_ns / 1e9  # convert to seconds


def main():
    # Configuration
    RSA_KEY_SIZES = [2048, 3072]
    EC_CURVES = {
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
    }
    MESSAGE_SIZE = 1024  # 1 KB
    N_ITERATIONS = 100

    # Prepare results containers
    results = {
        "algorithm": [],
        "key_size_or_curve": [],
        "private_key_size_B": [],
        "public_key_size_B": [],
        "signature_size_B": [],
        "overhead_pct_64B": [],
        "time_keygen_s": [],
        "time_sign_s": [],
        "time_verify_s": [],
    }

    # ---------- RSA ----------
    for key_size in RSA_KEY_SIZES:
        alg_label = f"RSA-{key_size}"

        # Generate keys once for size analysis and later benchmarks
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        # Serialize and save to PEM
        priv_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        priv_size = save_key_to_file(f"rsa_{key_size}_private.pem", priv_pem)
        pub_size = save_key_to_file(f"rsa_{key_size}_public.pem", pub_pem)

        # Prepare signer/verifier
        # We'll use PSS padding with SHA-256 (or SHA-384 for larger key? consistent hash)
        hash_algo = hashes.SHA256()
        if key_size >= 3072:
            # For larger key we can still use SHA-256, but for robustness we'll keep it.
            pass

        # Create a random message once (same for all)
        message = os.urandom(MESSAGE_SIZE)

        # Signature (for size measurement)
        signature = private_key.sign(
            message,
            PSS(
                mgf=MGF1(hash_algo),
                salt_length=PSS.MAX_LENGTH
            ),
            hash_algo,
        )
        sig_size = len(signature)

        # Overhead percentage relative to 64 B frame
        overhead_pct = (sig_size / 64) * 100

        # Benchmark key generation
        def gen_rsa():
            rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend(),
            )

        time_keygen = benchmark_operation(gen_rsa, n=N_ITERATIONS)

        # Benchmark signing
        def sign_rsa():
            private_key.sign(
                message,
                PSS(
                    mgf=MGF1(hash_algo),
                    salt_length=PSS.MAX_LENGTH
                ),
                hash_algo,
            )

        time_sign = benchmark_operation(sign_rsa, n=N_ITERATIONS)

        # Benchmark verification
        def verify_rsa():
            public_key.verify(
                signature,
                message,
                PSS(
                    mgf=MGF1(hash_algo),
                    salt_length=PSS.MAX_LENGTH
                ),
                hash_algo,
            )

        time_verify = benchmark_operation(verify_rsa, n=N_ITERATIONS)

        results["algorithm"].append("RSA")
        results["key_size_or_curve"].append(str(key_size))
        results["private_key_size_B"].append(priv_size)
        results["public_key_size_B"].append(pub_size)
        results["signature_size_B"].append(sig_size)
        results["overhead_pct_64B"].append(overhead_pct)
        results["time_keygen_s"].append(time_keygen)
        results["time_sign_s"].append(time_sign)
        results["time_verify_s"].append(time_verify)

    # ---------- ECC ----------
    for curve_name, curve in EC_CURVES.items():
        alg_label = f"ECC-{curve_name}"

        # Generate keys
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()

        # Serialize PEM
        priv_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        priv_size = save_key_to_file(
            f"ecc_{curve_name.lower()}_private.pem", priv_pem
        )
        pub_size = save_key_to_file(
            f"ecc_{curve_name.lower()}_public.pem", pub_pem
        )

        # Choose hash algorithm appropriate for curve
        if curve_name == "SECP256R1":
            hash_algo = hashes.SHA256()
        else:
            hash_algo = hashes.SHA384()

        message = os.urandom(MESSAGE_SIZE)

        # Sign
        signature = private_key.sign(message, ec.ECDSA(hash_algo))
        sig_size = len(signature)

        overhead_pct = (sig_size / 64) * 100

        # Benchmark key generation
        def gen_ecc():
            ec.generate_private_key(curve, default_backend())

        time_keygen = benchmark_operation(gen_ecc, n=N_ITERATIONS)

        # Benchmark signing
        def sign_ecc():
            private_key.sign(message, ec.ECDSA(hash_algo))

        time_sign = benchmark_operation(sign_ecc, n=N_ITERATIONS)

        # Benchmark verification
        def verify_ecc():
            public_key.verify(signature, message, ec.ECDSA(hash_algo))

        time_verify = benchmark_operation(verify_ecc, n=N_ITERATIONS)

        results["algorithm"].append("ECC")
        results["key_size_or_curve"].append(curve_name)
        results["private_key_size_B"].append(priv_size)
        results["public_key_size_B"].append(pub_size)
        results["signature_size_B"].append(sig_size)
        results["overhead_pct_64B"].append(overhead_pct)
        results["time_keygen_s"].append(time_keygen)
        results["time_sign_s"].append(time_sign)
        results["time_verify_s"].append(time_verify)

    # ---------- Output ----------
    print("\n" + "=" * 130)
    print(
        f"{'Alg':<6} {'Parametr':<15} {'PrivKey(B)':>10} {'PubKey(B)':>10} "
        f"{'Sig(B)':>8} {'Overhead(%)':>12} {'KeyGen(s)':>14} {'Sign(s)':>14} {'Verify(s)':>14}"
    )
    print("-" * 130)
    for i in range(len(results["algorithm"])):
        algo = results["algorithm"][i]
        param = results["key_size_or_curve"][i]
        priv = results["private_key_size_B"][i]
        pub = results["public_key_size_B"][i]
        sig = results["signature_size_B"][i]
        overhead = results["overhead_pct_64B"][i]
        keygen = results["time_keygen_s"][i]
        sign = results["time_sign_s"][i]
        verify = results["time_verify_s"][i]
        print(
            f"{algo:<6} {param:<15} {priv:>10} {pub:>10} "
            f"{sig:>8} {overhead:>11.2f}% {keygen:>14.9f} {sign:>14.9f} {verify:>14.9f}"
        )
    print("=" * 130)
    print(
        "\n* Overhead obliczony jako (rozmiar podpisu / 64 bajty) * 100%."
        " Wartości >100% oznaczają, że podpis przekracza rozmiar ramki."
    )

    # Save results to file
    with open("wyniki_benchmark.txt", "w") as f:
        f.write("PORÓWNANIE WYDAJNOŚCI RSA I ECC\n")
        f.write("=" * 130 + "\n")
        f.write(
            f"{'Alg':<6} {'Parametr':<15} {'PrivKey(B)':>10} {'PubKey(B)':>10} "
            f"{'Sig(B)':>8} {'Overhead(%)':>12} {'KeyGen(s)':>14} {'Sign(s)':>14} {'Verify(s)':>14}\n"
        )
        f.write("-" * 130 + "\n")
        for i in range(len(results["algorithm"])):
            algo = results["algorithm"][i]
            param = results["key_size_or_curve"][i]
            priv = results["private_key_size_B"][i]
            pub = results["public_key_size_B"][i]
            sig = results["signature_size_B"][i]
            overhead = results["overhead_pct_64B"][i]
            keygen = results["time_keygen_s"][i]
            sign = results["time_sign_s"][i]
            verify = results["time_verify_s"][i]
            f.write(
                f"{algo:<6} {param:<15} {priv:>10} {pub:>10} "
                f"{sig:>8} {overhead:>11.2f}% {keygen:>14.9f} {sign:>14.9f} {verify:>14.9f}\n"
            )
        f.write("=" * 130 + "\n")
        f.write(
            "\n* Overhead obliczony jako (rozmiar podpisu / 64 bajty) * 100%.\n"
            "* Czasy podane w sekundach (średnia z 100 pomiarów).\n"
            "* Czas mierzony z dokładnością nanosekund.\n"
        )

    print("\n✓ Wyniki zapisane do pliku 'wyniki_benchmark.txt'")


if __name__ == "__main__":
    main()