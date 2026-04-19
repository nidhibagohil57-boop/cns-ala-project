import hashlib
import secrets


def _sha256_int(msg):
    digest = hashlib.sha256(msg.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = _egcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def _mod_inverse(a, m):
    gcd, x, _ = _egcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _is_probable_prime(n, rounds=12):
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_keys(key_size=512):
    e = 65537
    while True:
        p = _generate_prime(key_size // 2)
        q = _generate_prime(key_size // 2)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue

        d = _mod_inverse(e, phi)
        return (e, n), (d, n)


def sign_message(msg):
    public, private = generate_keys()
    hash_int = _sha256_int(msg) % private[1]
    signature = pow(hash_int, private[0], private[1])
    return signature, public, format(hash_int, "x")


def verify_signature(msg, signature, public):
    expected_hash = _sha256_int(msg) % public[1]
    recovered_hash = pow(signature, public[0], public[1])
    return (
        expected_hash == recovered_hash,
        format(expected_hash, "x"),
        format(recovered_hash, "x"),
    )