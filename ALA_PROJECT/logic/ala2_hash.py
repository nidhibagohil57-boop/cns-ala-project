import hashlib


def sha1(msg):
    return hashlib.sha1(msg.encode("utf-8")).hexdigest()


def sha256(msg):
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def sha512(msg):
    return hashlib.sha512(msg.encode("utf-8")).hexdigest()


def _hex_to_bits(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)


def _hamming_distance_bits(hex_a, hex_b):
    bits_a = _hex_to_bits(hex_a)
    bits_b = _hex_to_bits(hex_b)
    return sum(1 for a, b in zip(bits_a, bits_b) if a != b), len(bits_a)


def _hex_char_difference(hex_a, hex_b):
    changed = sum(1 for a, b in zip(hex_a, hex_b) if a != b)
    total = len(hex_a)
    return changed, total


def analyze_sha_integrity(original_text, changed_text):
    is_modified = original_text != changed_text

    original_hashes = {
        "SHA1": sha1(original_text),
        "SHA256": sha256(original_text),
        "SHA512": sha512(original_text),
    }

    changed_hashes = {
        "SHA1": sha1(changed_text),
        "SHA256": sha256(changed_text),
        "SHA512": sha512(changed_text),
    }

    avalanche = {}
    for algo in ("SHA1", "SHA256", "SHA512"):
        bit_changed, bit_total = _hamming_distance_bits(original_hashes[algo], changed_hashes[algo])
        hex_changed, hex_total = _hex_char_difference(original_hashes[algo], changed_hashes[algo])
        avalanche[algo] = {
            "bit_changed": bit_changed,
            "bit_total": bit_total,
            "bit_change_percent": round((bit_changed / bit_total) * 100, 2),
            "hex_changed": hex_changed,
            "hex_total": hex_total,
            "hex_change_percent": round((hex_changed / hex_total) * 100, 2),
        }

    return {
        "original_text": original_text,
        "changed_text": changed_text,
        "is_modified": is_modified,
        "original_hashes": original_hashes,
        "changed_hashes": changed_hashes,
        "avalanche": avalanche,
    }