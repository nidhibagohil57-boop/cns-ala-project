import hashlib
import hmac


def generate_mac(msg, key):
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_mac(msg, key, received_mac):
    expected_mac = generate_mac(msg, key)
    is_valid = hmac.compare_digest(expected_mac, received_mac)
    return is_valid, expected_mac