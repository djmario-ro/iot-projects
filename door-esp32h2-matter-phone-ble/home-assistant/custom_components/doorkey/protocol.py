"""Stock Matter UserLabel transport; no vendor cluster patches required."""
import base64
import hashlib
import re


def valid_name(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 29 or any(not 32 <= ord(c) <= 126 for c in name):
        raise ValueError("BLE name must contain 1–29 printable ASCII characters")
    return name


def checked_key(hex_key, fingerprint):
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(hex_key, str) or not re.fullmatch(r"04[0-9a-fA-F]{128}", hex_key):
        raise ValueError("Invalid P-256 public key")
    key = bytes.fromhex(hex_key)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
    if hashlib.sha256(key).hexdigest() != fingerprint.lower():
        raise ValueError("Manager public key fingerprint does not match")
    return key


def encode(name, key):
    valid_name(name)
    if len(key) != 65 or key[0] != 4:
        raise ValueError("Expected uncompressed P-256 public key")
    payload = f"1{len(name):02x}{name}" + base64.b64encode(key).decode("ascii")
    result = []
    for i in range(4):
        segment = payload[i*30:(i+1)*30]
        result.append({"label": f"D{i}" + segment[:14], "value": segment[14:]})
    return result


def decode(labels):
    if not isinstance(labels, list) or len(labels) != 4:
        raise ValueError("Reader has no DoorKey settings; use Configure reader first")
    parts = {}
    for item in labels:
        label = item.get("label", item.get("0"))
        value = item.get("value", item.get("1"))
        if not isinstance(label, str) or not isinstance(value, str) or not re.fullmatch(r"D[0-3].*", label) or len(label) > 16 or len(value) > 16 or label[:2] in parts:
            raise ValueError("Invalid reader settings")
        parts[label[:2]] = label[2:] + value
    payload = "".join(parts[f"D{i}"] for i in range(4))
    if payload[:1] != "1" or not re.fullmatch(r"[0-9a-f]{2}", payload[1:3]):
        raise ValueError("Unsupported settings version")
    n = int(payload[1:3], 16)
    name = valid_name(payload[3:3+n])
    key = base64.b64decode(payload[3+n:], validate=True)
    if len(payload) != 3+n+88 or len(key) != 65 or key[0] != 4:
        raise ValueError("Invalid key payload")
    return name, key


def check_write_result(result):
    if not isinstance(result, list) or not result:
        raise ValueError("Matter Server returned no write status")
    statuses = [item.get("Status", item.get("status", -1)) for item in result if isinstance(item, dict)]
    if len(statuses) != len(result):
        raise ValueError("Matter Server returned an unsupported write status format")
    failures = [status for status in statuses if status != 0]
    if failures:
        raise ValueError("H2 rejected Matter UserLabel write (status=" + ",".join(str(s) for s in failures) + "). Check the H2 firmware/storage initialization.")
