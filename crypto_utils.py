"""
crypto_utils.py — Hybrid Encryption Helpers
============================================
Combines CP-ABE (for AES key protection) with AES-GCM (for token encryption).

Flow:
    Encrypt:
        1. Generate random AES-256 key
        2. Encrypt WiFi token with AES-GCM
        3. Encrypt AES key with CP-ABE under policy
        → Store: {encrypted_token, nonce, tag, encrypted_aes_key_ct}

    Decrypt:
        1. Retrieve encrypted bundle
        2. Attempt CP-ABE decrypt of AES key
        3. If success → AES-GCM decrypt token
        → Return token string or None
"""

import os
import json
import secrets
import string
import time
from Crypto.Cipher import AES

from abe_engine import (
    cpabe_encrypt, cpabe_decrypt,
    deserialize_pk, deserialize_private_key,
    serialize_ciphertext, deserialize_ciphertext
)


def generate_wifi_token(length: int = 16) -> str:
    """Generate a random alphanumeric WiFi access token."""
    alphabet = string.ascii_uppercase + string.digits
    return "WIFI_" + "".join(secrets.choice(alphabet) for _ in range(length))


def encrypt_token(token_str: str, policy: str, pk: dict) -> dict | None:
    """
    Hybrid-encrypt a WiFi token under a CP-ABE policy.

    Returns
    -------
    bundle : dict with keys:
        encrypted_token     (hex) — AES-GCM ciphertext
        nonce               (hex)
        tag                 (hex)
        encrypted_aes_key   (str) — JSON-serialized ABE ciphertext
        policy              (str)
    """
    # Step 1 — Generate AES-256 key
    aes_key = os.urandom(32)

    # Step 2 — AES-GCM encrypt the token
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(token_str.encode())

    # Step 3 — CP-ABE encrypt the AES key under the policy
    abe_ct = cpabe_encrypt(pk, aes_key, policy)
    if abe_ct is None:
        return None

    return {
        "encrypted_token":   ciphertext.hex(),
        "nonce":             cipher.nonce.hex(),
        "tag":               tag.hex(),
        "encrypted_aes_key": serialize_ciphertext(abe_ct),
        "policy":            policy
    }


def decrypt_token(bundle: dict, private_key: dict, pk: dict) -> str | None:
    """
    Attempt to decrypt a hybrid-encrypted WiFi token using a user's CP-ABE key.

    Returns the token string on success, None if attributes don't satisfy policy.
    """
    try:
        abe_ct = deserialize_ciphertext(bundle["encrypted_aes_key"])

        # Step 1 — Attempt CP-ABE decryption of the AES key
        aes_key = cpabe_decrypt(pk, private_key, abe_ct)
        if aes_key is None or len(aes_key) != 32:
            return None

        # Step 2 — AES-GCM decrypt the token
        nonce       = bytes.fromhex(bundle["nonce"])
        tag         = bytes.fromhex(bundle["tag"])
        ciphertext  = bytes.fromhex(bundle["encrypted_token"])

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        token_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return token_bytes.decode()

    except Exception:
        return None


def benchmark_encryption(pk: dict, attribute_counts: list[int]) -> list[dict]:
    """
    Performance evaluation: runs encryption and decryption timing for
    different attribute counts.

    Returns list of result dicts per attribute count.
    """
    from abe_engine import cpabe_setup, cpabe_keygen

    results = []
    sample_token = "WIFI_BENCHMARK_TOKEN_001"
    policy_template = "({attrs})"

    for n in attribute_counts:
        # Build synthetic attributes and policy
        attrs         = [f"attr{i}:val{i}" for i in range(n)]
        policy_parts  = " AND ".join(attrs)
        policy        = f"({policy_parts})"
        aes_key       = os.urandom(32)

        # --- Encryption timing ---
        t0 = time.perf_counter()
        ct = cpabe_encrypt(pk, aes_key, policy)
        enc_time = (time.perf_counter() - t0) * 1000   # ms

        # Keygen for matching user
        _, msk = cpabe_setup()
        sk = cpabe_keygen(pk, msk, attrs, user_id=9999)

        # --- Decryption timing ---
        t0 = time.perf_counter()
        result = cpabe_decrypt(pk, sk, ct)
        dec_time = (time.perf_counter() - t0) * 1000   # ms

        results.append({
            "attributes": n,
            "policy":     policy,
            "enc_time_ms": round(enc_time, 3),
            "dec_time_ms": round(dec_time, 3),
            "success":    result is not None
        })

    return results
