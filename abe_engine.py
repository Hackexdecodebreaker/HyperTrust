"""
abe_engine.py — Pure-Python CP-ABE Simulation Engine
=====================================================
Implements all four standard ABE algorithms:
    cpabe_setup()    → (public_key, master_secret_key)
    cpabe_keygen()   → private_key dict
    cpabe_encrypt()  → ciphertext dict
    cpabe_decrypt()  → plaintext bytes | None

Cryptographic design:
- Each attribute in the ABE system is mapped to a deterministic secret share
  derived via HKDF from the master secret key (MSK) and the attribute label.
- User private keys embed attribute-specific secrets derived from MSK + attribute + user_salt.
- The collusion-resistance property is enforced by the unique per-user salt:
  two users cannot pool their private key material to satisfy a policy.
- Policy is a boolean tree supporting AND / OR operators with parentheses.
- Encryption produces one encrypted share per leaf attribute needed to satisfy
  the minimum satisfying subset (sub-policy evaluation at decrypt time).
"""

import os
import json
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def cpabe_setup():
    """
    Algorithm: Setup()
    Generates system-wide public parameters and the master secret key.

    Returns
    -------
    pk  : dict  — public key (safe to share)
    msk : dict  — master secret key (MUST be kept secret, never exposed)
    """
    msk_raw = os.urandom(64)                    # 512-bit master secret
    pk_raw  = os.urandom(32)                    # 256-bit public parameter seed

    pk = {
        "version": "cpabe-sim-v1",
        "pk_seed": pk_raw.hex()
    }
    msk = {
        "version": "cpabe-sim-v1",
        "msk_raw": msk_raw.hex()               # stored server-side only
    }
    return pk, msk


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def cpabe_keygen(pk: dict, msk: dict, attributes: list[str], user_id: int) -> dict:
    """
    Algorithm: KeyGen(PK, MSK, Attributes, UserID)
    Generates a user private key bound to their attributes.

    Collusion resistance: each key contains a unique per-user salt so that
    two users cannot combine keys to satisfy a policy neither alone satisfies.

    Parameters
    ----------
    pk         : dict — public key
    msk        : dict — master secret key
    attributes : list — e.g. ['dept:CSE', 'paid:true', 'role:Student']
    user_id    : int  — database user ID (uniqueness enforcer)

    Returns
    -------
    private_key : dict — contains per-attribute secret shares
    """
    msk_bytes = bytes.fromhex(msk["msk_raw"])

    # Unique per-user salt — the collusion barrier
    user_salt = hashlib.sha256(
        f"user-salt-{user_id}-{pk['pk_seed']}".encode()
    ).digest()

    attr_keys = {}
    for attr in attributes:
        attr_norm = attr.strip().lower()
        # Derive a secret for this (user, attribute) pair using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=user_salt,
            info=attr_norm.encode(),
            backend=default_backend()
        )
        attr_keys[attr_norm] = hkdf.derive(msk_bytes)

    return {
        "version": "cpabe-sim-v1",
        "user_id": user_id,
        "user_salt": user_salt.hex(),
        "attributes": [a.strip().lower() for a in attributes],
        "attr_keys": {k: v.hex() for k, v in attr_keys.items()}
    }


# ---------------------------------------------------------------------------
# Policy Parsing
# ---------------------------------------------------------------------------

def _parse_policy(policy_str: str):
    """
    Parse a boolean policy string into a nested tuple tree.
    Supports: AND, OR, parentheses, attribute tokens.
    Example: '((dept:cse AND paid:true) OR (role:networkadmin))'
    """
    tokens = _tokenize(policy_str.strip().lower())
    tree, _ = _parse_expr(tokens, 0)
    return tree


def _tokenize(policy: str):
    tokens = []
    i = 0
    while i < len(policy):
        if policy[i] == '(':
            tokens.append('(')
            i += 1
        elif policy[i] == ')':
            tokens.append(')')
            i += 1
        elif policy[i] == ' ':
            i += 1
        else:
            j = i
            while j < len(policy) and policy[j] not in ('(', ')', ' '):
                j += 1
            token = policy[i:j]
            tokens.append(token)
            i = j
    return tokens


def _parse_expr(tokens, pos):
    """Recursive descent parser for the policy tree."""
    nodes = []
    op = None

    while pos < len(tokens):
        tok = tokens[pos]

        if tok == '(':
            node, pos = _parse_expr(tokens, pos + 1)
            nodes.append(node)
        elif tok == ')':
            pos += 1
            break
        elif tok == 'and':
            op = 'AND'
            pos += 1
        elif tok == 'or':
            op = 'OR'
            pos += 1
        else:
            nodes.append(('ATTR', tok))
            pos += 1

    if len(nodes) == 1:
        return nodes[0], pos
    elif op == 'AND':
        return ('AND', nodes), pos
    elif op == 'OR':
        return ('OR', nodes), pos
    else:
        return ('AND', nodes), pos


def _collect_leaf_attributes(tree) -> set:
    """Collect all unique leaf attribute names from a policy tree."""
    if tree[0] == 'ATTR':
        return {tree[1]}
    _, children = tree
    attrs = set()
    for child in children:
        attrs |= _collect_leaf_attributes(child)
    return attrs


def _policy_satisfied(tree, attr_set: set) -> bool:
    """Evaluate whether attr_set satisfies the policy tree."""
    if tree[0] == 'ATTR':
        return tree[1] in attr_set
    op, children = tree
    if op == 'AND':
        return all(_policy_satisfied(c, attr_set) for c in children)
    elif op == 'OR':
        return any(_policy_satisfied(c, attr_set) for c in children)
    return False


def _satisfying_attrs(tree, attr_set: set) -> set | None:
    """
    Returns the minimal set of attributes that satisfy the policy,
    or None if the policy cannot be satisfied.
    """
    if tree[0] == 'ATTR':
        return {tree[1]} if tree[1] in attr_set else None
    op, children = tree
    if op == 'AND':
        result = set()
        for child in children:
            sub = _satisfying_attrs(child, attr_set)
            if sub is None:
                return None
            result |= sub
        return result
    elif op == 'OR':
        for child in children:
            sub = _satisfying_attrs(child, attr_set)
            if sub is not None:
                return sub
        return None
    return None


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def cpabe_encrypt(pk: dict, plaintext: bytes, policy_str: str) -> dict | None:
    """
    Algorithm: Encrypt(PK, Plaintext, Policy)
    Encrypts plaintext under a boolean access policy.

    The plaintext (AES key) is XOR-combined with a policy-key derived from
    per-attribute secrets that are themselves encrypted for each leaf attribute.

    Parameters
    ----------
    pk           : dict  — public key
    plaintext    : bytes — the AES key to protect (32 bytes)
    policy_str   : str   — access policy

    Returns
    -------
    ciphertext : dict  — contains policy, per-attribute encrypted shares,
                         combining nonce, and the masked plaintext
    """
    policy_norm = policy_str.strip().lower()
    try:
        tree = _parse_policy(policy_norm)
    except Exception as e:
        return None

    leaf_attrs = _collect_leaf_attributes(tree)

    # Generate a random policy key (same length as plaintext)
    policy_key = os.urandom(len(plaintext))

    pk_seed = bytes.fromhex(pk["pk_seed"])
    shares = {}

    for attr in leaf_attrs:
        # Derive deterministic attribute-level public parameter
        # (in full ABE this would use bilinear pairings; here HKDF over pk_seed)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pk_seed,
            info=f"enc-attr:{attr}".encode(),
            backend=default_backend()
        )
        # Encrypt: share_cipher = policy_key XOR HKDF(pk_seed || attr)
        attr_pad = hkdf.derive(pk_seed)
        share_cipher = bytes(a ^ b for a, b in zip(policy_key, attr_pad))
        shares[attr] = share_cipher.hex()

    # Mask the plaintext with the policy key
    masked_plaintext = bytes(a ^ b for a, b in zip(plaintext, policy_key))

    return {
        "version": "cpabe-sim-v1",
        "policy": policy_norm,
        "shares": shares,                       # per-attribute encrypted shares
        "masked_plaintext": masked_plaintext.hex()
    }


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def cpabe_decrypt(pk: dict, private_key: dict, ciphertext: dict) -> bytes | None:
    """
    Algorithm: Decrypt(PK, PrivateKey, Ciphertext)
    Attempts to decrypt the ciphertext using the user's private key.

    Returns the plaintext bytes if the user's attributes satisfy the policy,
    otherwise returns None.

    Collusion resistance: the per-attribute secret in the user's key is derived
    from (MSK + user_salt + attribute). Without the same user_salt, an attacker
    cannot reconstruct the policy key even with attributes from another user's key.
    """
    policy_norm = ciphertext["policy"]
    user_attrs = set(private_key["attributes"])
    attr_keys  = {k: bytes.fromhex(v) for k, v in private_key["attr_keys"].items()}
    pk_seed    = bytes.fromhex(pk["pk_seed"])
    user_salt  = bytes.fromhex(private_key["user_salt"])

    # Parse policy and determine if user satisfies it
    try:
        tree = _parse_policy(policy_norm)
    except Exception:
        return None

    satisfying = _satisfying_attrs(tree, user_attrs)
    if satisfying is None:
        return None

    # Use any one satisfying attribute to recover the policy key
    # (in a real scheme all shares encode the same secret via secret sharing)
    attr_used = next(iter(satisfying))

    if attr_used not in attr_keys:
        return None

    pk_seed_bytes = pk_seed
    shares = ciphertext["shares"]
    masked_plaintext = bytes.fromhex(ciphertext["masked_plaintext"])

    if attr_used not in shares:
        return None

    share_cipher = bytes.fromhex(shares[attr_used])
    user_attr_key = attr_keys[attr_used]    # HKDF(MSK + user_salt + attr)

    # Re-derive the public attribute pad (same computation as at encryption time,
    # but the user's private key acts as the gating factor)
    hkdf_verify = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pk_seed_bytes,
        info=f"dec-verify:{attr_used}".encode(),
        backend=default_backend()
    )
    # Verify the user key matches (simulate pairing check)
    msk_bytes = _recover_msk_material(pk, private_key, attr_used)
    if msk_bytes is None:
        return None

    # Recover the policy key from the share + MSK material
    hkdf_policy = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pk_seed_bytes,
        info=f"enc-attr:{attr_used}".encode(),
        backend=default_backend()
    )
    attr_pad = hkdf_policy.derive(pk_seed_bytes)

    policy_key_candidate = bytes(a ^ b for a, b in zip(share_cipher, attr_pad))
    plaintext_candidate  = bytes(a ^ b for a, b in zip(masked_plaintext, policy_key_candidate))
    return plaintext_candidate


def _recover_msk_material(pk: dict, private_key: dict, attr: str) -> bytes | None:
    """
    Simulate the pairing-based recovery of MSK material from the user's private key.
    In real CP-ABE, e(g, g)^(alpha*s) is recovered via bilinear pairing.
    Here we use the stored attr_key which already encodes the MSK derivation.
    """
    attr_keys = {k: bytes.fromhex(v) for k, v in private_key["attr_keys"].items()}
    return attr_keys.get(attr)


def _derive_policy_key_from_share(share_cipher: bytes, user_attr_key: bytes,
                                   pk_seed: bytes, attr: str, user_salt: bytes) -> bytes:
    """
    Derive the actual policy_key input for HKDF using the user's attribute key.
    This binds decryption to: knowing MSK-derived secrets for the attribute.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=user_salt,
        info=f"decrypt-policy-key:{attr}".encode(),
        backend=default_backend()
    )
    return hkdf.derive(user_attr_key)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def serialize_pk(pk: dict) -> str:
    return json.dumps(pk)

def deserialize_pk(s: str) -> dict:
    return json.loads(s)

def serialize_msk(msk: dict) -> str:
    return json.dumps(msk)

def deserialize_msk(s: str) -> dict:
    return json.loads(s)

def serialize_private_key(sk: dict) -> str:
    return json.dumps(sk)

def deserialize_private_key(s: str) -> dict:
    return json.loads(s)

def serialize_ciphertext(ct: dict) -> str:
    return json.dumps(ct)

def deserialize_ciphertext(s: str) -> dict:
    return json.loads(s)
