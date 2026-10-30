"""
crypto_demo.py
==============

A teaching module with two contrasting approaches to encrypting a text string:

1. `encrypt_strong` / `decrypt_strong`
   Current best practice (as of 2026): password -> Argon2id KDF -> AES-256-GCM
   authenticated encryption. Returns a self-describing bundle holding everything
   needed for future decryption (salt, nonce, KDF params, ciphertext).

2. `encrypt_weak` / `decrypt_weak` / `crack_weak`
   A deliberately weak scheme for *learning how key-stretching defeats brute force*.
   Password -> PBKDF2-HMAC-SHA256 with a TUNABLE iteration count -> XOR keystream.
   `crack_weak` brute-forces it against a wordlist and times the attempt, so you
   can watch the cost of an attack scale with the iteration count.

                            ⚠️  DO NOT ship the weak scheme. It exists only to be broken.

Dependencies:
    pip install cryptography argon2-cffi
    (PBKDF2 and XOR use only the standard library.)

Background (why these choices):
    - AES-256-GCM is an AEAD cipher: it gives confidentiality *and* integrity, so
      tampering is detected on decrypt. Preferred over AES-CBC, which needs a
      separate MAC and is prone to padding-oracle mistakes.
    - Argon2id is the current recommended password KDF (RFC 9106, OWASP). It is
      memory-hard, which blunts GPU/ASIC cracking in a way PBKDF2 cannot.
    - You never "encrypt with a password" directly. You stretch the password into
      a key with a KDF, using a random per-message salt, then encrypt with that key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Iterable, Optional

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# 1. STRONG: Argon2id key derivation + AES-256-GCM authenticated encryption
# ---------------------------------------------------------------------------

# OWASP 2026 baseline Argon2id parameters. Tune UP for your hardware, not down.
_ARGON2_TIME_COST = 3          # iterations (t)
_ARGON2_MEMORY_COST = 65536    # KiB -> 64 MiB (m)
_ARGON2_PARALLELISM = 1        # lanes (p)
_ARGON2_KEY_LEN = 32           # 32 bytes -> AES-256
_ARGON2_SALT_LEN = 16
_AESGCM_NONCE_LEN = 12         # 96-bit nonce, the GCM standard


def _derive_key_argon2(password: bytes, salt: bytes, *,
                       time_cost: int, memory_cost: int,
                       parallelism: int, key_len: int) -> bytes:
    """Stretch a password into a raw AES key with Argon2id."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_len,
        type=Argon2Type.ID,
    )


def encrypt_strong(plaintext: str, password: str, *,
                   time_cost: int = _ARGON2_TIME_COST,
                   memory_cost: int = _ARGON2_MEMORY_COST,
                   parallelism: int = _ARGON2_PARALLELISM) -> str:
    """
    Encrypt `plaintext` under `password` using Argon2id + AES-256-GCM.

    Returns a single URL-safe base64 string (a JSON bundle) that carries
    *everything* required to decrypt later: the algorithm name, the KDF
    parameters, the random salt, the random nonce, and the ciphertext+tag.
    Store that string anywhere. The password is the only secret; it is never
    stored.

    You can safely store the returned bundle in a database column, a file, etc.
    """
    pw = password.encode("utf-8")
    salt = secrets.token_bytes(_ARGON2_SALT_LEN)
    nonce = secrets.token_bytes(_AESGCM_NONCE_LEN)

    key = _derive_key_argon2(
        pw, salt,
        time_cost=time_cost, memory_cost=memory_cost,
        parallelism=parallelism, key_len=_ARGON2_KEY_LEN,
    )

    # AES-GCM returns ciphertext with the 16-byte auth tag appended.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)

    bundle = {
        "alg": "AES-256-GCM",
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "key_len": _ARGON2_KEY_LEN,
        },
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }
    return _b64e(json.dumps(bundle, separators=(",", ":")).encode("utf-8"))


def decrypt_strong(bundle_str: str, password: str) -> str:
    """
    Reverse `encrypt_strong`. Raises if the password is wrong or the data was
    tampered with (GCM authentication failure).
    """
    bundle = json.loads(_b64d(bundle_str).decode("utf-8"))
    p = bundle["kdf_params"]

    key = _derive_key_argon2(
        password.encode("utf-8"),
        _b64d(bundle["salt"]),
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        key_len=p["key_len"],
    )

    plaintext = AESGCM(key).decrypt(
        _b64d(bundle["nonce"]),
        _b64d(bundle["ciphertext"]),
        None,
    )
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# 2. WEAK: tunable-iteration PBKDF2 + XOR keystream  (for cracking practice)
# ---------------------------------------------------------------------------
#
# This is INTENTIONALLY breakable. Two independent weaknesses, both on purpose:
#   - The KDF iteration count is a knob you set low, so each password guess is cheap.
#   - The cipher is a raw XOR keystream with no authentication, so a correct guess
#     is recognizable and nothing stops you trying every candidate.
# Together they let you measure how attack cost scales with the iteration count.

_WEAK_SALT_LEN = 8
_WEAK_KEYSTREAM_HASH = "sha256"
# A short "canary" prefix is prepended to the plaintext before encryption. On a
# guess, if the decrypted bytes start with this canary, the guess is almost
# certainly correct. This is the "known-plaintext" handle a real attacker exploits.
_WEAK_CANARY = b"OK:"


def _pbkdf2_key(password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=length)


def _xor_keystream(key_seed: bytes, length: int) -> bytes:
    """
    Expand `key_seed` into `length` bytes of keystream by hashing
    seed || counter in blocks. Toy construction — do not reuse elsewhere.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.new(_WEAK_KEYSTREAM_HASH,
                            key_seed + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


@dataclass
class WeakBundle:
    """Everything needed to decrypt (or attack) a weakly-encrypted message."""
    alg: str
    kdf: str
    iterations: int
    salt: str          # base64
    ciphertext: str    # base64

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "WeakBundle":
        return cls(**json.loads(s))


def encrypt_weak(plaintext: str, password: str, iterations: int = 1000) -> WeakBundle:
    """
    Weakly encrypt `plaintext` under `password`.

    `iterations` is the PBKDF2 work factor and the whole point of the exercise:
    set it to 100 and cracking is near-instant; set it to 5_000_000 and the same
    brute force takes far longer, because every guess pays that cost.

    Returns a `WeakBundle` (serialize with `.to_json()`).
    """
    pw = password.encode("utf-8")
    salt = secrets.token_bytes(_WEAK_SALT_LEN)
    message = _WEAK_CANARY + plaintext.encode("utf-8")

    key_seed = _pbkdf2_key(pw, salt, iterations, length=32)
    keystream = _xor_keystream(key_seed, len(message))
    ciphertext = bytes(a ^ b for a, b in zip(message, keystream))

    return WeakBundle(
        alg="XOR-keystream(sha256)",
        kdf="pbkdf2-hmac-sha256",
        iterations=iterations,
        salt=_b64e(salt),
        ciphertext=_b64e(ciphertext),
    )


def _weak_try_password(bundle: WeakBundle, candidate: str) -> Optional[str]:
    """Attempt one password. Return plaintext if the canary matches, else None."""
    salt = _b64d(bundle.salt)
    ct = _b64d(bundle.ciphertext)
    key_seed = _pbkdf2_key(candidate.encode("utf-8"), salt, bundle.iterations, length=32)
    keystream = _xor_keystream(key_seed, len(ct))
    message = bytes(a ^ b for a, b in zip(ct, keystream))
    if message.startswith(_WEAK_CANARY):
        return message[len(_WEAK_CANARY):].decode("utf-8", errors="replace")
    return None


def decrypt_weak(bundle: WeakBundle, password: str) -> str:
    """Normal decryption with the known password. Raises ValueError if wrong."""
    result = _weak_try_password(bundle, password)
    if result is None:
        raise ValueError("Wrong password (canary mismatch).")
    return result


@dataclass
class CrackResult:
    cracked: bool
    password: Optional[str]
    plaintext: Optional[str]
    attempts: int
    seconds: float

    @property
    def guesses_per_second(self) -> float:
        return self.attempts / self.seconds if self.seconds else float("inf")


def crack_weak(bundle: WeakBundle, wordlist: Iterable[str],
               verbose: bool = False) -> CrackResult:
    """
    Brute-force a `WeakBundle` by trying each password in `wordlist`, timing the run.

    Run it against the same plaintext encrypted at different `iterations` values to
    see attack time scale with the KDF work factor. Example:

        words = [f"pw{i}" for i in range(50_000)] + ["hunter2"]
        for n in (100, 10_000, 500_000):
            b = encrypt_weak("the treasure is buried under the oak", "hunter2", iterations=n)
            r = crack_weak(b, words)
            print(n, "iters ->", round(r.seconds, 3), "s", int(r.guesses_per_second), "guesses/s")
    """
    start = time.perf_counter()
    attempts = 0
    for candidate in wordlist:
        attempts += 1
        plaintext = _weak_try_password(bundle, candidate)
        if plaintext is not None:
            elapsed = time.perf_counter() - start
            if verbose:
                print(f"[+] cracked after {attempts} attempts in {elapsed:.3f}s: {candidate!r}")
            return CrackResult(True, candidate, plaintext, attempts, elapsed)
    elapsed = time.perf_counter() - start
    if verbose:
        print(f"[-] exhausted {attempts} candidates in {elapsed:.3f}s, not found")
    return CrackResult(False, None, None, attempts, elapsed)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_SECRET = "the treasure is buried under the old oak tree"
DEFAULT_PASSWORD = "hunter2"


def _load_wordlist(path: Optional[str], ensure: Optional[str] = None) -> list:
    """
    Load candidate passwords from `path`, one per line (blank lines and
    '#' comments ignored). Falls back to a synthetic list if the file is
    missing. If `ensure` is given and absent, it is appended so the demo
    crack can succeed.
    """
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            words = [ln.strip() for ln in fh
                     if ln.strip() and not ln.lstrip().startswith("#")]
    else:
        if path:
            print(f"(wordlist {path!r} not found — using a synthetic 20,000-word list)")
        words = [f"pw{i}" for i in range(20_000)]
    if ensure is not None and ensure not in words:
        words.append(ensure)
    return words


def _cmd_demo(args: argparse.Namespace) -> None:
    wordlist = _load_wordlist(args.wordlist, ensure=args.password)

    print("=== STRONG (Argon2id + AES-256-GCM) ===")
    bundle = encrypt_strong(args.secret, args.password)
    print("stored bundle:", bundle[:72], "...")
    print("decrypted:    ", decrypt_strong(bundle, args.password))
    try:
        decrypt_strong(bundle, args.password + "_wrong")
    except Exception as e:  # noqa: BLE001 - demonstrating the rejection
        print("wrong password rejected:", type(e).__name__)

    print(f"\n=== WEAK (PBKDF2 tunable iters + XOR) — dictionary of {len(wordlist):,} words ===")
    print(f"{'iterations':>12} | {'time (s)':>9} | {'guesses/s':>12} | cracked")
    print("-" * 56)
    for iters in args.iterations:
        wb = encrypt_weak(args.secret, args.password, iterations=iters)
        r = crack_weak(wb, wordlist)
        print(f"{iters:>12,} | {r.seconds:>9.3f} | {r.guesses_per_second:>12,.0f} | {r.password!r}")

    print("\nguesses/sec is the headline: every ~10x on iterations cuts it ~10x.")
    print("That cost is paid per guess — the whole point of key stretching.")
    print("Argon2id adds *memory* cost on top, which GPUs/ASICs can't parallelize away.")


def _cmd_crack(args: argparse.Namespace) -> None:
    wordlist = _load_wordlist(args.wordlist, ensure=args.password)
    wb = encrypt_weak(args.secret, args.password, iterations=args.iterations)
    print(f"Weakly encrypted at {args.iterations:,} PBKDF2 iterations.")
    print(f"Brute-forcing against {len(wordlist):,} candidates...\n")
    r = crack_weak(wb, wordlist, verbose=True)
    if r.cracked:
        print(f"\nplaintext recovered: {r.plaintext!r}")
    print(f"{r.attempts:,} attempts in {r.seconds:.3f}s "
          f"({r.guesses_per_second:,.0f} guesses/s)")


def main(argv: Optional[list] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Strong vs. deliberately-weak text encryption — a teaching demo.")
    sub = parser.add_subparsers(dest="command")

    d = sub.add_parser(
        "demo", help="encrypt strongly, then crack the weak scheme at several iteration counts")
    d.add_argument("--iterations", type=int, nargs="+", default=[100, 1_000, 10_000, 100_000],
                   help="PBKDF2 iteration counts to compare (default: 100 1000 10000 100000)")
    d.add_argument("--wordlist", default="wordlist.txt",
                   help="password list, one per line (default: wordlist.txt)")
    d.add_argument("--secret", default=DEFAULT_SECRET, help="plaintext to encrypt")
    d.add_argument("--password", default=DEFAULT_PASSWORD, help="password to encrypt with / find")
    d.set_defaults(func=_cmd_demo)

    c = sub.add_parser(
        "crack", help="weakly encrypt once at a given iteration count, then brute-force it")
    c.add_argument("--iterations", type=int, default=1_000,
                   help="PBKDF2 iteration count (default: 1000)")
    c.add_argument("--wordlist", default="wordlist.txt",
                   help="password list, one per line (default: wordlist.txt)")
    c.add_argument("--secret", default=DEFAULT_SECRET, help="plaintext to encrypt")
    c.add_argument("--password", default=DEFAULT_PASSWORD, help="password to encrypt with / find")
    c.set_defaults(func=_cmd_crack)

    args = parser.parse_args(argv)
    if args.command is None:          # bare `crypto_demo.py` -> run the demo with defaults
        args = parser.parse_args(["demo"])
    args.func(args)


if __name__ == "__main__":
    main()
