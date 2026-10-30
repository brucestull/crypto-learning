# crypto-demo

A small teaching module contrasting two ways to encrypt a text string in Python:

- **Strong** — password → **Argon2id** key derivation → **AES-256-GCM** authenticated
  encryption. Returns one self-describing bundle (algorithm, KDF params, salt, nonce,
  ciphertext+tag) with everything needed to decrypt later. The password is the only secret.
- **Weak** (on purpose) — password → **PBKDF2-HMAC-SHA256** with a *tunable* iteration
  count → XOR keystream, plus a brute-force cracker that times itself. Lower the iterations
  and watch cracking speed up. It exists only to be broken — never ship it.

## Project layout

```
crypto-demo/
├── crypto_demo.py     # the module + CLI (demo / crack subcommands)
├── wordlist.txt       # tiny demo dictionary (contains "hunter2" so the crack lands)
├── pyproject.toml     # uv/PEP 621 project + console-script entry point
├── .python-version    # pins the interpreter uv uses (3.12)
├── .gitignore
└── README.md
```

## Requirements

- Python 3.9+ (the project pins **3.12** via `.python-version`; uv will fetch it if missing)
- [uv](https://docs.astral.sh/uv/) (recommended) — or plain `venv` + `pip`
- Dependencies: `cryptography`, `argon2-cffi` (PBKDF2 and XOR are stdlib-only)

Install uv (once, user-local — no sudo, nothing global):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Setup with uv (nothing installed globally)

uv keeps everything in a project-local `.venv/`. Your system Python stays untouched —
exactly what you want on REACT-NODES.

```bash
cd crypto-demo
uv sync          # creates .venv/, installs deps + this project, writes uv.lock
```

`uv sync` reads `pyproject.toml`, resolves, locks, and installs — all inside the project.
Because `pyproject.toml` now declares a `[project.scripts]` entry, this project is an
installable package: `uv sync` also installs it (editable) into the venv, so the
`crypto-demo` command becomes available. (First run also downloads CPython 3.12 if your
system Python doesn't match; it still never touches system packages.)

## Running the app

Two equivalent ways — the console script, or the module directly:

```bash
# Console script (from the [project.scripts] entry point)
uv run crypto-demo demo
uv run crypto-demo crack --iterations 500000

# Or run the file directly
uv run python crypto_demo.py demo
```

Common invocations:

```bash
# Full demo: strong round-trip, then crack the weak scheme at several iteration counts
uv run crypto-demo demo

# Pick your own iteration counts (shows the timing curve more sharply)
uv run crypto-demo demo --iterations 1000 50000 200000

# Point at a different wordlist / secret / password
uv run crypto-demo demo --wordlist wordlist.txt --secret "meet at noon" --password letmein

# Single dictionary attack at one iteration count (verbose)
uv run crypto-demo crack --iterations 1000
uv run crypto-demo crack --iterations 500000   # feel the per-guess cost climb
```

Bare `uv run crypto-demo` (no subcommand) runs `demo` with defaults.

Expected demo output (times depend on your CPU — a Pi will be slower):

```
=== STRONG (Argon2id + AES-256-GCM) ===
stored bundle: eyJhbGciOiJBRVMtMjU2LUdDTSIsImtkZiI6ImFyZ29uMmlk... ...
decrypted:     the treasure is buried under the old oak tree
wrong password rejected: InvalidTag

=== WEAK (PBKDF2 tunable iters + XOR) — dictionary of 47 words ===
  iterations |  time (s) |    guesses/s | cracked
--------------------------------------------------------
         100 |     0.002 |       18,000 | 'hunter2'
       1,000 |     0.020 |        2,000 | 'hunter2'
      10,000 |     0.172 |          226 | 'hunter2'
     100,000 |     1.700 |           23 | 'hunter2'
```

`guesses/sec` is the number to watch: it drops ~10x for every ~10x on iterations, and
that cost is paid *per guess*. Argon2id (the strong path) adds a **memory** cost on top,
which is what defeats GPU/ASIC cracking that PBKDF2 alone can't.

## Useful uv commands

```bash
uv sync                      # install/refresh deps + project into .venv
uv add requests              # add a dependency (updates pyproject.toml + uv.lock)
uv remove requests           # drop one
uv lock                      # re-resolve and update uv.lock
uv run <cmd>                 # run a command in the project venv
uv run python -V             # confirm which Python the venv uses
uv python pin 3.13           # change the pinned interpreter (rewrites .python-version)
uv venv                      # (re)create .venv manually if you ever need to
```

## Coming from Pipenv

| Pipenv | uv |
|---|---|
| `pipenv install` | `uv sync` |
| `pipenv install <pkg>` | `uv add <pkg>` |
| `pipenv uninstall <pkg>` | `uv remove <pkg>` |
| `pipenv run <cmd>` | `uv run <cmd>` |
| `pipenv shell` | `source .venv/bin/activate` (or just use `uv run`) |
| `pipenv lock` | `uv lock` |
| `Pipfile` / `Pipfile.lock` | `pyproject.toml` / `uv.lock` |

Commit `pyproject.toml`, `uv.lock`, and `.python-version`; `.venv/` is gitignored.

## Without uv (plain venv + pip fallback)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .            # installs deps + the crypto-demo command from pyproject.toml
crypto-demo demo           # or: python crypto_demo.py demo
```

## Note for REACT-NODES / Raspberry Pi (aarch64)

`cryptography` and `argon2-cffi` ship prebuilt wheels for 64-bit ARM (`aarch64`), so
`uv sync` normally just downloads them — no compiler needed. If uv ever falls back to
building `cryptography` from source (e.g. a 32-bit OS or an unusual platform), you'll
need a Rust toolchain (`rustup`) and `libffi-dev` / `python3-dev`. Running 64-bit
Raspberry Pi OS avoids this.

## Security note

The weak scheme is intentionally breakable (cheap tunable KDF + unauthenticated XOR with a
known-plaintext canary). Use it to learn how key stretching raises attack cost — never for
anything real. For real work, use the strong functions, or the even simpler
`cryptography.fernet.Fernet` recipe if you don't need AES-256 specifically.
