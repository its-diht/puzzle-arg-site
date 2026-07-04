#!/usr/bin/env python3
"""
build.py -- generates encrypted, gated stage pages for the ARG.

Each stage is unlocked by the answer to the *previous* stage:
    folder name    = sha256(normalize(previous_answer))[:32]
    encryption key = normalize(previous_answer)

Requires: pip install cryptography
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match the constants in unlock.js exactly.
PBKDF2_ITERATIONS = 250_000
SALT_LEN = 16   # bytes
IV_LEN = 12     # bytes, required nonce length for AES-GCM
KEY_LEN = 32    # bytes -> AES-256

OUTPUT_DIR = "."                  # site root; stage -> <OUTPUT_DIR>/<hash>/index.html
UNLOCK_JS_PATH = "../unlock.js"   # relative path from a stage page to the shared script


def normalize(answer: str) -> str:
    """lowercase + strip whitespace -- must match normalize() in unlock.js"""
    return answer.strip().lower()


def stage_hash(previous_answer: str) -> str:
    digest = hashlib.sha256(normalize(previous_answer).encode("utf-8")).hexdigest()
    return digest[:32]


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_LEN
    )


def encrypt_html(html: str, key: bytes, salt: bytes) -> dict:
    iv = os.urandom(IV_LEN)
    ciphertext = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)  # tag appended
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iterations": PBKDF2_ITERATIONS,
    }


def encrypt_asset(data: bytes, key: bytes) -> bytes:
    """Encrypts a binary asset with the same key as the page. Output format is
    iv (12 bytes) || ciphertext+tag, written raw -- no base64, no bloat.
    unlock.js slices the iv back off the front after fetch()."""
    iv = os.urandom(IV_LEN)
    ciphertext = AESGCM(key).encrypt(iv, data, None)
    return iv + ciphertext


STAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title>Locked</title>
<style>
  body {{ font-family: monospace; max-width: 32em; margin: 4em auto; padding: 0 1em; }}
  #unlock-form {{ display: flex; gap: .5em; }}
  input[type=text] {{ flex: 1; font: inherit; padding: .4em; }}
  #unlock-error {{ color: #b00; min-height: 1.2em; }}
</style>
</head>
<body>
  <div id="lock-screen">
    <p>This stage is locked. Enter the previous answer to continue.</p>
    <form id="unlock-form">
      <input type="text" id="unlock-input" autocomplete="off" autofocus>
      <button type="submit">Unlock</button>
    </form>
    <p id="unlock-error"></p>
  </div>

  <script id="stage-data" type="application/json">{payload_json}</script>
  <script src="{unlock_js_path}" defer></script>
</body>
</html>
"""


# The front page is the entry point: it lives at the site *root* (not a hashed
# folder) and has no "previous answer" -- it's unlocked by a standalone passcode
# you distribute (typed into the form, or auto-applied via a #fragment on the
# shared entry URL). Same crypto as a stage; only the chrome differs.
FRONT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title></title>
<style>
  html, body {{ margin: 0; height: 100%; background: #000; }}
  body {{
    display: flex; align-items: center; justify-content: center;
    font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
    color: #bbb;
  }}
  #lock-screen {{ text-align: center; padding: 1.5em; }}
  #lock-screen p.prompt {{ margin: 0 0 1em; letter-spacing: .18em;
    text-transform: uppercase; font-size: .8rem; color: #777; }}
  #unlock-form {{ display: inline-flex; gap: .5em; }}
  #unlock-input {{
    font: inherit; padding: .55em .7em; width: 12em;
    background: #0d0d0d; border: 1px solid #333; color: #eee; border-radius: 3px;
    outline: none; text-align: center; letter-spacing: .1em;
  }}
  #unlock-input:focus {{ border-color: #666; }}
  #unlock-form button {{
    font: inherit; padding: .55em 1em; cursor: pointer;
    background: #eee; border: none; color: #111; border-radius: 3px;
  }}
  #unlock-error {{ color: #a33; min-height: 1.2em; margin-top: .8em; font-size: .8rem; }}
</style>
</head>
<body>
  <div id="lock-screen">
    <p class="prompt">enter passcode</p>
    <form id="unlock-form">
      <input type="text" id="unlock-input" autocomplete="off" autofocus spellcheck="false">
      <button type="submit">&rarr;</button>
    </form>
    <p id="unlock-error"></p>
  </div>

  <script id="stage-data" type="application/json">{payload_json}</script>
  <script src="{unlock_js_path}" defer></script>
</body>
</html>
"""


def render_stage_html(payload: dict, template: str = STAGE_TEMPLATE,
                      unlock_js_path: str = UNLOCK_JS_PATH) -> str:
    return template.format(
        payload_json=json.dumps(payload),
        unlock_js_path=unlock_js_path,
    )


def build_stage(previous_answer: str, source_html: str, assets=None, output_dir: str = OUTPUT_DIR) -> str:
    """Encrypts source_html (and any binary assets) with key=normalize(previous_answer)
    and writes them to <output_dir>/<sha256(normalize(previous_answer))[:32]>/:
        index.html          -- encrypted page (AES-GCM, PBKDF2-derived key)
        <asset>.enc          -- encrypted binary asset, same key, own random iv
    Assets are read from content/<asset>. Returns the folder name (hash) written.
    """
    folder = stage_hash(previous_answer)
    password = normalize(previous_answer)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)

    stage_dir = os.path.join(output_dir, folder)
    os.makedirs(stage_dir, exist_ok=True)

    payload = encrypt_html(source_html, key, salt)
    with open(os.path.join(stage_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_stage_html(payload))

    for asset in assets or []:
        with open(os.path.join("content", asset), "rb") as f:
            data = f.read()
        encrypted = encrypt_asset(data, key)
        with open(os.path.join(stage_dir, asset + ".enc"), "wb") as f:
            f.write(encrypted)

    return folder


def build_front(passcode: str, source_html: str, assets=None, output_dir: str = OUTPUT_DIR) -> None:
    """Encrypts the front page (source_html + any assets) with key=normalize(passcode)
    and writes them to the site *root*:
        index.html          -- encrypted decryptor shell (unlock.js referenced at root)
        <asset>.enc          -- encrypted binary asset (e.g. qr.png.enc), same key
    Unlike a stage, the front page has no hashed folder -- it *is* the entry URL.
    Assets are read from content/<asset>. Nothing plaintext is written."""
    password = normalize(passcode)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)

    os.makedirs(output_dir, exist_ok=True)
    payload = encrypt_html(source_html, key, salt)
    with open(os.path.join(output_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_stage_html(payload, template=FRONT_TEMPLATE, unlock_js_path="unlock.js"))

    for asset in assets or []:
        with open(os.path.join("content", asset), "rb") as f:
            data = f.read()
        with open(os.path.join(output_dir, asset + ".enc"), "wb") as f:
            f.write(encrypt_asset(data, key))

    asset_note = f" (+{len(assets)} asset(s))" if assets else ""
    print(f"[+] front page passcode={passcode!r:20} -> /index.html{asset_note}")


def build_all(triples, output_dir: str = OUTPUT_DIR):
    results = []
    for previous_answer, source_html, assets in triples:
        folder = build_stage(previous_answer, source_html, assets, output_dir)
        results.append((previous_answer, folder))
        asset_note = f" (+{len(assets)} asset(s))" if assets else ""
        print(f"[+] answer={previous_answer!r:30} -> /{folder}/index.html{asset_note}")
    return results


def load(name: str) -> str:
    with open(os.path.join("content", name), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    # STAGES (answers + content) live in stages_local.py, which is gitignored
    # and never committed -- see stages_local.py.example for the format.
    try:
        from stages_local import STAGES, FRONT
    except ImportError:
        raise SystemExit(
            "stages_local.py not found (or missing STAGES/FRONT).\n"
            "Copy stages_local.py.example to stages_local.py and fill in "
            "your real answers/content. That file is gitignored -- keep it "
            "that way, it must never be committed."
        )
    build_front(*FRONT)
    build_all(STAGES)
