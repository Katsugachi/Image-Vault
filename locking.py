#!/usr/bin/env python3
"""
generate_locked_page.py
-----------------------
Generates a self-contained, password-locked HTML page that reveals a hidden
image only when the correct password is entered.

Encryption scheme (mirrors the HTML page exactly):
  - Key derivation : PBKDF2-HMAC-SHA256, 200 000 iterations
  - Cipher         : AES-256-GCM
  - Payload format : "<mime_type>|<base64_image>" (UTF-8, then encrypted)
  - All binary blobs stored as standard Base64 inside the HTML

Usage:
  python generate_locked_page.py

  The script will interactively prompt for:
    - Image path   (input hidden from terminal history)
    - Password     (input hidden, confirmed twice)
    - Output name  (optional, defaults to <image_basename>_locked.html)
"""

import base64
import hashlib
import mimetypes
import os
import secrets
import sys


# ---------------------------------------------------------------------------
# Pure-Python AES-GCM implementation helpers
# ---------------------------------------------------------------------------
# We use the `cryptography` library when available (fastest, correct).
# Fall back to `pycryptodome` (Crypto.Cipher.AES), then abort with a clear
# message rather than rolling our own crypto primitives.

def _encrypt_aes_gcm(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Return AES-256-GCM ciphertext+tag (tag appended, 16 bytes)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        # cryptography appends the 16-byte tag automatically
        return aesgcm.encrypt(iv, plaintext, None)
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES  # pycryptodome
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext + tag
    except ImportError:
        pass

    sys.exit(
        "\n[ERROR] A crypto library is required.\n"
        "Install one with:\n"
        "    pip install cryptography\n"
        "or:\n"
        "    pip install pycryptodome\n"
    )


def _pbkdf2(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256 (stdlib, no deps)."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


# ---------------------------------------------------------------------------
# MIME detection
# ---------------------------------------------------------------------------
_MAGIC = [
    (b"\x89PNG\r\n\x1a\n",          "image/png"),
    (b"\xff\xd8\xff",               "image/jpeg"),
    (b"GIF87a",                     "image/gif"),
    (b"GIF89a",                     "image/gif"),
    (b"RIFF",                       "image/webp"),   # checked further below
    (b"BM",                         "image/bmp"),
    (b"\x49\x49\x2a\x00",          "image/tiff"),
    (b"\x4d\x4d\x00\x2a",          "image/tiff"),
]

def _detect_mime(path: str) -> str:
    """Return the MIME type by inspecting magic bytes, no third-party libs."""
    with open(path, "rb") as f:
        header = f.read(16)

    for magic, mime in _MAGIC:
        if header[:len(magic)] == magic:
            # Disambiguate RIFF: could be WebP or WAV etc.
            if mime == "image/webp" and header[8:12] != b"WEBP":
                continue
            return mime

    # Last resort: extension guess
    mime, _ = mimetypes.guess_type(path)
    if mime and mime.startswith("image/"):
        return mime

    sys.exit(
        f"\n[ERROR] Could not determine image type for '{path}'.\n"
        "Supported formats: PNG, JPEG, GIF, WebP, BMP, TIFF.\n"
    )


# ---------------------------------------------------------------------------
# Encryption pipeline
# ---------------------------------------------------------------------------

def encrypt_image(image_path: str, password: str) -> dict:
    """
    Read *image_path*, encrypt with *password*, return a dict with keys:
      salt  – base64 string (16 bytes random)
      iv    – base64 string (12 bytes random, standard for AES-GCM)
      data  – base64 string (ciphertext + 16-byte GCM tag)
    """
    if not os.path.isfile(image_path):
        sys.exit(f"\n[ERROR] Image file not found: '{image_path}'\n")

    mime = _detect_mime(image_path)

    with open(image_path, "rb") as f:
        raw = f.read()

    if not raw:
        sys.exit(f"\n[ERROR] Image file is empty: '{image_path}'\n")

    img_b64 = base64.b64encode(raw).decode("ascii")

    # Payload mirrors the JS decoder: "<mime>|<base64_image>"
    payload = f"{mime}|{img_b64}".encode("utf-8")

    # 16-byte salt (PBKDF2), 12-byte IV (AES-GCM standard nonce length)
    salt = secrets.token_bytes(16)
    iv   = secrets.token_bytes(12)

    key        = _pbkdf2(password, salt)
    ciphertext = _encrypt_aes_gcm(key, iv, payload)

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv":   base64.b64encode(iv).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# HTML template (exact visual replica of the original)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Locked</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    min-height: 100vh;
    background: #1e1e3c;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: Arial, sans-serif;
  }}
  #lock-screen {{
    text-align: center;
    padding: 40px;
    background: #2a2a50;
    border-radius: 20px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    width: 320px;
  }}
  .lock-icon {{ margin-bottom: 12px; line-height: 1; }}
  h2 {{ color: #ccccff; font-size: 16px; margin-bottom: 24px; font-weight: normal; }}
  input {{
    width: 100%;
    padding: 12px;
    font-size: 16px;
    border: none;
    border-radius: 10px;
    background: #1e1e3c;
    color: white;
    text-align: center;
    outline: none;
    letter-spacing: 2px;
    margin-bottom: 14px;
  }}
  input::placeholder {{ letter-spacing: normal; color: #666; }}
  button {{
    width: 100%;
    padding: 12px;
    background: #ffd700;
    color: #1e1e3c;
    font-size: 15px;
    font-weight: bold;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.2s;
  }}
  button:hover {{ background: #ffec6e; }}
  button:disabled {{ background: #888; cursor: default; }}
  .error {{ color: #ff6b6b; margin-top: 12px; font-size: 14px; display: none; align-items: center; justify-content: center; }}
  #image-screen {{
    display: none;
    text-align: center;
    padding: 30px;
    background: #2a2a50;
    border-radius: 20px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    max-width: 90vw;
  }}
  #image-screen img {{
    max-width: 100%;
    max-height: 80vh;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  }}
  .unlocked-label {{ color: #ffd700; font-size: 18px; margin-bottom: 16px; display: flex; align-items: center; justify-content: center; }}
</style>
</head>
<body>
<div id="lock-screen">
  <div class="lock-icon"><svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#ffd700" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
  <h2>Enter password to view image</h2>
  <input type="password" id="pw" placeholder="Password" onkeydown="if(event.key==='Enter') unlock()">
  <button id="btn" onclick="unlock()">Unlock</button>
  <div class="error" id="err"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff6b6b" stroke-width="2.5" stroke-linecap="round" style="vertical-align:middle;margin-right:5px"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Wrong password. Try again.</div>
</div>
<div id="image-screen">
  <div class="unlocked-label"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ffd700" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> Unlocked!</div>
  <img id="secret-img" src="" alt="Secret Image">
</div>
<script>
const ENCRYPTED = {{
  salt: "{salt}",
  iv:   "{iv}",
  data: "{data}"
}};
function b64ToBytes(b64) {{
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}}
async function unlock() {{
  const password = document.getElementById("pw").value;
  if (!password) return;
  const btn = document.getElementById("btn");
  btn.disabled = true; btn.textContent = "Decrypting...";
  document.getElementById("err").style.display = "none";
  try {{
    const keyMaterial = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      {{ name: "PBKDF2", salt: b64ToBytes(ENCRYPTED.salt), iterations: 200000, hash: "SHA-256" }},
      keyMaterial, {{ name: "AES-GCM", length: 256 }}, false, ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      {{ name: "AES-GCM", iv: b64ToBytes(ENCRYPTED.iv) }}, key, b64ToBytes(ENCRYPTED.data)
    );
    const text = new TextDecoder().decode(decrypted);
    const [mime, imgB64] = text.split("|");
    document.getElementById("secret-img").src = "data:" + mime + ";base64," + imgB64;
    document.getElementById("lock-screen").style.display = "none";
    document.getElementById("image-screen").style.display = "block";
  }} catch (e) {{
    document.getElementById("err").style.display = "flex";
    document.getElementById("pw").value = "";
    document.getElementById("pw").focus();
    btn.disabled = false; btn.textContent = "Unlock";
  }}
}}
document.getElementById("pw").focus();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("\n=== Locked Image Page Generator ===\n")

    # Image path
    while True:
        image_path = input("  Image path   : ").strip().strip('"').strip("'")
        if not image_path:
            print("  [!] Path cannot be empty.")
            continue
        if not os.path.isfile(image_path):
            print(f"  [!] File not found: '{image_path}'")
            continue
        break

    # Password
    while True:
        password = input("  Password      : ")
        if not password:
            print("  [!] Password cannot be empty.")
            continue
        break

    # Output filename
    base = os.path.splitext(os.path.basename(image_path))[0]
    default = f"{base}_locked.html"
    raw = input(f"  Output file   [{default}]: ").strip()
    out_path = raw if raw else default

    print(f"\n[*] Encrypting … ", end="", flush=True)
    enc = encrypt_image(image_path, password)
    print("done.")

    html = HTML_TEMPLATE.format(
        salt=enc["salt"],
        iv=enc["iv"],
        data=enc["data"],
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"[✓] Written: {out_path}  ({size_kb:.1f} KB)")
    print(f"[✓] Open in any modern browser and enter your password to unlock.\n")


if __name__ == "__main__":
    main()
