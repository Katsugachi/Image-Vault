import base64
import hashlib
import secrets
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Locked</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    min-height: 100vh;
    background: #1e1e3c;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: Arial, sans-serif;
  }

  #lock-screen {
    text-align: center;
    padding: 40px;
    background: #2a2a50;
    border-radius: 20px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    width: 320px;
  }

  .lock-icon {
    margin-bottom: 12px;
    line-height: 1;
  }

  h2 {
    color: #ccccff;
    font-size: 16px;
    margin-bottom: 24px;
    font-weight: normal;
  }

  input {
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
  }

  input::placeholder {
    letter-spacing: normal;
    color: #666;
  }

  button {
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
  }

  button:hover {
    background: #ffec6e;
  }

  button:disabled {
    background: #888;
    cursor: default;
  }

  .error {
    color: #ff6b6b;
    margin-top: 12px;
    font-size: 14px;
    display: none;
    align-items: center;
    justify-content: center;
  }

  #image-screen {
    display: none;
    text-align: center;
    padding: 30px;
    background: #2a2a50;
    border-radius: 20px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    max-width: 90vw;
  }

  #image-screen img {
    max-width: 100%;
    max-height: 80vh;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  }

  .unlocked-label {
    color: #ffd700;
    font-size: 18px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
</style>
</head>

<body>

<div id="lock-screen">
  <div class="lock-icon">
    <svg xmlns="http://www.w3.org/2000/svg" width="56" height="56"
      viewBox="0 0 24 24" fill="none" stroke="#ffd700"
      stroke-width="1.8" stroke-linecap="round"
      stroke-linejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  </div>

  <h2>Enter password to view image</h2>

  <input type="password" id="pw" placeholder="Password"
         onkeydown="if(event.key==='Enter') unlock()">

  <button id="btn" onclick="unlock()">Unlock</button>

  <div class="error" id="err">
    Wrong password. Try again.
  </div>
</div>

<div id="image-screen">
  <div class="unlocked-label">
    🔓 Unlocked!
  </div>

  <img id="secret-img" src="" alt="Secret Image">
</div>

<script>
const ENCRYPTED = {
  salt: "__SALT__",
  iv: "__IV__",
  data: "__DATA__"
};

async function deriveKey(password, salt) {
  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: Uint8Array.from(atob(salt), c => c.charCodeAt(0)),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    {
      name: "AES-CBC",
      length: 256
    },
    false,
    ["decrypt"]
  );
}

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function unlock() {
  const pw = document.getElementById("pw").value;
  const err = document.getElementById("err");

  err.style.display = "none";

  try {
    const key = await deriveKey(pw, ENCRYPTED.salt);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: b64ToBytes(ENCRYPTED.iv)
      },
      key,
      b64ToBytes(ENCRYPTED.data)
    );

    const bytes = new Uint8Array(decrypted);

    let pad = bytes[bytes.length - 1];
    const unpadded = bytes.slice(0, bytes.length - pad);

    const decoder = new TextDecoder();
    const imageData = decoder.decode(unpadded);

    document.getElementById("secret-img").src = imageData;

    document.getElementById("lock-screen").style.display = "none";
    document.getElementById("image-screen").style.display = "block";

  } catch {
    err.style.display = "flex";
  }
}
</script>

</body>
</html>
'''

def encrypt_image(image_path: str, password: str):
    image_bytes = Path(image_path).read_bytes()

    ext = Path(image_path).suffix.lower().replace(".", "")
    mime = f"image/{'jpeg' if ext == 'jpg' else ext}"

    data_url = (
        f"data:{mime};base64,"
        + base64.b64encode(image_bytes).decode()
    )

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    key = PBKDF2(
        password,
        salt,
        dkLen=32,
        count=100000,
        hmac_hash_module=hashlib.sha256
    )

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data_url.encode(), AES.block_size))

    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(encrypted).decode()
    }


def build_html(image_path: str, password: str, output_file="locked_image.html"):
    encrypted = encrypt_image(image_path, password)

    html = (
        HTML_TEMPLATE
        .replace("__SALT__", encrypted["salt"])
        .replace("__IV__", encrypted["iv"])
        .replace("__DATA__", encrypted["data"])
    )

    Path(output_file).write_text(html, encoding="utf-8")

    print(f"[+] Created: {output_file}")


if __name__ == "__main__":
    image_path = input("Image path: ").strip()
    password = input("Password: ").strip()

    build_html(image_path, password)