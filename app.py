from flask import Flask, render_template, request
import string
import numpy as np
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

ALPHABET = string.ascii_uppercase
ALPHABET_LEN = len(ALPHABET)


def normalize_text(text):
    """Convert text to uppercase and keep only A–Z letters."""
    return ''.join(ch for ch in text.upper() if ch in ALPHABET)


# ---------------- Caesar cipher ----------------
def caesar_encrypt(plaintext, key):
    """Encrypt plaintext by shifting each letter forward by key positions."""
    key = int(key) % ALPHABET_LEN
    result = []
    for ch in plaintext:
        if ch.upper() in ALPHABET:
            idx = ALPHABET.index(ch.upper())
            enc = ALPHABET[(idx + key) % ALPHABET_LEN]
            result.append(enc if ch.isupper() else enc.lower())
        else:
            result.append(ch)
    return ''.join(result)
def caesar_decrypt(ciphertext, key):
    """Decrypt a Caesar ciphertext by shifting letters backward by key."""
    return caesar_encrypt(ciphertext, -int(key))


# ---------------- Hill cipher (2x2) ----------------
def text_to_numbers(text):
    """Map normalized A–Z text to a list of numbers 0–25."""
    return [ALPHABET.index(ch) for ch in normalize_text(text)]


def numbers_to_text(nums):
    """Convert a list of numbers 0–25 back into A–Z text."""
    return ''.join(ALPHABET[n % ALPHABET_LEN] for n in nums)


def parse_hill_key(key_str):
    """
    Expect key as four integers separated by spaces or commas, e.g. '3 3 2 5'
    Returns 2x2 numpy matrix modulo 26.
    """
    parts = key_str.replace(',', ' ').split()
    if len(parts) != 4:
        raise ValueError("Hill cipher key must have 4 integers for a 2x2 matrix.")
    nums = [int(p) % ALPHABET_LEN for p in parts]
    mat = np.array(nums).reshape(2, 2)
    det = int(round(np.linalg.det(mat))) % ALPHABET_LEN
    if np.gcd(det, ALPHABET_LEN) != 1:
        raise ValueError("Hill matrix determinant must be coprime with 26.")
    return mat


def modinv(a, m):
    """Compute the modular inverse of a modulo m by brute force search."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse.")


def hill_encrypt(plaintext, key_str):
    """Encrypt plaintext with a 2x2 Hill matrix (linear algebra mod 26)."""
    key = parse_hill_key(key_str)
    nums = text_to_numbers(plaintext)
    # pad with X if needed
    if len(nums) % 2 == 1:
        nums.append(ALPHABET.index('X'))
    result = []
    for i in range(0, len(nums), 2):
        vec = np.array(nums[i:i + 2]).reshape(2, 1)
        enc_vec = key.dot(vec) % ALPHABET_LEN
        result.extend(int(x) for x in enc_vec.flatten())
    return numbers_to_text(result)


def hill_decrypt(ciphertext, key_str):
    """Decrypt Hill ciphertext using the inverse of the 2x2 key matrix."""
    key = parse_hill_key(key_str)
    det = int(round(np.linalg.det(key))) % ALPHABET_LEN
    det_inv = modinv(det, ALPHABET_LEN)
    # adjugate matrix
    adj = np.array([[key[1, 1], -key[0, 1]],
                    [-key[1, 0], key[0, 0]]])
    inv_key = (det_inv * adj) % ALPHABET_LEN
    nums = text_to_numbers(ciphertext)
    if len(nums) % 2 == 1:
        nums.append(ALPHABET.index('X'))
    result = []
    for i in range(0, len(nums), 2):
        vec = np.array(nums[i:i + 2]).reshape(2, 1)
        dec_vec = inv_key.dot(vec) % ALPHABET_LEN
        result.extend(int(x) for x in dec_vec.flatten())
    return numbers_to_text(result)


# ---------------- Vigenere cipher ----------------
def vigenere_encrypt(plaintext, key):
    """Encrypt text with the Vigenère cipher (changing Caesar shifts from key)."""
    key = normalize_text(key)
    if not key:
        raise ValueError("Vigenere key must contain letters A–Z, e.g. LEMON. For numeric keys use the Hill cipher.")
    result = []
    j = 0
    for ch in plaintext:
        if ch.upper() in ALPHABET:
            p_idx = ALPHABET.index(ch.upper())
            k_idx = ALPHABET.index(key[j % len(key)])
            enc = ALPHABET[(p_idx + k_idx) % ALPHABET_LEN]
            result.append(enc if ch.isupper() else enc.lower())
            j += 1
        else:
            result.append(ch)
    return ''.join(result)
def vigenere_decrypt(ciphertext, key):
    """Reverse Vigenère encryption using the same alphabetic key."""
    key = normalize_text(key)
    if not key:
        raise ValueError("Vigenere key must contain letters A–Z, e.g. LEMON. For numeric keys use the Hill cipher.")
    result = []
    j = 0
    for ch in ciphertext:
        if ch.upper() in ALPHABET:
            c_idx = ALPHABET.index(ch.upper())
            k_idx = ALPHABET.index(key[j % len(key)])
            dec = ALPHABET[(c_idx - k_idx) % ALPHABET_LEN]
            result.append(dec if ch.isupper() else dec.lower())
            j += 1
        else:
            result.append(ch)
    return ''.join(result)


# ---------------- Playfair cipher ----------------
def generate_playfair_square(key):
    """Build the 5x5 Playfair key square from a keyword."""
    key = normalize_text(key).replace('J', 'I')
    seen = set()
    square = []
    for ch in key + ALPHABET.replace('J', ''):
        if ch not in seen and ch != 'J':
            seen.add(ch)
            square.append(ch)
    # 5x5 matrix
    return [square[i:i + 5] for i in range(0, 25, 5)]
def find_position(square, ch):
    """Return row and column of a character inside the Playfair square."""
    ch = 'I' if ch == 'J' else ch
    for r in range(5):
        for c in range(5):
            if square[r][c] == ch:
                return r, c
    raise ValueError("Character not in Playfair square.")
def prepare_playfair_text(text, for_encrypt=True):
    """Normalize and split text into Playfair digraph-ready form (with X padding)."""
    text = normalize_text(text).replace('J', 'I')
    if not for_encrypt:
        return text
    result = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i + 1]
        if a == b:
            result.append(a)
            result.append('X')
            i += 1
        else:
            result.append(a)
            if b:
                result.append(b)
                i += 2
            else:
                i += 1
    if len(result) % 2 == 1:
        result.append('X')
    return ''.join(result)
def playfair_process(text, key, encrypt=True):
    """Core Playfair routine: apply row/column/rectangle rules over digraphs."""
    square = generate_playfair_square(key)
    text = prepare_playfair_text(text, for_encrypt=encrypt)
    result = []
    step = 1 if encrypt else -1
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]
        r1, c1 = find_position(square, a)
        r2, c2 = find_position(square, b)
        if r1 == r2:
            # same row
            result.append(square[r1][(c1 + step) % 5])
            result.append(square[r2][(c2 + step) % 5])
        elif c1 == c2:
            # same column
            result.append(square[(r1 + step) % 5][c1])
            result.append(square[(r2 + step) % 5][c2])
        else:
            # rectangle
            result.append(square[r1][c2])
            result.append(square[r2][c1])
    return ''.join(result)
def playfair_encrypt(plaintext, key):
    """Encrypt text using the Playfair cipher."""
    return playfair_process(plaintext, key, encrypt=True)


def playfair_decrypt(ciphertext, key):
    """Decrypt Playfair ciphertext and attempt to remove padding X characters."""
    # For decryption, skip text preparation for digraph rules
    square = generate_playfair_square(key)
    text = normalize_text(ciphertext).replace('J', 'I')
    result = []
    step = -1
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]
        r1, c1 = find_position(square, a)
        r2, c2 = find_position(square, b)
        if r1 == r2:
            result.append(square[r1][(c1 + step) % 5])
            result.append(square[r2][(c2 + step) % 5])
        elif c1 == c2:
            result.append(square[(r1 + step) % 5][c1])
            result.append(square[(r2 + step) % 5][c2])
        else:
            result.append(square[r1][c2])
            result.append(square[r2][c1])

    # Try to remove padding 'X' characters that were inserted during encryption
    plaintext = ''.join(result)
    cleaned = []
    i = 0
    while i < len(plaintext):
        # If we see pattern A X A, drop the X (typical Playfair padding between double letters)
        if i + 2 < len(plaintext) and plaintext[i] == plaintext[i + 2] and plaintext[i + 1] == 'X':
            cleaned.append(plaintext[i])
            i += 2  # skip the X
        else:
            cleaned.append(plaintext[i])
            i += 1

    # Drop a single trailing X which is very often just padding
    if cleaned and cleaned[-1] == 'X':
        cleaned.pop()

    return ''.join(cleaned)


# ---------------- Modern block ciphers: DES, AES, Blowfish ----------------
def _derive_key(key_str, algorithm):
    """
    Derive a fixed‑size binary key from an arbitrary passphrase.
    This is purely for demo purposes and is NOT secure practice.
    """
    digest = SHA256.new(key_str.encode("utf-8")).digest()
    if algorithm == "aes":
        # 32‑byte key (AES‑256)
        return digest
    elif algorithm == "des":
        # 8‑byte key
        return digest[:8]
    elif algorithm == "blowfish":
        # 16‑byte key (Blowfish supports 4‑56 bytes)
        return digest[:16]
    else:
        raise ValueError("Unsupported algorithm for key derivation.")
def _symmetric_encrypt(plaintext, key_str, algorithm):
    """Encrypt UTF‑8 text with the chosen block cipher and return hex ciphertext."""
    data = plaintext.encode("utf-8")
    if algorithm == "aes":
        key = _derive_key(key_str, "aes")
        cipher = AES.new(key, AES.MODE_ECB)
        block_size = AES.block_size
    elif algorithm == "des":
        key = _derive_key(key_str, "des")
        cipher = DES.new(key, DES.MODE_ECB)
        block_size = DES.block_size
    elif algorithm == "blowfish":
        key = _derive_key(key_str, "blowfish")
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        block_size = Blowfish.block_size
    else:
        raise ValueError("Unknown block cipher.")

    enc_bytes = cipher.encrypt(pad(data, block_size))
    # Represent as hex so it fits nicely in the text box
    return enc_bytes.hex()
def _symmetric_decrypt(ciphertext_hex, key_str, algorithm):
    """Decrypt hex ciphertext produced by _symmetric_encrypt back to text."""
    try:
        enc = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        raise ValueError("Ciphertext must be a hexadecimal string produced by the encrypt step.")

    if algorithm == "aes":
        key = _derive_key(key_str, "aes")
        cipher = AES.new(key, AES.MODE_ECB)
        block_size = AES.block_size
    elif algorithm == "des":
        key = _derive_key(key_str, "des")
        cipher = DES.new(key, DES.MODE_ECB)
        block_size = DES.block_size
    elif algorithm == "blowfish":
        key = _derive_key(key_str, "blowfish")
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        block_size = Blowfish.block_size
    else:
        raise ValueError("Unknown block cipher.")

    try:
        data = unpad(cipher.decrypt(enc), block_size)
    except ValueError:
        raise ValueError("Invalid padding or key for this ciphertext.")

    return data.decode("utf-8", errors="replace")
def des_encrypt(plaintext, key_str):
    """User-facing helper: DES encrypt plaintext with a passphrase."""
    return _symmetric_encrypt(plaintext, key_str, "des")


def des_decrypt(ciphertext, key_str):
    """User-facing helper: DES decrypt hex ciphertext with a passphrase."""
    return _symmetric_decrypt(ciphertext, key_str, "des")


def aes_encrypt(plaintext, key_str):
    """User-facing helper: AES encrypt plaintext with a passphrase."""
    return _symmetric_encrypt(plaintext, key_str, "aes")


def aes_decrypt(ciphertext, key_str):
    """User-facing helper: AES decrypt hex ciphertext with a passphrase."""
    return _symmetric_decrypt(ciphertext, key_str, "aes")


def blowfish_encrypt(plaintext, key_str):
    """User-facing helper: Blowfish encrypt plaintext with a passphrase."""
    return _symmetric_encrypt(plaintext, key_str, "blowfish")


def blowfish_decrypt(ciphertext, key_str):
    """User-facing helper: Blowfish decrypt hex ciphertext with a passphrase."""
    return _symmetric_decrypt(ciphertext, key_str, "blowfish")


# ---------------- Toy RSA (for demonstration only) ----------------
def parse_rsa_key(key_str):
    """
    Parse p, q, e and build a tiny RSA key pair (n, e, d) for demo purposes.
    Expect key as three integers p, q, e separated by spaces or commas, e.g. '61 53 17'.
    Not secure and only for small demo primes.
    """
    parts = key_str.replace(",", " ").split()
    if len(parts) != 3:
        raise ValueError(
            "RSA key must have exactly 3 integers: p q e, e.g. '61 53 17'."
        )
    p, q, e = map(int, parts)
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be primes greater than 1 for toy RSA.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if np.gcd(e, phi) != 1:
        raise ValueError("e must be coprime with (p-1)(q-1).")
    d = modinv(e, phi)
    return n, e, d


def rsa_encrypt(plaintext, key_str):
    """Encrypt each character code with toy RSA; output space‑separated integers."""
    n, e, _ = parse_rsa_key(key_str)
    nums = []
    for ch in plaintext:
        m = ord(ch)
        if m >= n:
            raise ValueError(
                "For this toy RSA, n must be larger than all character codes in the message."
            )
        c = pow(m, e, n)
        nums.append(str(c))
    return " ".join(nums)


def rsa_decrypt(ciphertext, key_str):
    """Decrypt space‑separated RSA integers back into a text string."""
    n, _, d = parse_rsa_key(key_str)
    parts = ciphertext.replace(",", " ").split()
    chars = []
    for token in parts:
        if not token.strip():
            continue
        c = int(token)
        m = pow(c, d, n)
        chars.append(chr(m))
    return "".join(chars)


@app.route("/", methods=["GET", "POST"])
def index():
    """Main Flask view: route form inputs to the selected cipher and render the result."""
    result = ""
    error = ""
    text = ""
    key = ""
    cipher = "caesar"
    mode = "encrypt"
    if request.method == "POST":
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        cipher = request.form.get("cipher", "caesar")
        mode = request.form.get("mode", "encrypt")
        try:
            if cipher == "caesar":
                result = (
                    caesar_encrypt(text, key)
                    if mode == "encrypt"
                    else caesar_decrypt(text, key)
                )
            elif cipher == "hill":
                result = (
                    hill_encrypt(text, key)
                    if mode == "encrypt"
                    else hill_decrypt(text, key)
                )
            elif cipher == "vigenere":
                result = (
                    vigenere_encrypt(text, key)
                    if mode == "encrypt"
                    else vigenere_decrypt(text, key)
                )
            elif cipher == "playfair":
                result = (
                    playfair_encrypt(text, key)
                    if mode == "encrypt"
                    else playfair_decrypt(text, key)
                )
            elif cipher == "des":
                result = (
                    des_encrypt(text, key)
                    if mode == "encrypt"
                    else des_decrypt(text, key)
                )
            elif cipher == "aes":
                result = (
                    aes_encrypt(text, key)
                    if mode == "encrypt"
                    else aes_decrypt(text, key)
                )
            elif cipher == "blowfish":
                result = (
                    blowfish_encrypt(text, key)
                    if mode == "encrypt"
                    else blowfish_decrypt(text, key)
                )
            elif cipher == "rsa":
                result = (
                    rsa_encrypt(text, key)
                    if mode == "encrypt"
                    else rsa_decrypt(text, key)
                )
        except Exception as e:
            error = str(e)
    return render_template(
        "index.html",
        result=result,
        error=error,
        text_value=text,
        key_value=key,
        cipher_value=cipher,
        mode_value=mode,
    )


if __name__ == "__main__":
    app.run(debug=True)