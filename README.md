# Classical & Modern Cipher Web Tool

This project demonstrates several cryptosystems and how they are implemented in code:

- **Caesar cipher** (encrypt/decrypt)
- **Hill cipher** (2×2 matrix, encrypt/decrypt)
- **Vigenère cipher** (encrypt/decrypt)
- **Playfair cipher** (encrypt/decrypt)
- **DES** (encrypt/decrypt, demo via PyCryptodome)
- **AES** (encrypt/decrypt, demo via PyCryptodome)
- **Blowfish** (encrypt/decrypt, demo via PyCryptodome)
- **Toy RSA** (encrypt/decrypt, small educational example)

## Setup

1. (Optional) Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # macOS / Linux
# or
.venv\\Scripts\\activate   # Windows
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python app.py
```

4. Open the browser at `http://127.0.0.1:5000/`.

## Key formats

- **Caesar**: integer shift, e.g. `3`
- **Hill (2×2)**: 4 integers (matrix) separated by spaces/commas, e.g. `3 3 2 5`
- **Vigenère**: alphabetic word, e.g. `LEMON`
- **Playfair**: alphabetic word, e.g. `MONARCHY`
- **DES / AES / Blowfish**: any text **passphrase**.  
  - Encryption outputs a **hex string** (e.g. `6f2c9a...`).  
  - To decrypt, paste that hex string back as the text with the **same passphrase**.
- **Toy RSA**: three integers `p q e`, e.g. `61 53 17`.  
  - Encryption outputs **space-separated integers** (e.g. `2790 1654 ...`).  
  - To decrypt, paste those integers back as the text and reuse the same `p q e`.

Non-alphabetic characters in text are preserved where appropriate, but for Hill and Playfair the letters are normalized to uppercase A–Z.

---

## How the ciphers work (math + code)

This section is written so you can explain the algorithms in a presentation.

### 1. Caesar cipher

- **Idea (math)**  
  - Replace each letter by another letter a fixed number of positions down the alphabet.  
  - If \(k\) is the key (shift) and letters are encoded as numbers \(A=0, B=1, \dots, Z=25\), then:
    \[
    C = (P + k) \bmod 26,\quad P = (C - k) \bmod 26
    \]
    where \(P\) is the plaintext letter, \(C\) is the ciphertext letter.

- **In code (`app.py`)**
  - Function: `caesar_encrypt(plaintext, key)` and `caesar_decrypt(ciphertext, key)`.
  - Steps:
    1. Convert the key to an integer and reduce it modulo 26.
    2. For each character:
       - If it is a letter, find its index in `ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"`.
       - Add or subtract the key, wrap with modulo 26, and look up the new letter.
       - Preserve the original case (upper / lower).
       - If it is not a letter (space, comma, etc.), leave it unchanged.
  - Decryption calls `caesar_encrypt` with `-key`, which is exactly the inverse operation.

You can say: **“Caesar is just adding a constant number to each letter index modulo 26.”**

---

### 2. Hill cipher (2×2)

- **Idea (math)**  
  - Works on **blocks of 2 letters** at a time.  
  - Encode letters as numbers \(A=0, B=1, \dots, Z=25\).  
  - The key is a **2×2 matrix** \(K\) with entries modulo 26, e.g. key `3 3 2 5` means
    \[
    K = \begin{bmatrix}3 & 3\\ 2 & 5\end{bmatrix}
    \]
  - For each plaintext pair \((P_1, P_2)\) you form a column vector
    \[
    \mathbf{P} = \begin{bmatrix}P_1 \\ P_2\end{bmatrix}
    \]
    and compute
    \[
    \mathbf{C} = K \mathbf{P} \bmod 26
    \]
    to get ciphertext pair \((C_1, C_2)\).
  - To decrypt you need the **inverse matrix** \(K^{-1}\) modulo 26:
    \[
    \mathbf{P} = K^{-1} \mathbf{C} \bmod 26
    \]
  - For the key to be valid, `det(K)` must be **coprime with 26**, so that \(K^{-1}\) exists.

- **In code**
  - Helper functions: `parse_hill_key`, `text_to_numbers`, `numbers_to_text`, `modinv`.
  - `parse_hill_key("3 3 2 5")`:
    - Splits the string into integers, builds a 2×2 `numpy` matrix.
    - Checks that the determinant is invertible modulo 26.
  - `hill_encrypt(plaintext, key_str)`:
    1. Normalize the text to uppercase letters only (`A`–`Z`).
    2. Convert letters to numbers using `text_to_numbers`.
    3. If the length is odd, pad with `X` so we have complete pairs.
    4. For every pair, compute `K · vector % 26` with `numpy`.
    5. Convert the resulting numbers back to letters.
  - `hill_decrypt(ciphertext, key_str)`:
    1. Compute the determinant of `K` and its modular inverse with `modinv`.
    2. Compute the adjugate matrix to get \(K^{-1}\) modulo 26.
    3. Multiply each ciphertext pair by \(K^{-1}\) modulo 26.
    4. Convert back to letters.

You can say: **“Hill uses matrix multiplication on pairs of letters; encryption and decryption are linear algebra modulo 26.”**

---

### 3. Vigenère cipher

- **Idea (math)**  
  - Like Caesar, but the **shift changes** for each letter, controlled by a repeating key word.
  - Encode plaintext letters \(P_i\) and key letters \(K_i\) as numbers 0–25:
    \[
    C_i = (P_i + K_i) \bmod 26,\quad
    P_i = (C_i - K_i) \bmod 26
    \]
  - The key word (e.g. `LEMON`) is repeated or cycled to match the length of the plaintext.

- **In code**
  - Functions: `vigenere_encrypt(plaintext, key)` and `vigenere_decrypt(ciphertext, key)`.
  - Steps:
    1. Normalize the key to uppercase letters only (`normalize_text(key)`).
    2. Walk through the text; maintain an index `j` into the key.
    3. For each letter:
       - Find its index \(P_i\) in the alphabet.
       - Find the current key letter’s index \(K_i\).
       - For encryption: compute \((P_i + K_i) mod 26\).
       - For decryption: compute \((C_i - K_i) mod 26\).
       - Preserve original case; non-letters are copied unchanged and **do not** advance the key index.

You can say: **“Vigenère is just Caesar cipher with a different shift for each position, taken from the key word.”**

---

### 4. Playfair cipher

- **Idea (conceptual + math)**
  - Uses a **5×5 table** of letters built from a key word (I/J are combined):
    1. Start with the key word (e.g. `MONARCHY`), remove duplicates.
    2. Fill the 5×5 grid row by row with key letters, then the remaining letters of the alphabet (without `J`).
  - Text is processed in **digraphs (pairs of letters)**:
    1. Normalize to uppercase, replace `J` with `I`.
    2. Split into pairs; if a pair has the same letter (e.g. `LL`), insert an `X` between them: `LX L`.
    3. If the length is odd, add a trailing `X` to complete the final pair.
  - For each pair:
    - Let the positions be \((r_1, c_1)\) and \((r_2, c_2)\) in the 5×5 grid.
    - **Same row**: shift each letter one step right (encrypt) or left (decrypt) modulo 5.
    - **Same column**: shift each letter one step down (encrypt) or up (decrypt) modulo 5.
    - **Rectangle**: replace each letter by the one in the same row but the other letter’s column:
      \[
      (r_1, c_1), (r_2, c_2) \rightarrow (r_1, c_2), (r_2, c_1)
      \]

- **In code**
  - Building the square: `generate_playfair_square(key)`
    - Normalizes the key, merges `J` into `I`, tracks which letters are already used, and returns a 5×5 list.
  - Locating letters: `find_position(square, ch)` returns the row and column.
  - Preparing text for encryption: `prepare_playfair_text(text, for_encrypt=True)`
    - Normalizes, merges `J` into `I`.
    - Inserts `X` between repeated letters in a pair.
    - Adds a final `X` if needed.
  - Encryption: `playfair_encrypt(plaintext, key)` calls `playfair_process(..., encrypt=True)` which:
    1. Builds the square and prepares the text.
    2. Applies the row/column/rectangle rules with `step = +1`.
  - Decryption: `playfair_decrypt(ciphertext, key)`:
    1. Builds the same square.
    2. Processes the pairs with `step = -1` (reverse shifts).
    3. After getting the raw plaintext, removes typical padding:
       - Patterns like `A X A` (X between two identical letters) -> drop the `X`.
       - A single trailing `X` is removed.

You can say: **“Playfair operates on pairs of letters in a 5×5 key square; encryption is purely geometric (shifting positions in the grid). Padding X’s are added for repeated letters and odd length, and removed on decrypt.”**

---

### 5. DES, AES, Blowfish (block ciphers – demo mode)

- **Idea (conceptual)**  
  - These are modern **block ciphers** that work on fixed-size blocks of bytes (e.g. 8 or 16 bytes).  
  - In this demo, the passphrase is hashed with SHA‑256 to get a fixed-size binary key.  
  - The message is:
    1. Converted to UTF‑8 bytes.
    2. **Padded** to a multiple of the block size (PKCS#7 style).
    3. Encrypted with the chosen block cipher in **ECB mode** (for simplicity).
    4. Shown as a **hex string** so it fits in the text box.

- **In code (`app.py`)**  
  - Helper `_derive_key` turns a passphrase into a key for DES/AES/Blowfish.  
  - `_symmetric_encrypt` / `_symmetric_decrypt` wrap PyCryptodome’s cipher objects and handle padding and hex encoding/decoding.  
  - Public helpers: `des_encrypt/des_decrypt`, `aes_encrypt/aes_decrypt`, `blowfish_encrypt/blowfish_decrypt`.

You can say: **“DES, AES, and Blowfish are modern block ciphers; here we demo them by turning the passphrase into a binary key, padding the message, and encrypting in ECB mode, then displaying the result as hex.”**

> ⚠️ This demo is **not meant to be secure** (fixed mode, derived keys, toy settings). It is for educational purposes only.

---

### 6. Toy RSA

- **Idea (conceptual)**  
  - Real RSA uses a modulus \( n = p \times q \) (product of two large primes) and exponents \( e \) (public) and \( d \) (private) with
    \[
    d \cdot e \equiv 1 \pmod{\varphi(n)}, \quad \varphi(n) = (p-1)(q-1).
    \]
  - Encryption: \( C = P^e \bmod n \)  
    Decryption: \( P = C^d \bmod n \)
  - Our **toy implementation** uses small integers so the calculations are easy to understand.

- **In code (`app.py`)**  
  - `parse_rsa_key(key_str)` reads three integers `p q e`, computes:
    - \( n = p \cdot q \)  
    - \( \varphi(n) = (p-1)(q-1) \)  
    - \( d = e^{-1} \bmod \varphi(n) \) using the existing `modinv`.
  - `rsa_encrypt(plaintext, key_str)`:
    - Converts each character to its Unicode code (`ord(ch)`).
    - Checks that the code is less than \( n \).
    - Computes \( C = P^e \bmod n \) with Python’s `pow`.
    - Outputs the ciphertext as space-separated integers.
  - `rsa_decrypt(ciphertext, key_str)`:
    - Parses the space-separated integers.
    - Computes \( P = C^d \bmod n \) for each.
    - Converts back to characters with `chr`.

You can say: **“Our toy RSA treats each character as a small number and applies the RSA formulas with small primes; it’s only for illustration, not for real security.”**

---

## How to explain in a presentation (summary)

- **Caesar**:  
  - “Add a fixed number \(k\) to each letter index modulo 26. Decrypt by subtracting \(k\).”

- **Hill (2×2)**:  
  - “Group letters in pairs, treat them as 2D vectors, and multiply by a 2×2 key matrix modulo 26. Decrypt using the inverse matrix.”

- **Vigenère**:  
  - “Use a key word to decide a different Caesar shift for each position. Shifts repeat according to the key.”

- **Playfair**:  
  - “Build a 5×5 key table from a word, split the message into pairs, and transform each pair by moving within the table (same row, same column, or rectangle).”
- **DES / AES / Blowfish**:  
  - “Turn the passphrase into a binary key, pad the message to a fixed block length, and apply a modern block cipher to each block; we show the result as hex.”  
- **Toy RSA**:  
  - “Pick small primes \(p, q\) and an exponent \(e\); compute \(n = p q\) and the inverse \(d\). Encrypt each character as \(c = m^e \bmod n\) and decrypt as \(m = c^d \bmod n\); in practice RSA uses huge primes and better padding.” 