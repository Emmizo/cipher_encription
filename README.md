# Classical Cipher Web Tool

This is a small Python + HTML5 web application that demonstrates four classical cryptosystems:

- Caesar cipher (encrypt/decrypt)
- Hill cipher (2×2 matrix, encrypt/decrypt)
- Vigenère cipher (encrypt/decrypt)
- Playfair cipher (encrypt/decrypt)

The backend is implemented in Python using Flask, and the frontend is a single HTML5 page.

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

Non-alphabetic characters in text are preserved where appropriate, but for Hill and Playfair the letters are normalized to uppercase A–Z.