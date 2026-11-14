# Vortex

Encrypted steganography toolkit with ML-based steganalysis.

Vortex hides password-encrypted messages inside ordinary images using LSB
embedding, and includes detectors (chi-square + a lightweight ML classifier)
to measure how visible that hiding is.

## Project layout

```
vortex/
  crypto/       AES-256-GCM + password key derivation
  stego/        LSB embed / extract (PNG, BMP)
  detection/    Chi-square attack and ML steganalysis
  eval/         PSNR, SSIM, capacity, detection curves
app/            Streamlit UI
tests/
docs/
```

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Status

Early scaffolding. Crypto layer is next; stego, detection, and UI follow.

## Team

- Shobaan Mohsin (23L-3009)
- Abdul Rafay (23L-3063)
- Rana Daniyal (23L-3057)

National University of Computer and Emerging Sciences, Lahore
