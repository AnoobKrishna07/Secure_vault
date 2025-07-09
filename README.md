# 🔐 Secure File Vault

A lightweight Python application to encrypt and decrypt any file using AES-GCM and password-based encryption.

## 💻 Features

- AES-GCM encryption (256-bit secure)
- File integrity check (tamper detection)
- Password-based key derivation with salt
- Works for any file type (.txt, .jpg, .pdf, etc.)
- Simple and user-friendly GUI with Tkinter
- Cross-platform (can be packaged into .exe)

## 🔧 Requirements

- Python 3.x
- Install dependencies:
pip install -r requirements.txt

## 🚀 How to Use

1. Run the script:
python secure_vault.py
2. Browse and select a file
3. Enter a strong password
4. Click `Encrypt` or `Decrypt`
5. Encrypted file is saved as `.enc`, decrypted file as `_decrypted.txt`

## ⚠️ Notes

- Do **not forget your password** — decryption will fail.
- Make sure to handle file extensions manually when working with images/PDFs.

## 📦 Packaging to EXE (Optional)

You can package this app as `.exe` using:
pyinstaller --onefile --windowed --icon=icon.ico secure_vault.py

## 🙋‍♂️ Author

**Anoob Krishna S N**  
2nd Year CSE Student @ Prathyusha Engineering College  
Cybersecurity Enthusiast 👨‍💻
