# 🔐 FileEncryptor

A Basic and secure command-line tool to encrypt and decrypt files using [libsodium](https://github.com/jedisct1/libsodium) via the `sodiumoxide` Rust crate.

## ✨ Features

- 🔒 Password-based file encryption using `secretbox` (XSalsa20 + Poly1305)
- 🧂 Salted password hashing with `pwhash` (Argon2)
- 🔁 Symmetric encryption & decryption
- ✅ Ergonomic CLI interface
- 🧪 100% test coverage (including edge cases)


## TODO
- [] Add secure password prompt (rpassword)
- [] Add optional config file support
- [] Add file overwrite confirmation
- [] Add streaming support for large files

## 🚀 Installation

```bash
cargo install file_encryptor
```

## 📦 Usage
### Encrypt a file
```bash
file_encryptor -e -i plaintext.txt -o encrypted.bin -p "your_password"
```
### Decrypt a file
```bash
file_encryptor -d -i encrypted.bin -o decrypted.txt -p "your_password"
```

## Flags
```bash
Usage: file_encryptor [OPTIONS] --input <INPUT> --output <OUTPUT> --password <PASSWORD>

Options:
  -i, --input <INPUT>        Input file path
  -o, --output <OUTPUT>      Output file path
  -p, --password <PASSWORD>  Password for encryption/decryption
  -e, --encrypt              Encrypt the file
  -d, --decrypt              Decrypt the file
  -h, --help                 Print help
  -V, --version              Print version

```

## 🔐 Security

- Uses pwhash::derive_key (Argon2) with a random salt for each file.
- Authenticated encryption with secretbox (XSalsa20 + Poly1305).
- Salt and nonce are prepended to the ciphertext.

> Never share your password. If you lose it, your data cannot be recovered.

## 📜 License
MIT © 2025 Milad
