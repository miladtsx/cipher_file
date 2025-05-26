# 🔐 FileEncryptor

A Basic and secure command-line tool to encrypt and decrypt files using [libsodium](https://github.com/jedisct1/libsodium) via the `sodiumoxide` Rust crate.

## ✨ Features

- 🔒 Password-based file encryption using `secretbox` (XSalsa20 + Poly1305)
- 🧂 Salted password hashing with `pwhash` (Argon2)
- 🔁 Symmetric encryption & decryption
- ✅ Ergonomic CLI interface
- 🧪 100% test coverage (including edge cases)

## 🚀 Installation

```bash
cargo install file_encryptor
