use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use file_encryptor::{decrypt_file, encrypt_file};

fn temp_file(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(name);
    let _ = fs::remove_file(&path); // Clean up old test artifacts
    path
}

fn write_temp_file(path: &PathBuf, content: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(content).unwrap();
}

#[test]
fn test_encrypt_and_decrypt_success() {
    sodiumoxide::init().unwrap();

    let input_path = temp_file("test_input.txt");
    let encrypted_path = temp_file("test_encrypted.dat");
    let decrypted_path = temp_file("test_decrypted.txt");

    let plaintext = b"Hello, Milad!";
    let password = "strong_pass";

    write_temp_file(&input_path, plaintext);

    encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        password,
    )
    .unwrap();
    decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        password,
    )
    .unwrap();

    let decrypted = fs::read(decrypted_path).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wrong_password_fails() {
    sodiumoxide::init().unwrap();

    let input_path = temp_file("test_input_fail.txt");
    let encrypted_path = temp_file("test_encrypted_fail.dat");
    let decrypted_path = temp_file("test_decrypted_fail.txt");

    let plaintext = b"Sensitive data";
    write_temp_file(&input_path, plaintext);

    encrypt_file(
        input_path.to_str().unwrap(),
        encrypted_path.to_str().unwrap(),
        "right_pass",
    )
    .unwrap();
    let result = decrypt_file(
        encrypted_path.to_str().unwrap(),
        decrypted_path.to_str().unwrap(),
        "wrong_pass",
    );

    assert!(result.is_err());
}

#[test]
fn test_decrypt_too_small_file() {
    sodiumoxide::init().unwrap();

    let corrupted_path = temp_file("too_small.dat");
    write_temp_file(&corrupted_path, b"too short");

    let out = temp_file("out_should_not_exist.txt");
    let result = decrypt_file(
        corrupted_path.to_str().unwrap(),
        out.to_str().unwrap(),
        "any",
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn test_decrypt_corrupt_salt_or_nonce() {
    sodiumoxide::init().unwrap();

    let bad_data = vec![0u8; 48]; // 16 bytes salt + 24 bytes nonce + 8 bytes of garbage
    let corrupted_path = temp_file("corrupt_salt_nonce.dat");
    write_temp_file(&corrupted_path, &bad_data);

    let out = temp_file("decrypt_fail_out.txt");
    let result = decrypt_file(
        corrupted_path.to_str().unwrap(),
        out.to_str().unwrap(),
        "pw",
    );

    assert!(result.is_err());
}
