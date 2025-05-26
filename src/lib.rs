use sodiumoxide::crypto::{pwhash, secretbox};
use std::{fs, io};

pub fn encrypt_file(input: &str, output: &str, password: &str) -> io::Result<()> {
    let data = fs::read(input)?;
    let password = password.as_bytes();

    let salt = pwhash::gen_salt();
    let mut key = secretbox::Key([0u8; secretbox::KEYBYTES]);
    pwhash::derive_key(
        &mut key.0,
        password,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .expect("Key derivation failed");

    let nonce = secretbox::gen_nonce();
    let encrypted = secretbox::seal(&data, &nonce, &key);

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&salt.0);
    output_data.extend_from_slice(&nonce.0);
    output_data.extend_from_slice(&encrypted);

    fs::write(output, output_data)?;
    Ok(())
}

pub fn decrypt_file(input: &str, output: &str, password: &str) -> io::Result<()> {
    let data = fs::read(input)?;
    if data.len() < pwhash::SALTBYTES + secretbox::NONCEBYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small"));
    }

    let salt = pwhash::Salt::from_slice(&data[..pwhash::SALTBYTES])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid salt"))?;
    let nonce = secretbox::Nonce::from_slice(
        &data[pwhash::SALTBYTES..pwhash::SALTBYTES + secretbox::NONCEBYTES],
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid nonce"))?;

    let ciphertext = &data[pwhash::SALTBYTES + secretbox::NONCEBYTES..];

    let mut key = secretbox::Key([0u8; secretbox::KEYBYTES]);
    pwhash::derive_key(
        &mut key.0,
        password.as_bytes(),
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .expect("Key derivation failed");

    let decrypted = secretbox::open(ciphertext, &nonce, &key).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Decryption failed. Wrong password or corrupted file.",
        )
    })?;

    fs::write(output, decrypted)?;
    Ok(())
}
