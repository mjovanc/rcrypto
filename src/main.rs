use std::string::FromUtf8Error;
use aes_gcm::aead::OsRng;
use aes_gcm::{AeadCore, Aes256Gcm, Error, KeyInit};
use crate::encryption::{decrypt_aes256, encrypt_aes256};

mod encryption;

fn main() {
    // Generate a random encryption key
    let key = Aes256Gcm::generate_key(OsRng);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = match encrypt_aes256(&key, &nonce) {
        Ok(cipher_text) => cipher_text,
        Err(err) => {
            eprintln!("Error encrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Cipher text: {:?}", cipher);

    let plaintext_bytes = match decrypt_aes256(&key, &nonce, cipher) {
        Ok(plaintext) => plaintext,
        Err(err) => {
            eprintln!("Error decrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Plaintext (bytes): {:?}", plaintext_bytes);

    match String::from_utf8(plaintext_bytes) {
        Ok(str) => println!("Plaintext: {:?}", str),
        Err(err) => {
            eprintln!("Error converting bytes array to String, {}", err);
            return;
        }
    }
}
