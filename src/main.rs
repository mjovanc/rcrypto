use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, Error, KeyInit};
use crate::encryption::{decrypt_aes256, encrypt_aes256};

mod encryption;

fn main() {
    // Generate a random encryption key
    let key = Aes256Gcm::generate_key(OsRng);

    let cipher_text = match encrypt_aes256(key) {
        Ok(cipher_text) => cipher_text,
        Err(err) => {
            eprintln!("Error encrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Cipher text: {:?}", cipher_text);

    let plaintext = match decrypt_aes256(key, cipher_text) {
        Ok(plaintext) => plaintext,
        Err(err) => {
            eprintln!("Error decrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Plaintext: {:?}", plaintext);
}
