use aes_gcm::aead::OsRng;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use crate::encryption::{decrypt_aes256, encrypt_aes256};

mod encryption;

fn main() {
    // Generate a random encryption key
    let key = Aes256Gcm::generate_key(OsRng);
    // Generate a nonce value
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let text = b"Some text to be encrypted...".as_ref();

    // Encrypt
    let cipher = match encrypt_aes256(&key, &nonce, &text) {
        Ok(cipher_text) => cipher_text,
        Err(err) => {
            eprintln!("Error encrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Cipher text: {:?}", cipher);

    // Decrypt cipher text
    let plaintext_bytes = match decrypt_aes256(&key, &nonce, cipher) {
        Ok(plaintext) => plaintext,
        Err(err) => {
            eprintln!("Error decrypting using AES-256, {}", err);
            return;
        }
    };

    println!("Plaintext (bytes): {:?}", plaintext_bytes);

    match String::from_utf8(plaintext_bytes) {
        Ok(str) => println!("Plaintext (String): {:?}", str),
        Err(err) => {
            eprintln!("Error converting bytes array to String, {}", err);
            return;
        }
    }
}
