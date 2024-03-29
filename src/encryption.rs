use aes_gcm::{aead::{Aead, KeyInit}, AeadCore, Aes256Gcm, AesGcm, Key};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Nonce, OsRng};
use aes_gcm::aes::Aes256;
use std::str;

pub fn encrypt_aes256(
    key: &Key<AesGcm<Aes256, U12>>,
    nonce: &Nonce<AesGcm<Aes256, U12>>,
    text: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, text.as_ref())?;

    Ok(ciphertext)
}

pub fn decrypt_aes256(
    key: &Key<AesGcm<Aes256, U12>>,
    nonce: &Nonce<AesGcm<Aes256, U12>>,
    cipher: Vec<u8>
) -> Result<Vec<u8>, aes_gcm::Error>  {
    let cipher_inst = Aes256Gcm::new(&key);
    let plaintext = cipher_inst.decrypt(&nonce, cipher.as_ref())?;

    Ok(plaintext)
}

#[test]
fn encrypt_and_decrypt_test() {
    let key = Aes256Gcm::generate_key(OsRng);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let text = b"Some text to be encrypted...".as_ref();

    // Encrypt text
    let cipher = encrypt_aes256(&key, &nonce, &text).unwrap();

    // Decrypt text to bytes vector
    let plaintext_bytes = decrypt_aes256(&key, &nonce, cipher).unwrap();

    let text_str = str::from_utf8(&text).unwrap();
    let initial_str = String::from(text_str);
    let result_str = String::from_utf8(plaintext_bytes).unwrap();
    assert_eq!(initial_str, result_str);
}
