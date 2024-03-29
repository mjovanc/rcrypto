use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, AesGcm, Key};
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;

pub fn encrypt_aes256(key: Key<AesGcm<Aes256, U12>>) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;

    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
    assert_eq!(&plaintext, b"plaintext message");

    Ok(ciphertext)
}

pub fn decrypt_aes256(key: Key<AesGcm<Aes256, U12>>, cipher_text: Vec<u8>) -> Result<Vec<u8>, aes_gcm::Error>  {
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let plaintext = cipher.decrypt(&nonce, cipher_text.as_ref())?;

    Ok(plaintext)
}

