use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, AesGcm, Key};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::Nonce;
use aes_gcm::aes::Aes256;

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

