use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;

pub struct Crypto;

impl Crypto {
    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
        key
    }

    pub fn encrypt(plaintext: &str, password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
        let key = Self::derive_key(password, salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(ciphertext: &[u8], password: &str, salt: &[u8]) -> Result<String, String> {
        if ciphertext.len() < 12 {
            return Err("Invalid ciphertext".to_string());
        }
        let key = Self::derive_key(password, salt);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|e| e.to_string())?;
        String::from_utf8(plaintext).map_err(|e| e.to_string())
    }

    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    pub fn generate_verifier(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
        Self::encrypt("TASK_MANAGER_VERIFIED", password, salt)
    }

    pub fn verify_password(verifier: &[u8], password: &str, salt: &[u8]) -> bool {
        Self::decrypt(verifier, password, salt)
            .map(|s| s == "TASK_MANAGER_VERIFIED")
            .unwrap_or(false)
    }
}
