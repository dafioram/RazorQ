//! Optional encryption: Argon2id key derivation + XChaCha20-Poly1305.
//!
//! Blocks are encrypted *before* erasure coding and hashing, so check and repair
//! never need the password and never see plaintext.

use crate::error::{Error, Result};
use crate::format::Kdf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("system randomness unavailable");
    b
}

#[derive(Clone)]
pub struct Crypto {
    key: [u8; 32],
    uuid: [u8; 16],
}

impl Crypto {
    pub fn new_kdf() -> Kdf {
        Kdf { salt: random_bytes::<16>(), m_kib: 64 * 1024, t_cost: 3, lanes: 1 }
    }

    pub fn derive(password: &str, kdf: &Kdf, uuid: [u8; 16]) -> Result<Crypto> {
        if kdf.m_kib > 256 * 1024 || kdf.t_cost > 10 || kdf.lanes > 8 {
            return Err(Error::Unsupported("archive KDF exceeds the reader work limit".into()));
        }
        let params = argon2::Params::new(kdf.m_kib, kdf.t_cost, kdf.lanes, Some(32))
            .map_err(|e| Error::Other(format!("bad KDF parameters: {e}")))?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        a.hash_password_into(password.as_bytes(), &kdf.salt, &mut key)
            .map_err(|e| Error::Other(format!("key derivation failed: {e}")))?;
        Ok(Crypto { key, uuid })
    }

    pub(crate) fn inventory_hash(&self, bytes: &[u8]) -> [u8; 16] {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(b"rqz-file-inventory-v1");
        h.update(bytes);
        h.finalize().as_bytes()[..16].try_into().unwrap()
    }

    /// Lets us tell a wrong password from corruption without revealing the key.
    pub fn key_check(&self) -> [u8; 16] {
        let h = blake3::keyed_hash(&self.key, b"rqz-key-check");
        let mut o = [0u8; 16];
        o.copy_from_slice(&h.as_bytes()[..16]);
        o
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    fn aad(&self, seq: u64) -> [u8; 24] {
        let mut a = [0u8; 24];
        a[..16].copy_from_slice(&self.uuid);
        a[16..].copy_from_slice(&seq.to_le_bytes());
        a
    }

    /// Random block nonces remain unique when copies of the same archive are appended independently.
    pub fn encrypt_block(&self, seq: u64, data: &[u8]) -> Vec<u8> {
        let nonce = random_bytes::<NONCE_LEN>();
        let mut out = nonce.to_vec();
        out.extend(
            self.cipher()
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: data, aad: &self.aad(seq) })
                .expect("encryption cannot fail"),
        );
        out
    }

    pub fn decrypt_random_block(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Corrupt("encrypted block is too short".into()));
        }
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &self.aad(seq) })
            .map_err(|_| Error::Corrupt("block failed authentication".into()))
    }

    pub fn decrypt_block(&self, seq: u64, data: &[u8]) -> Result<Vec<u8>> {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&seq.to_le_bytes());
        self.cipher()
            .decrypt(XNonce::from_slice(&n), Payload { msg: data, aad: &self.aad(seq) })
            .map_err(|_| Error::Corrupt("block failed authentication".into()))
    }

    /// Metadata encryption: fresh random nonce each time, stored as a prefix.
    pub fn seal(&self, data: &[u8]) -> Vec<u8> {
        let n = random_bytes::<NONCE_LEN>();
        let mut out = n.to_vec();
        out.extend(
            self.cipher()
                .encrypt(XNonce::from_slice(&n), Payload { msg: data, aad: &self.uuid })
                .expect("encryption cannot fail"),
        );
        out
    }

    pub fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Corrupt("sealed metadata too short".into()));
        }
        let (n, ct) = data.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(XNonce::from_slice(n), Payload { msg: ct, aad: &self.uuid })
            .map_err(|_| Error::Corrupt("metadata failed authentication".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kdf = Kdf { salt: [3; 16], m_kib: 64, t_cost: 1, lanes: 1 };
        let c = Crypto::derive("pw", &kdf, [1; 16]).unwrap();
        let e = c.encrypt_block(5, b"hello");
        assert_eq!(c.decrypt_random_block(5, &e).unwrap(), b"hello");
        assert!(c.decrypt_random_block(6, &e).is_err());
        assert_ne!(&e[..NONCE_LEN], &c.encrypt_block(5, b"hello")[..NONCE_LEN]);
        assert_eq!(c.open(&c.seal(b"meta")).unwrap(), b"meta");
        let other = Crypto::derive("nope", &kdf, [1; 16]).unwrap();
        assert_ne!(c.key_check(), other.key_check());
    }
}
