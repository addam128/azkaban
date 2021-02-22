use ring::aead;
use ring::rand::{SystemRandom, SecureRandom};

use crate::memguard;
use crate::utils;

const KEY_LEN: usize = 256 / 8;

pub(crate) fn generate_dek() 
-> Result<(Box<[u8; KEY_LEN]>, Box<[u8; aead::NONCE_LEN]>), utils::Error> {

    let mut key = Box::new([0u8; KEY_LEN]);
    let mut nonce = Box::new([0u8; aead::NONCE_LEN]);

    memguard::mlock(key.as_mut())?;
    memguard::mlock(nonce.as_mut())?;

    let rng = SystemRandom::new();

    rng.fill(key.as_mut())?;
    rng.fill(nonce.as_mut())?;

    Ok((key, nonce))
}

