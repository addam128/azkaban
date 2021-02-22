
use ring::aead::{self, Aad, NONCE_LEN, Nonce, MAX_TAG_LEN};
use ring::rand::{SystemRandom, SecureRandom};

use crate::memguard;
use crate::utils;
use crate::protobuf_local::KeyAndNonce::KeyAndNonce;
use crate::dbmanagers;

const KEY_LEN: usize = 256 / 8;
const KEY_N_TAG_LEN: usize = KEY_LEN + MAX_TAG_LEN;
const NONCE_N_TAG_LEN: usize = NONCE_LEN + MAX_TAG_LEN;

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

pub(crate) async fn save_keys(
    user: &str,
    data_key: &mut [u8],
    data_nonce: &mut [u8],
    master_key: &aead::LessSafeKey,
    uniq_db: &dbmanagers::UniqenessDBManager)
    -> Result<KeyAndNonce, utils::Error> {

    let nonce_for_key = Vec::<u8>::from(
        utils::get_unique_nonce(user, uniq_db).await?
    );
    let nonce_for_nonce = Vec::<u8>::from(
        utils::get_unique_nonce(user, uniq_db).await?
    );

    let mut tag = master_key.seal_in_place_separate_tag(
        Nonce::try_assume_unique_for_key(nonce_for_key.as_ref())?,
        Aad::from("dek"),
        data_key)?;
    let mut data_key_vec = Vec::<u8>::from(data_key);
    data_key_vec.extend(tag.as_ref());

    tag = master_key.seal_in_place_separate_tag(
        Nonce::try_assume_unique_for_key(nonce_for_nonce.as_ref())?,
        Aad::from("den"),
        data_nonce)?;
    let mut data_nonce_vec = Vec::<u8>::from(data_nonce);
    data_nonce_vec.extend(tag.as_ref());

    let mut kn = KeyAndNonce::new();
    
    kn.set_data_key(data_key_vec);
    kn.set_data_nonce(data_nonce_vec);
    kn.set_nonce_for_key(nonce_for_key);
    kn.set_nonce_for_nonce(nonce_for_nonce);

    Ok(kn)
}

pub(crate) fn load_keys(
    master_key: &aead::LessSafeKey,
    kn: &mut KeyAndNonce)
    -> Result<(Box<[u8; KEY_LEN]>, Box<[u8; aead::NONCE_LEN]>),
    utils::Error> {

    let mut key_bytes = [0u8; KEY_N_TAG_LEN];
    let mut nonce_bytes = [0u8; NONCE_N_TAG_LEN];

    memguard::mlock(&mut key_bytes)?;
    memguard::mlock(&mut nonce_bytes)?;
    
    key_bytes.clone_from_slice(kn.get_data_key());
    nonce_bytes.clone_from_slice(kn.get_data_nonce());

    let mut key = Box::new([0u8; KEY_LEN]);

    key.clone_from_slice( 
        master_key.open_in_place(
        Nonce::try_assume_unique_for_key(kn.get_nonce_for_key())?,
        Aad::from("dek"),
        &mut key_bytes)?
    );
    memguard::shred(&mut key_bytes);
    memguard::mlock(key.as_mut())?;

    let mut nonce = Box::new([0u8; NONCE_LEN]);
    nonce.clone_from_slice(
        master_key.open_in_place(
            Nonce::try_assume_unique_for_key(kn.get_nonce_for_nonce())?,
            Aad::from("den"),
            &mut nonce_bytes)?
    );
    memguard::shred(&mut nonce_bytes);
    memguard::mlock(nonce.as_mut())?;

    Ok((key, nonce))
}