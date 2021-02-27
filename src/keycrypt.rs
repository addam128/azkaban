
use ring::aead::{self, Aad, NONCE_LEN, Nonce, MAX_TAG_LEN as TAG_LEN};
use ring::rand::{SystemRandom, SecureRandom};

use indicatif::ProgressBar;

use std::sync::Arc;

use crate::memguard;
use crate::utils;
use crate::protobuf_local::KeyAndNonce::KeyAndNonce;
use crate::dbmanagers;

pub(crate) const KEY_LEN: usize = 256 / 8;
const KEY_N_TAG_LEN: usize = KEY_LEN + TAG_LEN;
const NONCE_N_TAG_LEN: usize = NONCE_LEN + TAG_LEN;

pub(crate) fn generate_dek() 
-> Result<(Arc<[u8; KEY_LEN]>, Arc<[u8; aead::NONCE_LEN]>), utils::Error> {

    let mut key: Arc<[u8; KEY_LEN]> = Arc::new([0u8; KEY_LEN]);
    let mut nonce = Arc::new([0u8; aead::NONCE_LEN]);


    memguard::mlock(
        match Arc::get_mut(&mut key) {
            Some(bytes) => { bytes },
            None => { return Err(utils::Error::SyncError);}
        }
    )?;
    memguard::mlock( 
        match Arc::get_mut(&mut nonce) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    })?;

    let rng = SystemRandom::new();

    rng.fill( 
        match Arc::get_mut(&mut key) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    })?;

    rng.fill( match Arc::get_mut(&mut nonce) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    })?;

    Ok((key, nonce))
}

pub(crate) async fn save_keys(
    user: &str,
    data_key: Arc<[u8; KEY_LEN]>,
    data_nonce: Arc<[u8; NONCE_LEN]>,
    master_key: Arc<aead::LessSafeKey>,
    uniq_db: Arc<dbmanagers::UniqenessDBManager>,
    pb: Arc<ProgressBar>)
    -> Result<KeyAndNonce, utils::Error> {

    let nonce_for_key = Vec::<u8>::from(
        utils::get_unique_nonce(user, uniq_db.as_ref()).await?
    );
    pb.inc(1);
    let nonce_for_nonce = Vec::<u8>::from(
        utils::get_unique_nonce(user, uniq_db.as_ref()).await?
    );
    pb.inc(1);

    let mut data_key_vec = Vec::<u8>::new();
    data_key_vec.reserve(KEY_N_TAG_LEN);
    data_key_vec.extend(data_key.as_ref());
    memguard::mlock(data_key_vec.as_mut())?;
    let mut tag = master_key.seal_in_place_separate_tag(
        Nonce::try_assume_unique_for_key(nonce_for_key.as_ref())?,
        Aad::from("dek"),
        data_key_vec.as_mut())?;
    data_key_vec.extend(tag.as_ref());
    pb.inc(1);

    let mut data_nonce_vec = Vec::<u8>::new();
    data_nonce_vec.reserve(NONCE_N_TAG_LEN);
    data_nonce_vec.extend(data_nonce.as_ref());
    memguard::mlock(data_nonce_vec.as_mut())?;
    tag = master_key.seal_in_place_separate_tag(
        Nonce::try_assume_unique_for_key(nonce_for_nonce.as_ref())?,
        Aad::from("den"),
        data_nonce_vec.as_mut())?;
    data_nonce_vec.extend(tag.as_ref());
    pb.inc(1);

    let mut kn = KeyAndNonce::new();
    
    kn.set_data_key(data_key_vec);
    kn.set_data_nonce(data_nonce_vec);
    kn.set_nonce_for_key(nonce_for_key);
    kn.set_nonce_for_nonce(nonce_for_nonce);

    pb.inc(1);

    Ok(kn)
}

pub(crate) fn load_keys(
    master_key: Arc<aead::LessSafeKey>,
    kn: KeyAndNonce,
    pb: Arc<ProgressBar>)
    -> Result<(Arc<[u8; KEY_LEN]>, Arc<[u8; aead::NONCE_LEN]>),
    utils::Error> {

    let mut key_bytes = [0u8; KEY_N_TAG_LEN];
    let mut nonce_bytes = [0u8; NONCE_N_TAG_LEN];

    memguard::mlock(&mut key_bytes)?;
    memguard::mlock(&mut nonce_bytes)?;
    
    key_bytes.clone_from_slice(kn.get_data_key());
    pb.inc(1);
    nonce_bytes.clone_from_slice(kn.get_data_nonce());
    pb.inc(1);
    
    let mut key = Arc::new([0u8; KEY_LEN]);

    match Arc::get_mut(&mut key) {
        Some(bytes) => {
            bytes.clone_from_slice( 
                master_key.open_in_place(
                Nonce::try_assume_unique_for_key(kn.get_nonce_for_key())?,
                Aad::from("dek"),
                &mut key_bytes)?
            );
        }
        None => {
            memguard::shred(&mut key_bytes);
            return Err(utils::Error::SyncError)
        }
    }
    memguard::shred(&mut key_bytes);
    memguard::mlock(
        match Arc::get_mut(&mut key) {
                Some(bytes) => { bytes },
                None => { return Err(utils::Error::SyncError);}
    })?;
    pb.inc(1);

    let mut nonce = Arc::new([0u8; NONCE_LEN]);
    match Arc::get_mut(&mut nonce) {
        Some(bytes) => {
            bytes.clone_from_slice(
                master_key.open_in_place(
                Nonce::try_assume_unique_for_key(kn.get_nonce_for_nonce())?,
                Aad::from("den"),
                &mut nonce_bytes)?
            );
        }
        None => {
            memguard::shred(&mut nonce_bytes);
            return Err(utils::Error::SyncError);
        }
    }
    memguard::shred(&mut nonce_bytes);
    memguard::mlock(
        match Arc::get_mut(&mut key) {
            Some(bytes) => { bytes },
            None => { return Err(utils::Error::SyncError);}
        })?;
    pb.inc(1);
    pb.finish();

    Ok((key, nonce))
}