use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use ring::aead::{self, NONCE_LEN, Nonce, Aad};
use ring::pbkdf2;
use protobuf::{CodedInputStream, CodedOutputStream, Message};

use std::{path::{Path, PathBuf}, str::FromStr};
use std::sync::Arc;
use std::num::NonZeroU32;

use crate::utils;
use crate::dbmanagers::{AssociationDBManager, UniqenessDBManager};
use crate::memguard;
use crate::config::Config;
use crate::keycrypt::{self, KEY_LEN};
use crate::datacrypt;
use crate::protobuf_local::KeyAndNonce::KeyAndNonce;


fn derive_master_key(
    passwd: &[u8])
    -> Result<Box<[u8; KEY_LEN]>, utils::Error> {

    let salt = blake3::hash(passwd);
    let mut master_key = Box::new([0u8; KEY_LEN]);

    memguard::mlock(master_key.as_mut())?;

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(7_500)?,
        salt.as_bytes(),
        passwd,
        master_key.as_mut());

    Ok(master_key)
}


async fn save_keys(
    user: String,
    path: PathBuf,
    master_key: Arc<aead::LessSafeKey>,
    data_key: Arc<[u8; KEY_LEN]>,
    data_nonce: Arc<[u8; aead::NONCE_LEN]>,
    uniq_db: Arc<UniqenessDBManager>)
    -> Result<(), utils::Error> {

    let kn = keycrypt::save_keys(
        user.as_str(),
        data_key,
        data_nonce,
        master_key,
        uniq_db).await?;

    let save_to_file = tokio::task::spawn_blocking( move || -> Result<(), utils::Error> {

            let mut key_file = std::fs::OpenOptions::new()
                                                .write(true)
                                                .read(true)
                                                .create_new(true)
                                                .open(path.as_path())?;
            let mut keystream = CodedOutputStream::new(&mut key_file);
            kn.write_to_with_cached_sizes(&mut keystream)?;

            Ok(())
        }
    );

    save_to_file.await?
}


async fn load_keys(
    dek_path: PathBuf,
    master_key: Arc<aead::LessSafeKey>)
    -> Result<(Arc<[u8; KEY_LEN]>, Arc<[u8; aead::NONCE_LEN]>),
    utils::Error> {

    let load_from_file = tokio::task::spawn_blocking(move || -> Result<KeyAndNonce, utils::Error> {

        let mut key_file = std::fs::OpenOptions::new()
                                                .read(true)
                                                .write(false)
                                                .create(false)
                                                .open(dek_path.as_path())?;

        let mut key_stream = CodedInputStream::new(&mut key_file);
        let mut kn = KeyAndNonce::new();
        kn.merge_from(&mut key_stream)?;
        Ok(kn)
    });

    keycrypt::load_keys(master_key,  load_from_file.await??)
}


async fn scramble_filename(
    user: &str,
    filename: Option<&str>,
    master_key: &aead::LessSafeKey,
    uniq_db: &UniqenessDBManager)
    -> Result<(Vec<u8>, [u8; NONCE_LEN]), utils::Error> {

    if let None = filename {
        return Err(utils::Error::ConversionError);
    }
    
    let nonce = utils::get_unique_nonce(user, uniq_db).await?;
    let mut scrambled = Vec::<u8>::from(filename.unwrap());

    master_key.seal_in_place_append_tag(
        Nonce::try_assume_unique_for_key(&nonce)?,
        Aad::from("filename"),
        &mut scrambled)?;

    Ok((scrambled, nonce))
        
}


fn unscramble_filename<'a>(
    filename: &'a mut  [u8],
    nonce: &[u8],
    master_key: &aead::LessSafeKey)
    -> Result<&'a [u8], utils::Error> {

    memguard::mlock(filename)?;

    let res = master_key.open_in_place(
        Nonce::try_assume_unique_for_key(nonce)?,
        Aad::from("filename"),
        filename)?;

    Ok(res)
}


pub(crate) async fn encrypt_file(
    user: String,
    in_path: PathBuf,
    master_key: Arc<aead::LessSafeKey>,
    assoc_db: Arc<AssociationDBManager>,
    uniq_db: Arc<UniqenessDBManager>,
    config: Arc<Config>)
    -> Result<(), utils::Error> {

    let mut in_file = OpenOptions::new()
                                            .read(true)
                                            .write(true)
                                            .create(false)
                                            .open(in_path.as_path())
                                            .await?;
    
    let encryption_name = utils::get_unique_filename(user.as_str(), uniq_db.as_ref()).await?;

    let mut cipher_path = PathBuf::new();
    cipher_path.push(config.get_seal_loc());
    cipher_path.push(format!("{}.enc", encryption_name));

    let mut key_path = PathBuf::new();
    key_path.push(config.get_dek_loc());
    key_path.push(format!("{}.dek", encryption_name));

    let outfile = OpenOptions::new()
                                        .read(true)
                                        .write(true)
                                        .create_new(true)
                                        .open(cipher_path)
                                        .await?;

    let (mut key, mut nonce) = keycrypt::generate_dek()?;

    let mut key_arc = Arc::clone(&key);
    let mut nonce_arc = Arc::clone(&nonce);

    let encrypt_job = tokio::task::spawn(async move {
            datacrypt::encrypt_file(
                in_file,
                outfile,
                key_arc,
                nonce_arc)
                .await
    });
    
    let user_str = user.clone();
    key_arc = Arc::clone(&key);
    nonce_arc = Arc::clone(&nonce);
    let mut master_key_arc = Arc::clone(&master_key);
    let uniq_arc = Arc::clone(&uniq_db); 

    let key_save = tokio::task::spawn(async move {

            save_keys(user_str,
                      key_path,
                      master_key_arc,
                      key_arc,
                      nonce_arc,
                      uniq_arc).await
        }
    );
    
    key_save.await??;
    let in_file = encrypt_job.await??;
    let (scrambled, s_nonce) = scramble_filename(user.as_str(),
                        in_path.as_os_str().to_str(),
                        master_key.as_ref(),
                        uniq_db.as_ref()).await?;
    assoc_db.save(user.as_str(),
                        scrambled.as_ref(),
                        &s_nonce,
                        encryption_name.as_bytes()).await?;
                    
    // TODO::shred infile

    memguard::shred(match Arc::get_mut(&mut key) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    });

    memguard::shred(match Arc::get_mut(&mut nonce) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    });

    Ok(())    
}


pub(crate) async fn decrypt_file<W: AsyncWriteExt + Send + Sync + Unpin + 'static>(
    enc_path: PathBuf,
    dek_path: PathBuf,
    out_writer: W,
    master_key: Arc<aead::LessSafeKey>)
    -> Result<(), utils::Error> {
    
    let enc_file = OpenOptions::new()
                                    .read(true)
                                    .write(false)
                                    .create(false)
                                    .open(enc_path.as_path()).await?;

    let (mut key, mut nonce) = load_keys(dek_path, master_key).await?;

    let key_arc = Arc::clone(&key);
    let nonce_arc = Arc::clone(&nonce);

    let decrypt_job = tokio::task::spawn(async move {
        datacrypt::decrypt_file(
            enc_file,
            out_writer,
            key_arc,
            nonce_arc)
            .await
    });

    decrypt_job.await??;

    memguard::shred(match Arc::get_mut(&mut key) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    });

    memguard::shred(match Arc::get_mut(&mut nonce) {
        Some(bytes) => { bytes },
        None => { return Err(utils::Error::SyncError);}
    });

    Ok(())
}