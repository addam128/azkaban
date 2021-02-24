
use std::option::NoneError;

use ring::{self, aead::{self, NONCE_LEN}, rand::{SystemRandom, SecureRandom}};
use rand::{distributions::Alphanumeric, Rng};

use sqlx;
use tokio::task::JoinError;

use crate::dbmanagers::{UniqenessDBManager, UniqueType};

const FILENAME_LEN :usize = 48;

#[derive(Debug)]
pub enum Error {
    CryptoError(ring::error::Unspecified),
    IOError(std::io::Error),
    MemoryLockError,
    AlreadySetError,
    SqliteError(sqlx::Error),
    ConversionError,
    AuthError,
    ChangedRowCountMismatch,
    NoSuchDataError,
    SyncError,
    ProtoBuferror(protobuf::error::ProtobufError),
    FutureJoinError(JoinError),
    NoneError(std::option::NoneError)
}


impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {Error::IOError(err)}
}

impl From<ring::error::Unspecified> for Error {
    fn from(err: ring::error::Unspecified) -> Self {Error::CryptoError(err)}
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {Error::SqliteError(err)}
}

impl From<protobuf::error::ProtobufError> for Error {
    fn from(err: protobuf::error::ProtobufError) -> Self {Error::ProtoBuferror(err)}
}

impl From<tokio::task::JoinError> for Error {
    fn from(err: tokio::task::JoinError) -> Self {Error::FutureJoinError(err)}
}

impl From<std::option::NoneError> for Error {
    fn from(err: std::option::NoneError) -> Self {Error::NoneError(err)}
}






pub(crate) async fn get_unique_nonce(
    user: &str,
    uniq_db: &UniqenessDBManager)
    -> Result<[u8; aead::NONCE_LEN], Error> {

    let rng = SystemRandom::new();

    let mut nonce = [0u8; aead::NONCE_LEN];
    
    loop {
        rng.fill(&mut nonce)?;

        if !uniq_db.exists(user, &nonce, UniqueType::Nonce).await? {
            break;
        }
    }

    Ok(nonce)
}



pub(crate) async fn get_unique_filename(
    user: &str,
    uniq_db: &UniqenessDBManager)
    -> Result<String, Error> {

    
    let filename = loop {
        
        /* https://stackoverflow.com/a/54277357 */
        let filename: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

        if !uniq_db.exists(user, filename.as_bytes(), UniqueType::Filename).await? {
            break filename;
        }
    };

    Ok(filename)
}

