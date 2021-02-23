use ring::{self, aead::{self, NONCE_LEN}, rand::{SystemRandom, SecureRandom}};

use sqlx;

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
    NoSuchDataError
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
    -> Result<[u8; FILENAME_LEN], Error> {

    let rng = SystemRandom::new();

    let mut filename = [0u8; FILENAME_LEN];
    
    loop {
        
        rng.fill(&mut filename)?;

        if !uniq_db.exists(user, &filename, UniqueType::Filename).await? {
            break;
        }
    }

    Ok(filename)
}

