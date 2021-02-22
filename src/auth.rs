use ring::{aead::{self, Nonce, Aad}, error::Unspecified};
use ring::rand::{SystemRandom, SecureRandom};

use crate::utils;
use crate::memguard;
use crate::dbmanagers::{UniqenessDBManager, AuthDBManager};

const AUTH_STR_LEN: usize = 512; 

pub(crate) struct AuthToken {
    _user: String,
    _nonce: Vec<u8>,
    _auth_str: Vec<u8>
}

impl AuthToken {

    pub(crate) fn new(
        user: &str,
        nonce: Vec<u8>,
        auth_str: Vec<u8>)
        -> Self {

        Self {
            _user: String::from(user), 
            _nonce: nonce,
            _auth_str: auth_str
        }
    }

    pub(crate) fn check_key(
        &mut self,
        master_key: &aead::LessSafeKey)
        -> Result<(), utils::Error> {

        memguard::mlock(self._auth_str.as_mut())?;

        master_key.open_in_place(
            Nonce::try_assume_unique_for_key(self._nonce.as_ref())?,
            Aad::from("auth"),
            self._auth_str.as_mut())
            .map_err(|_: Unspecified| utils::Error::AuthError)?;
        
        memguard::shred(self._auth_str.as_mut());
        
        Ok(())
    }

    pub(crate) async fn save_token(
        &self,
        auth_db: &AuthDBManager)
        -> Result<(), utils::Error> {

        auth_db.save(self._user.as_str(),
        self._nonce.as_ref(),
        self._auth_str.as_ref()).await
}
}

pub(crate) async fn create_auth_token(
    user: &str,
    master_key: &aead::LessSafeKey,
    auth_db: &AuthDBManager,
    uniq_db: &UniqenessDBManager)
    -> Result<(), utils::Error> {

    let rng = SystemRandom::new();
    let mut auth_str = [0u8; AUTH_STR_LEN];

    memguard::mlock(&mut auth_str)?;

    rng.fill(&mut auth_str)?;

    let nonce_bytes = utils::get_unique_nonce(user, uniq_db).await?;
    let tag = master_key.seal_in_place_separate_tag(
        Nonce::try_assume_unique_for_key(&nonce_bytes)?,
        Aad::from("auth"),
        &mut auth_str)?;

    let mut auth_vec = Vec::<u8>::from(auth_str);
    auth_vec.extend(tag.as_ref());

    AuthToken::new(
        user,
        Vec::from(nonce_bytes),
        auth_vec
    ).save_token(auth_db).await?;

    Ok(())
}