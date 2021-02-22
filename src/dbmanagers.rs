use rand::distributions::uniform;
use sqlx::{Connection, sqlite::{self, SqliteConnectOptions, SqliteArguments}, ConnectOptions, query::Query, Executor, Row};

use std::path::PathBuf;
use std::str::FromStr;

use crate::config::Config;
use crate::utils;
use crate::auth::AuthToken;
pub(crate) enum UniqueType {
    Nonce,
    Filename
}

impl ToString for UniqueType {
    fn to_string(&self) -> String {
        match self {
            UniqueType::Nonce => {String::from("nonce")},
            UniqueType::Filename => {String::from("filename")}
        }
    }
}

pub(crate) struct AuthDBManager {
    _path_buf: PathBuf
}

impl AuthDBManager {

    pub(crate) fn new(config: &Config) -> Self {
        let mut pbf = PathBuf::new();
        pbf.push(config.get_db_loc());
        pbf.push("auth.sqlite");

        Self {
            _path_buf: pbf
        }
    }

    fn get_path(&self) -> Result<&str, utils::Error> {
        if let Some(p) = self._path_buf.as_path().to_str() {
            Ok(p)
        } else {
            Err(utils::Error::ConversionError)
        }

    }

    pub(crate) async fn init(&self) -> Result<(), utils::Error> {

        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
                    .create_if_missing(true)
                    .connect().await?;
        let res = 
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name = 'auth'")
            .fetch_optional(&mut conn).await?;

        if let None = res{
            sqlx::query("CREATE TABLE auth (
                user TEXT PRIMARY KEY,
                nonce BLOB NOT NULL,
                token BLOB NOT NULL
            )").execute(&mut conn).await?;
        }

        Ok(())
    }

    pub(crate) async fn save(
        &self,
        user: &str,
        nonce: &[u8],
        auth_str: &[u8])
        -> Result<(), utils::Error> {

        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
                    .connect().await?;
        let rows_changed = conn.execute(sqlx::query(
                "INSERT INTO auth (user, nonce, token) VALUES (?, ?, ?)")
                .bind(user)
                .bind(nonce)
                .bind(auth_str))
                .await?;
        
        Ok(())
    }

    pub(crate) async fn query(&self, user: &str) -> Result<AuthToken, utils::Error> {
        
        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
                    .connect().await?;
        let row = sqlx::query(
                "SELECT user, nonce, token FROM auth WHERE user = ?")
                .bind(user)
                .fetch_one(&mut conn)
                .await?;
        
        Ok(AuthToken::new(row.get(0), row.get(1), row.get(2)))
    }


    pub(crate) async fn list_users(&self) -> Result<Vec<String>, utils::Error> {
        
        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
                    .connect().await?;
        let rows = sqlx::query(
                "SELECT user FROM auth")
                .fetch_all(&mut conn)
                .await?;
        
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }
}

pub(crate) struct UniqenessDBManager {

}

impl UniqenessDBManager {

    pub(crate) async fn exists(
        &self,
        user: &str,
        value: &[u8],
        kind: UniqueType)
        -> Result<bool, utils::Error> {
        
            Ok(false)
    } 
}

pub(crate) struct AssociationDBManager {

}