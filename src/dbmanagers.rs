use rand::distributions::uniform;
use sqlx::{ConnectOptions, Connection, Executor, Row, query::{self, Query}, sqlite::{self, SqliteConnectOptions, SqliteArguments, SqliteQueryResult}};

use std::{fs::File, path::PathBuf};
use std::str::FromStr;

use crate::config::Config;
use crate::utils;
use crate::auth::AuthToken;


macro_rules! utable {
    ($user: expr, $kind: expr) => {
      format!("{}_{}", $user, $kind.to_string())  
    }
}

macro_rules! atable {
    ($user: expr) => {
        format!("{}_assoc", $user)
    }
}

pub(crate) struct FileAssoc(Vec<u8>, Vec<u8>, Vec<u8>);


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
        let res = conn.execute(sqlx::query(
                "INSERT INTO auth (user, nonce, token) VALUES (?, ?, ?)")
                .bind(user)
                .bind(nonce)
                .bind(auth_str))
                .await?;

        if res.rows_affected() != 1 {
            return Err(utils::Error::ChangedRowCountMismatch);
        }
        
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
    _path_buf: PathBuf
}

impl UniqenessDBManager {

    pub(crate) fn new(config: &Config) -> Self {
        
        let mut pbf = PathBuf::new();
        pbf.push(config.get_db_loc());
        pbf.push("uniq.sqlite");

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

    pub(crate) async fn init_full(&self, user: &str)
        -> Result<(), utils::Error> {
        
        self.init(user, UniqueType::Nonce).await?;
        self.init(user, UniqueType::Filename).await?;
        
        Ok(())
    }  

    pub(crate) async fn init(
        &self,
        user: &str,
        kind: UniqueType)
        -> Result<(), utils::Error> {

        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
                        .create_if_missing(true)
                        .connect().await?;
        
        let res = 
            sqlx::query(&format!("SELECT name FROM sqlite_master WHERE type='table' AND name = '{}'", utable!(user, kind)))
            .fetch_optional(&mut conn).await?;

        if let None = res {
            sqlx::query(
                &format!("CREATE TABLE {} (
                            value BLOB PRIMARY KEY
                            )", utable!(user, kind)))
                .execute(&mut conn).await?;
        }

        Ok(())
    }

    pub(crate) async fn exists(
        &self,
        user: &str,
        value: &[u8],
        kind: UniqueType)
        -> Result<bool, utils::Error> {

        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .connect().await?;
        let row = sqlx::query(
        &format!("SELECT value FROM {} WHERE value = ?", utable!(user, kind)))
        .bind(value)
        .fetch_optional(&mut conn)
        .await?;
        
        match row {
            None => {Ok(false)}
            Some(_) => {Ok(true)}
        }
    }
    
    pub(crate) async fn save(
        &self,
        user: &str,
        value: &[u8],
        kind: UniqueType)
        -> Result<(), utils::Error> {

        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .connect().await?;
        
        let res = conn.execute(sqlx::query(
                &format!("INSERT INTO {} (value) VALUES ?", utable!(user, kind)))
                .bind(value))
                .await?;

        if res.rows_affected() != 1 {
   
            return Err(utils::Error::ChangedRowCountMismatch);
        }
        
        Ok(())
    }
}



pub(crate) struct AssociationDBManager {
    _path_buf: PathBuf
}

impl AssociationDBManager {

    pub(crate) fn new(config: &Config) -> Self {

        let mut pbf = PathBuf::new();
        pbf.push(config.get_db_loc());
        pbf.push("assoc.sqlite");

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

    pub(crate) async fn init(
        &self,
        user: &str)
        -> Result<(), utils::Error> {
        
        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .create_if_missing(true)
            .connect()
            .await?;
        

        let res = sqlx::query(
        &format!("SELECT name FROM sqlite_master WHERE type='table' AND name = '{}'", atable!(user)))
            .fetch_optional(&mut conn)
            .await?;

        if let None = res {
            sqlx::query(
            &format!("CREATE TABLE {} (
                id INTEGER PRIMARY KEY,
                filename NOT NULL,
                nonce BLOB NOT NULL,
                enc_name BLOB NOT NULL
                )", atable!(user)))
                .execute(&mut conn)
                .await?;
            }

        Ok(())
    }

    pub(crate) async fn save(
        &self,
        user: &str,
        filename: &[u8],
        nonce: &[u8],
        enc_name: &[u8])
        -> Result<(), utils::Error> {

        let mut conn  = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .connect().await?;
    
        let res = conn.execute(sqlx::query(
            &format!("INSERT INTO {} (filename, nonce, enc_name) VALUES (?, ?, ?)", atable!(user)))
            .bind(filename)
            .bind(nonce)
            .bind(enc_name))
            .await?;

        if res.rows_affected() != 1 {
            return Err(utils::Error::ChangedRowCountMismatch);
        }

        Ok(())
    }

    pub(crate) async fn query(
        &self,
        user: &str,
        id: i64)
        -> Result<FileAssoc, utils::Error> {

        let mut conn  = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .connect().await?;
        
        let res = sqlx::query(
            &format!("SELECT filename, nonce, enc_name FROM {} WHERE id = ?", atable!(user)))
                .bind(id)
                .fetch_optional(&mut conn)
                .await?;

        if let Some(row) = res {
            return Ok(FileAssoc(row.get(0), row.get(1), row.get(2)));
        }
        Err(utils::Error::NoSuchDataError)
    }

    pub(crate) async fn list_files(
        &self,
        user: &str)
        -> Result<Vec<(i64, Vec<u8>)>, utils::Error> {
        
        let mut conn = SqliteConnectOptions::from_str(&format!("sqlite://{}", self.get_path()?))?
            .connect().await?;

        let mut rows = sqlx::query(
            &format!("SELECT id, filename FROM {}", atable!(user)))
            .fetch_all(&mut conn)
            .await?;

        Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
    }
}