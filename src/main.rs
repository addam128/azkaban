#![feature(seek_stream_len)]
#![feature(try_trait)]

mod datacrypt;
mod keycrypt;
mod cryptengine;
mod utils;
mod memguard;
mod dbmanagers;
mod config;
mod cli;
mod nonceimpl;
mod protobuf_local;
mod auth;

use tokio;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    
    let mut conf = config::Config::new();
    conf.set_db_loc("/home/adam/Desktop/db/").unwrap();
    conf.set_dek_loc("/home/adam/Desktop/deks/").unwrap();
    conf.set_seal_loc("/home/adam/Desktop/sealed/").unwrap();
    
    let auth_db = dbmanagers::AuthDBManager::new(&conf);
    auth_db.init().await.unwrap();

    let assoc_db = dbmanagers::AssociationDBManager::new(&conf);
    let uniq_db = dbmanagers::UniqenessDBManager::new(&conf);

    cli::spawn(
        Arc::new(conf),
        Arc::new(auth_db),
        Arc::new(uniq_db),
        Arc::new(assoc_db))
    .await.expect("tty failed");
}
