#![feature(seek_stream_len)]

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

#[tokio::main]
async fn main() {
    let mut conf = config::Config::new();
    conf.set_db_loc("/home/adam/Desktop/").unwrap();
    let auth_db = dbmanagers::AuthDBManager::new(&conf);
    auth_db.init().await.unwrap();
}
