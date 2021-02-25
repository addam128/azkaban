use dialoguer::console::Term;
use dialoguer::{Input, Password};
use console::style;
use ring::aead::{self, AES_256_GCM, LessSafeKey, UnboundKey};

use std::{io::Write, sync::Arc};

use crate::utils;
use crate::memguard;
use crate::config::Config;
use crate::dbmanagers::{AssociationDBManager, AuthDBManager, UniqenessDBManager};
use crate::auth;
use crate::cryptengine;


macro_rules! warn {
    ($msg: expr) => {
        format!("{}", style($msg).underlined().red())
    }
}

macro_rules! prompt {
    ($msg: expr) => {
        format!("{}", style($msg).italic().cyan())   
    }
}

macro_rules! header {
    ($msg: expr) => {
        format!("\n\t\t\t{}\n\n", style($msg).green().italic())   
    }
}

macro_rules! usr_promtp {
    ($user:expr, $msg: expr) => {
        format!("{} ?> {}", style($user).italic().cyan(), style($msg).italic().cyan())   
    }
}

macro_rules! help {
    ($msg: expr) => {
        format!("{}", style($msg).yellow())   
    }
}

macro_rules! list {
    ($item: expr) => {
        format!("\t{}", style($item).underlined())   
    }
}

macro_rules! enum_list {
    ($num: expr, $item: expr) => {
        format!("\t{}\t{}", style($num)mem.green().underlined(), style($item).underlined())   
    }
}

macro_rules! trailer {
    ($msg: expr) => {
        format!("{}", stytle($msg).blue().italic())   
    }
}


fn print_main_help(console: &mut Term) -> Result<(), utils::Error> {

    console.write(
        help!("Available commands:
            exit  -- close the program
            help -- show this help menu
            login  -- login to a user account
            create -- create account
            users -- list existing users\n").as_bytes())?;
    Ok(())
}

async fn list_users(
    console: &mut Term,
    auth_db: &AuthDBManager)
    -> Result<(), utils::Error> {

    let users = auth_db.list_users().await?;

    for user in users {
        console.write_line(&list!(user.as_str()))?;
    }
    Ok(())
}

async fn create_user(
    console: &mut Term,
    auth_db: &AuthDBManager,
    assoc_db: &AssociationDBManager,
    uniq_db: &UniqenessDBManager)
    -> Result<(), utils::Error> {

    let raw_uname = 
        loop { match Input::<String>::new()
                                        .with_prompt(prompt!("azkaban ?> Username(or exit)"))
                                        .validate_with(|input: &String| {

                                                match input.chars().all(char::is_alphanumeric) {
                                                    true => {Ok(())}
                                                    false => {Err("Username must contain only alphanumerics.")}
                                                }
                                            }
                                        )
                                        .interact_on(console) {
                                            Ok(input) => {
                                                if input == "exit" {
                                                    return Ok(());
                                                }
                                                match auth_db.query(input.as_str()).await {
                                                    Ok(_) => {
                                                        console.write_line(&warn!("User already exists."))?;
                                                        continue;
                                                    }
                                                    Err(_) => {
                                                        break input;
                                                    }
                                                }
                                            }
                                            Err(_) => { continue;}
                                        }

        };
    
    let mut pwd = Password::new()
                            .with_prompt(prompt!("azkaban ?> Password"))
                            .with_confirmation(
                                prompt!("Repeat password"), warn!("Passwords do not match"))
                            .interact_on(console)?;

    memguard::mlock(unsafe { pwd.as_bytes_mut() })?;
    
    uniq_db.init_full(raw_uname.as_str()).await?;
    assoc_db.init(raw_uname.as_str()).await?;

    let mut mk_raw = cryptengine::derive_master_key(pwd.as_bytes())?;
    memguard::mlock(mk_raw.as_mut())?;
    memguard::shred(unsafe { pwd.as_bytes_mut()});

    let master_key = LessSafeKey::new(
        aead::UnboundKey::new(&AES_256_GCM, mk_raw.as_ref())?
    );

    auth::create_auth_token(
        raw_uname.as_str(),
        &master_key,
        &auth_db,
        &uniq_db).await?;    
    
    memguard::shred(mk_raw.as_mut());

    Ok(())
}


pub(crate) async fn spawn(
    config: Arc<Config>,
    auth_db: Arc<AuthDBManager>,
    uniq_db: Arc<UniqenessDBManager>,
    assoc_db: Arc<AssociationDBManager>)
    -> Result<(), utils::Error> {

    let mut console = Term::stdout();

    console.write(header!("Azkaban v1.0").as_bytes())?;

    loop {

        let input = Input::<String>::new()
                                        .with_prompt(prompt!("azkaban ?>"))
                                        .interact_on(&console)?;

        match input.as_str() {
            "help" => {print_main_help(&mut console)?;},
            "exit" => { break ;},
            "users" => { list_users(&mut console, &auth_db).await?;}
            "create" => {create_user(&mut console, &auth_db, &assoc_db, &uniq_db).await?;}
            "login" => {
                // Arc::clone()'s
                login(&mut console).await?; }
            _ => { console.write_line(&warn!("Unknown command."))?;}
        }
    }
    
    Ok(())
} 