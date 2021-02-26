use dialoguer::console::Term;
use dialoguer::{Input, Password};
use console::style;
use ring::aead::{self, AES_256_GCM, LessSafeKey, UnboundKey};

use std::{io::Write, str::from_utf8, sync::Arc};

use crate::{cryptengine::unscramble_filename, utils};
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

macro_rules! usr_prompt {
    ($user:expr, $msg: expr) => {
        format!("{} {}{}", style($user).italic().cyan(), style("?>").italic().cyan(), style($msg).italic().cyan())   
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
        format!("\t{}\t{}", style($num).green().underlined(), style($item).underlined())   
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

fn show_auth_help(console: &mut Term) -> Result<(), utils::Error> {

    console.write(
        &help!("Available commands:
            exit -- back to main menu
            help -- show this help
            list -- list all hidden files of the user
            bury  -- hide a file
            dig  --  unhide a file\n").as_bytes())?;
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

async fn list_files(
    console: &mut Term,
    user: &str,
    master_key: &aead::LessSafeKey,
    assoc_db: &AssociationDBManager)
    -> Result<(), utils::Error> {

    let mut file_vec = assoc_db.list_files(user).await?;
    
    for (id, filename, nonce) in file_vec.iter_mut() {
            console.write_line(
                &enum_list!(id,
                    std::str::from_utf8(
                        cryptengine::unscramble_filename(
                            filename, nonce, master_key
                            )?
                        )?
                    )
            )?;

            memguard::shred(filename);
        }
    Ok(())
}


async fn create_user(
    console: &mut Term,
    auth_db: &AuthDBManager,
    assoc_db: &AssociationDBManager,
    uniq_db: &UniqenessDBManager)
    -> Result<(), utils::Error> {

    let user = 
        loop { match Input::<String>::new()
                                .with_prompt(prompt!("azkaban ?> Username(or exit)"))
                                .validate_with(|input: &String| {

                                        match input.chars().all(char::is_alphanumeric) {
                                            true => {Ok(())}
                                            false => {Err(warn!("Username must contain only alphanumerics."))}
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
                            }
                            Err(_) => {
                                break input;
                            }
                        }
                    }
                    Err(err) => { return Err(utils::Error::IOError(err));}
                }

        };
    
    let mut pwd = Password::new()
                            .with_prompt(prompt!("create ?> Password"))
                            .with_confirmation(
                                prompt!("create ?> Repeat password"), warn!("Passwords do not match."))
                            .interact_on(console)?;

    memguard::mlock(unsafe { pwd.as_bytes_mut() })?;
    
    uniq_db.init_full(user.as_str()).await?;
    assoc_db.init(user.as_str()).await?;

    let mut mk_raw = cryptengine::derive_master_key(pwd.as_bytes())?;
    memguard::shred(unsafe { pwd.as_bytes_mut()});

    let master_key = LessSafeKey::new(
        aead::UnboundKey::new(&AES_256_GCM, mk_raw.as_ref())?
    );

    auth::create_auth_token(
        user.as_str(),
        &master_key,
        &auth_db,
        &uniq_db).await?;    
    
    memguard::shred(mk_raw.as_mut());

    Ok(())
}


async fn login(
    console: &mut Term,
    config: Arc<Config>,
    auth_db: Arc<AuthDBManager>,
    uniq_db: Arc<UniqenessDBManager>,
    assoc_db: Arc<AssociationDBManager>)
    -> Result<(), utils::Error> {
    
    let user = 
        loop {
            match Input::<String>::new()
                        .with_prompt(prompt!("login ?> Username"))
                        .validate_with(|input: &String| {

                                match input.chars().all(char::is_alphanumeric) && input.chars().count() <= 65 {
                                    true => {Ok(())}
                                    false => {Err("Username must contain only alphanumerics and must be less than 65 characters")}
                                }
                            }
                        )
                        .interact_on(console) {
                            Ok(input) => {
                                match auth_db.query(input.as_str()).await {
                                    Ok(_) => { break input; }
                                    Err(_) => { 
                                        console.write_line(&warn!("Username does not exist."))?;
                                    }
                                }
                            }
                            Err(err) => { return Err(utils::Error::IOError(err)); }
                        }
        };

        let mut pwd = Password::new()
                                    .with_prompt(prompt!("login ?> Password"))
                                    .interact_on(console)?;

        memguard::mlock(unsafe { pwd.as_bytes_mut() })?;
    
        let mut mk_raw = cryptengine::derive_master_key(pwd.as_bytes())?;
        memguard::shred(unsafe { pwd.as_bytes_mut()});
    
        let master_key = LessSafeKey::new(
            aead::UnboundKey::new(&AES_256_GCM, mk_raw.as_ref())?
        );

        let mut auth_token = auth_db.query(user.as_str()).await?;

        match  auth_token.check_key(&master_key){
            Ok(_) => {
                spawn_authed(
                    console,
                    user,
                    Arc::new(master_key),
                    config,
                    uniq_db,
                    assoc_db

                ).await?;
            }
            Err(_) => {
                console.write_line(&warn!("Invalid password."))?;
            }
        }
        
    memguard::shred(mk_raw.as_mut());

    Ok(())
}


async fn spawn_authed(
    console: &mut Term,
    user: String,
    master_key: Arc<aead::LessSafeKey>,
    config: Arc<Config>,
    uniq_db: Arc<UniqenessDBManager>,
    assoc_db: Arc<AssociationDBManager>)
    -> Result<(), utils::Error> {


    loop {

        let input = Input::<String>::new()
                          .with_prompt(&usr_prompt!(user.as_str(), ""))
                          .interact_on(console)?;

        match input.as_str() {
            "help" => { show_auth_help(console)?; },
            "exit" => { break; }
            "list" => { list_files(console, user.as_str(), master_key.as_ref(), assoc_db.as_ref()).await?;}
            _ => { console.write_line(&warn!("Unknown command."))?;} 
        }
    }
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
                            let conf_arc = Arc::clone(&config);
                            let auth_arc = Arc::clone(&auth_db);
                            let uniq_arc = Arc::clone(&uniq_db);
                            let assoc_arc = Arc::clone(&assoc_db); 
                            login(&mut console,
                                conf_arc,
                                auth_arc,
                                uniq_arc,
                                assoc_arc)
                                .await?;
                        }
            _ => { console.write_line(&warn!("Unknown command."))?;}
        }
    }
    
    Ok(())
} 