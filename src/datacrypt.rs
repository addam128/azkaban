use aead::LessSafeKey;
use ring::aead;
use ring::rand;

use crate::memguard;
use crate::utils;

use std::fs::File;
use std::io::Write;

pub(crate) fn encrypt_file<W: Write>(
        infile: &mut File,
        outstream: &mut W,
        master_key: &aead::LessSafeKey, 
        nonce: &[u8])
        -> Result<(), utils::Error> {

    
    let 
}