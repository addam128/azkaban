use ring::aead::{self, AES_256_GCM, Aad, BoundKey, UnboundKey};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::memguard;
use crate::utils;
use crate::nonceimpl::NonceSeqImpl;
use crate::keycrypt::KEY_LEN;

use tokio::fs::File;
use tokio::io::{ AsyncWriteExt, AsyncReadExt, AsyncSeekExt};

use std::{borrow::BorrowMut, sync::Arc};

use std::io::SeekFrom;


const CHUNK_LEN: u64 = 8192;
const CHUNK_N_TAG_LEN: u64 = CHUNK_LEN + aead::MAX_TAG_LEN as u64;



pub(crate) async fn encrypt_file(
        mut infile: File,
        mut outstream: File,
        data_key: Arc<[u8; KEY_LEN]>, 
        nonce: Arc<[u8; aead::NONCE_LEN]>,
        pb: ProgressBar)
        -> Result<File, utils::Error> {
    
    let nonces = NonceSeqImpl::new(nonce.as_ref())?;
    let u_key = UnboundKey::new(&AES_256_GCM, data_key.as_ref())?;
    let mut s_key = aead::SealingKey::new(u_key, nonces);

    let mut buffer = [0u8; CHUNK_LEN as usize]; // no need to mlock, file exists in plain
    let file_len = infile.metadata().await?.len();
    let mut counter: usize = 0;
    pb.set_length(file_len);

    let remainder = loop {

        let rem = file_len - infile.seek(SeekFrom::Current(0)).await?;
        if rem < CHUNK_LEN {
            break rem;
        }

        infile.read_exact(&mut buffer).await?;

        let tag = s_key.seal_in_place_separate_tag(
            Aad::from(counter.to_be_bytes()),
            &mut buffer)?;
        
        outstream.write_all(&buffer).await?;
        outstream.write_all(tag.as_ref()).await?;

        counter += 1;
        pb.inc(CHUNK_LEN);
    };

    infile.read_exact(&mut buffer[..remainder as usize]).await?;
    let tag = s_key.seal_in_place_separate_tag(
        Aad::from(counter.to_be_bytes()),
        &mut buffer[..remainder as usize])?;
    
    outstream.write_all(&buffer[..remainder as usize]).await?;
    outstream.write_all(tag.as_ref()).await?;
    pb.inc(remainder);
    pb.finish();

    Ok(infile)
}


pub(crate) async fn decrypt_file<W: AsyncWriteExt + Unpin + Send + Sync + 'static>(
    mut infile: File,
    mut outstream: W,
    data_key: Arc<[u8; KEY_LEN]>, 
    nonce: Arc<[u8; aead::NONCE_LEN]>,
    pb: ProgressBar)
    -> Result<W, utils::Error> {


    let nonces = NonceSeqImpl::new(nonce.as_ref())?;
    let u_key = UnboundKey::new(&AES_256_GCM, data_key.as_ref())?;
    let mut o_key = aead::OpeningKey::new(u_key, nonces);

    let mut buffer = [0u8; CHUNK_N_TAG_LEN as usize];
    let file_len = infile.metadata().await?.len();
    let mut counter: usize = 0;

    pb.set_length(file_len);
    
    memguard::mlock(&mut buffer)?; // should not be swapped as sometimes has plaintext in it
    
    let remainder = loop {

        let rem = file_len - infile.seek(SeekFrom::Current(0)).await?;
        if rem < CHUNK_N_TAG_LEN {
            break rem;
        }

        infile.read_exact(&mut buffer).await?;

        let res = o_key.open_in_place(
            Aad::from(counter.to_be_bytes()),
            &mut buffer)?;
        
        outstream.write_all(&res).await?;

        counter += 1;
        pb.inc(CHUNK_N_TAG_LEN);
    };

    infile.read_exact(&mut buffer[..remainder as usize]).await?;

    let res = o_key.open_in_place(
        Aad::from(counter.to_be_bytes()),
        &mut buffer[..remainder as usize])?;

    outstream.write_all(&res).await?;

    memguard::shred(&mut buffer);
    pb.inc(remainder);
    pb.finish();

    Ok(outstream)
}