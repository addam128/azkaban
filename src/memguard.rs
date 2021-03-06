use sodiumoxide;
use rand;

use crate::utils;


pub(crate) fn mlock(mem: &mut [u8])
    -> Result<(), utils::Error> {

    sodiumoxide::utils::mlock(mem)
            .map_err(|_| utils::Error::MemoryLockError)    
}

pub(crate) fn mlock_opt(mem: Option<&mut [u8]>)
    -> Result<(), utils::Error> {

    match mem {
        Some(underlying) => {
            mlock(underlying)
        }
        None => { Err(utils::Error::SyncError) }
    }
}


pub(crate) fn munlock(mem: &mut [u8])
    -> Result<(), utils::Error> {

    sodiumoxide::utils::munlock(mem)
            .map_err(|_| utils::Error::MemoryLockError)
} 


pub(crate) fn shred(mem: &mut [u8])-> &[u8] {
    
    match munlock(mem) { _ => {}};
    sodiumoxide::utils::memzero(mem);
    mem.iter_mut().for_each(|x| *x = rand::random());
    
    mem
}

pub(crate) fn shred_opt(mem: Option<&mut [u8]>) -> Result<(), utils::Error> {
    
    match mem {
        Some(underlying) => {
            shred(underlying);
            Ok(())
        }
        None => {
            Err(utils::Error::SyncError)
        }
    } 
}


