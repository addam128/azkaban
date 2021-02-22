use libc;
use rand::

use crate::utils;


pub(crate) fn mlock(mem: &mut [u8]) -> Result<(), utils::Error> {

    Ok(())
}

pub(crate) fn munlock(mem: &[u8]) -> Result<(), utils::Error> {

    Ok(())
} 

pub(crate) fn shred(mem: &mut [u8]) -> &[u8] {
    
    for i in 1 .. 100 {
        mem.iter_mut().for_each(|x| *x = rand::<u8>::random());
    }

    mem
}


