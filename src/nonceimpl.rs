use ring::{self, aead};

use crate::{memguard, utils};

pub(crate) struct NonceSeqImpl {
    _actual: Box<[u8; aead::NONCE_LEN]>,
    _start: Box<[u8; aead::NONCE_LEN]>,
    _failing: bool
}

impl NonceSeqImpl {
    
    pub fn new(bytes: &[u8]) -> Result<Self, utils::Error> {

        let mut instance = Self {
            _actual: Box::new([0u8; aead::NONCE_LEN]),
            _start: Box::new([0u8; aead::NONCE_LEN]),
            _failing: false
        };

        memguard::mlock(instance._actual.as_mut())?;
        memguard::mlock(instance._start.as_mut())?;

        instance._actual.copy_from_slice(bytes);
        instance._actual.copy_from_slice(bytes);

        Ok(instance)
    }
}

impl Drop for NonceSeqImpl {
    
    fn drop(&mut self) {

        memguard::shred(self._actual.as_mut());
        memguard::shred(self._start.as_mut());
    }
}

impl aead::NonceSequence for NonceSeqImpl {

    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        
        match self._failing {

            true => { Err(ring::error::Unspecified) },
            false => {
                increase_u8_array(self._actual.as_mut());
                match ring::constant_time::verify_slices_are_equal(
                    self._actual.as_ref(), self._start.as_ref()) {
                        Ok(_) => { 
                            self._failing = true;
                            Err(ring::error::Unspecified)
                        }
                        Err(_) => { Ok(aead::Nonce::try_assume_unique_for_key(self._actual.as_ref())?) }
                    }
            }
        }
    }
}

fn increase_u8_array(mem: &mut [u8]) -> () {

    let mut idx = mem.len() - 1; // start from last byte

    loop {
        mem[idx] += 1; // increase actual byte

        match mem[idx] {
            0 => { // if byte overflows, propagate
                match idx {
                    0 => { idx = mem.len() - 1} // circular manner
                    _ => { idx -= 1 }
                }

            }
            _ => { return ;} 
        }
    }
}

#[cfg(test)]
mod test {
    use ring::aead::{self, Nonce, NonceSequence};
    use super::*;
    
    #[test]
    fn test_increase() {
        let mut bytes = [0xffu8; aead::NONCE_LEN];
        increase_u8_array(&mut bytes);
        assert_ne!(bytes, [0x00u8; aead::NONCE_LEN]);
    }

}