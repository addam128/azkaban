use ring::aead;

pub(crate) struct NonceSeqImpl {
    _actual: [u8; aead::NONCE_LEN],
    _start: [u8; aead::NONCE_LEN],
    _failing: bool
}

impl NonceSeqImpl {
    fn new() {

        let 
    }
}