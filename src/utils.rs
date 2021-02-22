use ring;


pub enum Error {
    CryptoError(ring::error::Unspecified),
    IOError(std::io::Error),
    MemoryLockError
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {Error::IOError(err)}
}

impl From<ring::error::Unspecified> for Error {
    fn from(err: ring::error::Unspecified) -> Self {Error::CryptoError(err)}
}



