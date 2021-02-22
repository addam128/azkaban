
use std::path::{self, Path, PathBuf};

use crate::utils;

pub(crate) struct Config {
    _db_loc: PathBuf,
    _db_set:  bool, 
    _seal_loc: PathBuf,
    _seal_set: bool,
    _dek_loc: PathBuf,
    _dek_set: bool
}

impl Config {

    pub(crate) fn new() -> Self {
        Self {
            _db_loc: PathBuf::new(),
            _db_set: false,
            _seal_loc: PathBuf::new(),
            _seal_set: false, 
            _dek_loc: PathBuf::new(),
            _dek_set: false
        }
    }

    pub(crate) fn get_db_loc(&self) -> &Path {
        
        self._db_loc.as_path()
    }

    pub(crate) fn get_seal_loc(&self) -> &Path {
        
        self._seal_loc.as_path()
    } 

    pub(crate) fn get_dek_loc(&self) -> &Path {
        
        self._dek_loc.as_path()
    } 

    pub(crate) fn set_db_loc(&mut self, path_str: &str) -> Result<(), utils::Error> {
        
        if self._db_set { return Err(utils::Error::AlreadySetError);}
        
        self._db_loc.push(path_str);
        self._db_set = true;
        Ok(())
           
    }

    pub(crate) fn set_seal_loc(&mut self, path_str: &str) -> Result<(), utils::Error> {
        
        if self._seal_set { return Err(utils::Error::AlreadySetError);}
        
        self._seal_loc.push(path_str);
        self._seal_set = true;
        Ok(())
    }

    pub(crate) fn set_dek_loc(&mut self, path_str: &str) -> Result<(), utils::Error> {
        
        if self._dek_set { return Err(utils::Error::AlreadySetError);}
        
        self._dek_loc.push(path_str);
        self._dek_set = true;
        Ok(())
    }
}