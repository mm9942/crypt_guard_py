use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::PyResult;
use ::crypt_guard::{*, error::*};
use pyo3::exceptions::PyValueError;

#[pyclass]
#[derive(Debug, Clone)]
pub enum CryptGuardMode {
    AEncrypt,
    EEncrypt,
    ADecrypt,
    EDecrypt,
    Sign,
    Detached,
    Verify,
    Open,
}

#[pymethods]
impl CryptGuardMode {
    #[staticmethod]
    pub fn a_encrypt() -> Self {
        CryptGuardMode::AEncrypt
    }

    #[staticmethod]
    pub fn e_encrypt() -> Self {
        CryptGuardMode::EEncrypt
    }

    #[staticmethod]
    pub fn a_decrypt() -> Self {
        CryptGuardMode::ADecrypt
    }

    #[staticmethod]
    pub fn e_decrypt() -> Self {
        CryptGuardMode::EDecrypt
    }

    #[staticmethod]
    pub fn sign() -> Self {
        CryptGuardMode::Sign
    }

    #[staticmethod]
    pub fn detached() -> Self {
        CryptGuardMode::Detached
    }

    #[staticmethod]
    pub fn verify() -> Self {
        CryptGuardMode::Verify
    }

    #[staticmethod]
    pub fn open() -> Self {
        CryptGuardMode::Open
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub enum KeyTypes {
    Kyber,
    Dilithium,
    Falcon,
}

#[pymethods]
impl KeyTypes {
    #[staticmethod]
    pub fn kyber() -> Self {
        KeyTypes::Kyber
    }

    #[staticmethod]
    pub fn dilithium() -> Self {
        KeyTypes::Dilithium
    }

    #[staticmethod]
    pub fn falcon() -> Self {
        KeyTypes::Falcon
    }
}

#[pyclass]
pub struct CryptGuardPy {
    key: Vec<u8>,
    mode: CryptGuardMode,
    key_size: usize,
    key_type: KeyTypes,
}

#[pymethods]
impl CryptGuardPy {
    #[new]
    pub fn new(key: Vec<u8>, mode: CryptGuardMode, key_size: usize, key_type: KeyTypes) -> Self {
        CryptGuardPy {
            key,
            mode,
            key_size,
            key_type,
        }
    }

    #[staticmethod]
    pub fn keypair(key_type: KeyTypes, key_size: usize) -> PyResult<(Vec<u8>, Vec<u8>)> {
        use ::crypt_guard::KDF::*;
        match key_type {
            KeyTypes::Kyber => {
                let (secret_key, public_key) = match key_size {
                    1024 => KyberKeypair!(1024),
                    768 => KyberKeypair!(768),
                    512 => KyberKeypair!(512),
                    _ => return Err(PyValueError::new_err("Invalid key size for Kyber")),
                };
                Ok((secret_key, public_key))
            },
            KeyTypes::Dilithium => {
                let (secret_key, public_key) = match key_size {
                    5 => DilithiumKeypair!(5),
                    3 => DilithiumKeypair!(3),
                    2 => DilithiumKeypair!(2),
                    _ => return Err(PyValueError::new_err("Invalid key size for Dilithium")),
                };
                Ok((secret_key, public_key))
            },
            KeyTypes::Falcon => {
                let (secret_key, public_key) = match key_size {
                    1024 => FalconKeypair!(1024),
                    512 => FalconKeypair!(512),
                    _ => return Err(PyValueError::new_err("Invalid key size for Falcon")),
                };
                Ok((secret_key, public_key))
            },
        }
    }

    pub fn a_encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
        match self.key_size {
            1024 => Encryption!(self.key.clone(), 1024, data, passphrase, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            768 => Encryption!(self.key.clone(), 768, data, passphrase, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            512 => Encryption!(self.key.clone(), 512, data, passphrase, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            _ => return Err(PyValueError::new_err("Invalid key size")),
        }
    }

    pub fn a_decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>) -> PyResult<Vec<u8>> {
        match self.key_size {
            1024 => Decryption!(self.key.clone(), 1024, data, passphrase, cipher, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            768 => Decryption!(self.key.clone(), 768, data, passphrase, cipher, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            512 => Decryption!(self.key.clone(), 512, data, passphrase, cipher, AES).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            _ => return Err(PyValueError::new_err("Invalid key size")),
        }
    }

    pub fn x_encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        match self.key_size {
            1024 => Ok(Encryption!(self.key.clone(), 1024, data, passphrase, XChaCha20)),
            768 => Ok(Encryption!(self.key.clone(), 768, data, passphrase, XChaCha20)),
            512 => Ok(Encryption!(self.key.clone(), 512, data, passphrase, XChaCha20)),
            _ => return Err(PyValueError::new_err("Invalid key size")),
        }
    }

    pub fn x_decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, nonce: String) -> PyResult<Vec<u8>> {
        match self.key_size {
            1024 => Decryption!(self.key.clone(), 1024, data, passphrase, cipher, Some(nonce.clone()), XChaCha20).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            768 => Decryption!(self.key.clone(), 768, data, passphrase, cipher, Some(nonce.clone()), XChaCha20).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            512 => Decryption!(self.key.clone(), 512, data, passphrase, cipher, Some(nonce.clone()), XChaCha20).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e))),
            _ => return Err(PyValueError::new_err("Invalid key size")),
        }
    }

pub fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use ::crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => match self.key_size {
                1024 => Ok(Signature!(Falcon, self.key.clone(), 1024, data, Message)),
                512 => Ok(Signature!(Falcon, self.key.clone(), 512, data, Message)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Dilithium => match self.key_size {
                5 => Ok(Signature!(Dilithium, self.key.clone(), 5, data, Message)),
                3 => Ok(Signature!(Dilithium, self.key.clone(), 3, data, Message)),
                2 => Ok(Signature!(Dilithium, self.key.clone(), 2, data, Message)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid signing key type")),
        }
    }

    pub fn detached(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use ::crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => match self.key_size {
                1024 => Ok(Signature!(Falcon, self.key.clone(), 1024, data, Detached)),
                512 => Ok(Signature!(Falcon, self.key.clone(), 512, data, Detached)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Dilithium => match self.key_size {
                5 => Ok(Signature!(Dilithium, self.key.clone(), 5, data, Detached)),
                3 => Ok(Signature!(Dilithium, self.key.clone(), 3, data, Detached)),
                2 => Ok(Signature!(Dilithium, self.key.clone(), 2, data, Detached)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid signing key type")),
        }
    }

    pub fn verify(&self, signature: Vec<u8>, data: Vec<u8>) -> PyResult<bool> {
        use ::crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => match self.key_size {
                1024 => Ok(Verify!(Falcon, self.key.clone(), 1024, signature, data, Detached)),
                512 => Ok(Verify!(Falcon, self.key.clone(), 512, signature, data, Detached)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Dilithium => match self.key_size {
                5 => Ok(Verify!(Dilithium, self.key.clone(), 5, signature, data, Detached)),
                3 => Ok(Verify!(Dilithium, self.key.clone(), 3, signature, data, Detached)),
                2 => Ok(Verify!(Dilithium, self.key.clone(), 2, signature, data, Detached)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid signing key type")),
        }
    }

    pub fn open(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use ::crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => match self.key_size {
                1024 => Ok(Verify!(Falcon, self.key.clone(), 1024, data, Message)),
                512 => Ok(Verify!(Falcon, self.key.clone(), 512, data, Message)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Dilithium => match self.key_size {
                5 => Ok(Verify!(Dilithium, self.key.clone(), 5, data, Message)),
                3 => Ok(Verify!(Dilithium, self.key.clone(), 3, data, Message)),
                2 => Ok(Verify!(Dilithium, self.key.clone(), 2, data, Message)),
                _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!")),
            },
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
            _ => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid signing key type")),
        }
    }

}

#[pymodule]
fn crypt_guard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<CryptGuardMode>()?;
    m.add_class::<CryptGuardPy>()?;
    m.add_class::<KeyTypes>()?;
    Ok(())
}