use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::PyResult;
use crypt_guard::{
    KyberFunctions,
    KeyControKyber1024,
    KyberKeyFunctions,
    error::*,
    Encryption, 
    Decryption, 
    Kyber1024, 
    Message, 
    AES,
    Kyber,
    KDF::*,
    error::*,
    *
};

use pyo3::exceptions::PyValueError;

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
pub struct CipherAES {
    key: Vec<u8>,
    key_size: usize,
}

#[pymethods]
impl CipherAES {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize) -> Self {
        CipherAES { key, key_size }
    }

    pub fn encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
        if self.key_size == 1024 {
            return Encryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Encryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Encryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }

    pub fn decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>) -> PyResult<Vec<u8>> {
        if self.key_size == 1024 {
            return Decryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), cipher.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Decryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), cipher.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Decryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), cipher.clone(), AES)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }
}

#[pyclass]
pub struct CipherAES_XTS {
    key: Vec<u8>,
    key_size: usize,
}

#[pymethods]
impl CipherAES_XTS {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize) -> Self {
        CipherAES_XTS { key, key_size }
    }

    pub fn encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
        if self.key_size == 1024 {
            return Encryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Encryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Encryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }

    pub fn decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>) -> PyResult<Vec<u8>> {
        if self.key_size == 1024 {
            return Decryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), cipher.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Decryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), cipher.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Decryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), cipher.clone(), AES_XTS)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }
}

#[pyclass]
pub struct CipherAES_GCM_SIV {
    key: Vec<u8>,
    key_size: usize,
}

#[pymethods]
impl CipherAES_GCM_SIV {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize) -> Self {
        CipherAES_GCM_SIV { key, key_size }
    }

    pub fn encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        if self.key_size == 1024 {
            return Ok(Encryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), AES_GCM_SIV));
        } else if self.key_size == 768 {
            return Ok(Encryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), AES_GCM_SIV));
        } else if self.key_size == 512 {
            return Ok(Encryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), AES_GCM_SIV));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }

    pub fn decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, nonce: String) -> PyResult<Vec<u8>> {
        if self.key_size == 1024 {
            return Decryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_GCM_SIV)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Decryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_GCM_SIV)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Decryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_GCM_SIV)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }
}

#[pyclass]
pub struct CipherAES_CTR {
    key: Vec<u8>,
    key_size: usize,
}

#[pymethods]
impl CipherAES_CTR {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize) -> Self {
        CipherAES_CTR { key, key_size }
    }

    pub fn encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        if self.key_size == 1024 {
            return Ok(Encryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), AES_CTR));
        } else if self.key_size == 768 {
            return Ok(Encryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), AES_CTR));
        } else if self.key_size == 512 {
            return Ok(Encryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), AES_CTR));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }

    pub fn decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, nonce: String) -> PyResult<Vec<u8>> {
        if self.key_size == 1024 {
            return Decryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_CTR)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Decryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_CTR)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Decryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), AES_CTR)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }
}

#[pyclass]
pub struct CipherXChaCha20 {
    key: Vec<u8>,
    key_size: usize,
}

#[pymethods]
impl CipherXChaCha20 {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize) -> Self {
        CipherXChaCha20 { key, key_size }
    }

    pub fn encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        if self.key_size == 1024 {
            return Ok(Encryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), XChaCha20));
        } else if self.key_size == 768 {
            return Ok(Encryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), XChaCha20));
        } else if self.key_size == 512 {
            return Ok(Encryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), XChaCha20));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }

    pub fn decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, nonce: String) -> PyResult<Vec<u8>> {
        if self.key_size == 1024 {
            return Decryption!(self.key.clone(), 1024, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), XChaCha20)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 768 {
            return Decryption!(self.key.clone(), 768, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), XChaCha20)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        } else if self.key_size == 512 {
            return Decryption!(self.key.clone(), 512, data.clone(), passphrase.clone(), cipher.clone(), Some(nonce.clone()), XChaCha20)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)));
        }
        Err(PyValueError::new_err("Invalid key size"))
    }
}

#[pyclass]
pub struct CryptGuardPy {
    key: Vec<u8>,
    key_size: usize,
    key_type: KeyTypes,
}

#[pymethods]
impl CryptGuardPy {
    #[new]
    pub fn new(key: Vec<u8>, key_size: usize, key_type: KeyTypes) -> Self {
        CryptGuardPy {
            key,
            key_size,
            key_type,
        }
    }

    #[staticmethod]
    pub fn keypair(key_type: KeyTypes, key_size: usize) -> PyResult<(Vec<u8>, Vec<u8>)> {
        use crypt_guard::KDF::*;
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

    // Signing and verification logic remains the same
    pub fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => {
                if self.key_size == 1024 {
                    Ok(Signature!(Falcon, self.key.clone(), 1024, data.clone(), Message))
                } else if self.key_size == 512 {
                    Ok(Signature!(Falcon, self.key.clone(), 512, data.clone(), Message))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Dilithium => {
                if self.key_size == 5 {
                    Ok(Signature!(Dilithium, self.key.clone(), 5, data.clone(), Message))
                } else if self.key_size == 3 {
                    Ok(Signature!(Dilithium, self.key.clone(), 3, data.clone(), Message))
                } else if self.key_size == 2 {
                    Ok(Signature!(Dilithium, self.key.clone(), 2, data.clone(), Message))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Kyber => {
                Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type"))
            },
        }
    }

    pub fn detached(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => {
                if self.key_size == 1024 {
                    Ok(Signature!(Falcon, self.key.clone(), 1024, data.clone(), Detached))
                } else if self.key_size == 512 {
                    Ok(Signature!(Falcon, self.key.clone(), 512, data.clone(), Detached))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Dilithium => {
                if self.key_size == 5 {
                    Ok(Signature!(Dilithium, self.key.clone(), 5, data.clone(), Detached))
                } else if self.key_size == 3 {
                    Ok(Signature!(Dilithium, self.key.clone(), 3, data.clone(), Detached))
                } else if self.key_size == 2 {
                    Ok(Signature!(Dilithium, self.key.clone(), 2, data.clone(), Detached))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Kyber => {
                Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type"))
            },
        }
    }

    pub fn verify(&self, signature: Vec<u8>, data: Vec<u8>) -> PyResult<bool> {
        use crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => {
                if self.key_size == 1024 {
                    Ok(Verify!(Falcon, self.key.clone(), 1024, signature.clone(), data.clone(), Detached))
                } else if self.key_size == 512 {
                    Ok(Verify!(Falcon, self.key.clone(), 512, signature.clone(), data.clone(), Detached))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Dilithium => {
                if self.key_size == 5 {
                    Ok(Verify!(Dilithium, self.key.clone(), 5, signature.clone(), data.clone(), Detached))
                } else if self.key_size == 3 {
                    Ok(Verify!(Dilithium, self.key.clone(), 3, signature.clone(), data.clone(), Detached))
                } else if self.key_size == 2 {
                    Ok(Verify!(Dilithium, self.key.clone(), 2, signature.clone(), data.clone(), Detached))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Kyber => {
                Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type"))
            },
        }
    }

    pub fn open(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        use crypt_guard::KDF::*;
        match self.key_type {
            KeyTypes::Falcon => {
                if self.key_size == 1024 {
                    Ok(Verify!(Falcon, self.key.clone(), 1024, data.clone(), Message))
                } else if self.key_size == 512 {
                    Ok(Verify!(Falcon, self.key.clone(), 512, data.clone(), Message))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Dilithium => {
                if self.key_size == 5 {
                    Ok(Verify!(Dilithium, self.key.clone(), 5, data.clone(), Message))
                } else if self.key_size == 3 {
                    Ok(Verify!(Dilithium, self.key.clone(), 3, data.clone(), Message))
                } else if self.key_size == 2 {
                    Ok(Verify!(Dilithium, self.key.clone(), 2, data.clone(), Message))
                } else {
                    Err(PyErr::new::<pyo3::exceptions::PyException, _>("Invalid key size!"))
                }
            },
            KeyTypes::Kyber => {
                Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type"))
            },
        }
    }
}

#[pymodule]
fn crypt_guard_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<KeyTypes>()?;
    m.add_class::<CipherAES>()?;
    m.add_class::<CipherAES_XTS>()?;
    m.add_class::<CipherAES_GCM_SIV>()?;
    m.add_class::<CipherAES_CTR>()?;
    m.add_class::<CipherXChaCha20>()?;
    m.add_class::<CryptGuardPy>()?;
    Ok(())
}
