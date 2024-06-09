use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::PyResult;
use crypt_guard_lite::*;

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
        match key_type {
            KeyTypes::Kyber => {
                let (secret_key, public_key) = Crypto::keypair(key_size).unwrap();
                Ok((secret_key, public_key))
            },
            KeyTypes::Dilithium => {
                let (secret_key, public_key) = Sign::keypair(KeyVariants::Dilithium, key_size).unwrap();
                Ok((secret_key, public_key))
            },
            KeyTypes::Falcon => {
                let (secret_key, public_key) = Sign::keypair(KeyVariants::Falcon, key_size).unwrap();
                Ok((secret_key, public_key))
            },
        }
    }

    pub fn a_encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let mut guard = CryptGuard::cryptography(self.key.clone(), self.key_size, passphrase.to_string(), None, None);
        guard.aencrypt(data).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn a_decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut guard = CryptGuard::cryptography(self.key.clone(), self.key_size, passphrase.to_string(), Some(cipher), None);
        guard.adecrypt(data).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn x_encrypt(&self, data: Vec<u8>, passphrase: &str) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        let mut guard = CryptGuard::cryptography(self.key.clone(), self.key_size, passphrase.to_string(), None, None);
        guard.xencrypt(data).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn x_decrypt(&self, data: Vec<u8>, passphrase: &str, cipher: Vec<u8>, nonce: String) -> PyResult<Vec<u8>> {
        let mut guard = CryptGuard::cryptography(self.key.clone(), self.key_size, passphrase.to_string(), Some(cipher), None);
        guard.xdecrypt(data, nonce).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut guard = CryptGuard::signature(self.key.clone(), match self.key_type {
            KeyTypes::Falcon => KeyVariants::Falcon,
            KeyTypes::Dilithium => KeyVariants::Dilithium,
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
        }, self.key_size);
        guard.signed_data(data).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn detached(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut guard = CryptGuard::signature(self.key.clone(), match self.key_type {
            KeyTypes::Falcon => KeyVariants::Falcon,
            KeyTypes::Dilithium => KeyVariants::Dilithium,
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
        }, self.key_size);
        guard.detached(data).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let mut guard = CryptGuard::signature(self.key.clone(), match self.key_type {
            KeyTypes::Falcon => KeyVariants::Falcon,
            KeyTypes::Dilithium => KeyVariants::Dilithium,
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
        }, self.key_size);
        guard.verify(data, signature).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }

    pub fn open(&self, signature: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut guard = CryptGuard::signature(self.key.clone(), match self.key_type {
            KeyTypes::Falcon => KeyVariants::Falcon,
            KeyTypes::Dilithium => KeyVariants::Dilithium,
            KeyTypes::Kyber => return Err(PyErr::new::<pyo3::exceptions::PyException, _>("Kyber is not a signing key type")),
        }, self.key_size);
        guard.open(signature).map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("{:?}", e)))
    }
}

#[pymodule]
fn crypt_guard_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<CryptGuardMode>()?;
    m.add_class::<CryptGuardPy>()?;
    m.add_class::<KeyTypes>()?;
    Ok(())
}
