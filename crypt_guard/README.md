# Crypt Guard Python

Crypt Guard is a Python module for cryptographic operations using `crypt_guard_py`, the pyo3 for the rust crate: `crypt_guard`. It provides a user-friendly object-oriented interface for encryption, decryption, signing, and verification.

## Installation

To install the package, make sure you have Python 3.11 and then use pip:

```bash
pip install crypt_guard
```

## Usage

Here are some examples of how to use the `CryptGuard` class for different cryptographic operations:

### AES Encryption and Decryption

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'
passphrase = 'password'

# Initialize the CryptGuard for AES encryption
aes_guard = CryptGuard(crypt_guard_py.KeyTypes.kyber(), 1024)

# Encrypt the data
encrypted_data, cipher = aes_guard.encrypt_a(data, passphrase)
print(f'Encrypted Data (AES): {base64.b64encode(bytes(encrypted_data))}')
print(f'Cipher (AES): {base64.b64encode(bytes(cipher))}')

# Decrypt the data
decrypted_data = aes_guard.decrypt_a(encrypted_data, passphrase, cipher)
print(f'Decrypted Data (AES): {decrypted_data}')

assert data == decrypted_data, "AES Encryption/Decryption failed!"
```

### XChaCha20 Encryption and Decryption

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'
passphrase = 'password'

# Initialize the CryptGuard for XChaCha20 encryption
xchacha_guard = CryptGuard(crypt_guard_py.KeyTypes.kyber(), 1024)

# Encrypt the data
encrypted_data, cipher, nonce = xchacha_guard.encrypt_x(data, passphrase)
print(f'Encrypted Data (XChaCha20): {base64.b64encode(bytes(encrypted_data))}')
print(f'Cipher (XChaCha20): {base64.b64encode(bytes(cipher))}')
print(f'Nonce (XChaCha20): {nonce}')

# Decrypt the data
decrypted_data = xchacha_guard.decrypt_x(encrypted_data, passphrase, cipher, nonce)
print(f'Decrypted Data (XChaCha20): {decrypted_data}')

assert data == decrypted_data, "XChaCha20 Encryption/Decryption failed!"
```

### Signing and Verification with Falcon

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'

# Initialize the CryptGuard for signing
falcon_guard = CryptGuard(crypt_guard_py.KeyTypes.falcon(), 1024)

# Sign the data
signature = falcon_guard.sign(data)
print(f'Signature (Falcon): {base64.b64encode(bytes(signature))}')

# Verify the signature
verified = falcon_guard.verify_signature(data, signature)
print(f'Signature Verified (Falcon): {verified}')

assert verified, "Signature verification failed!"
```

### Detached Signing and Verification with Falcon

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'

# Initialize the CryptGuard for detached signing
falcon_guard = CryptGuard(crypt_guard_py.KeyTypes.falcon(), 1024)

# Create a detached signature
detached_signature = falcon_guard.detached_sign(data)
print(f'Detached Signature (Falcon): {base64.b64encode(bytes(detached_signature))}')

# Verify the detached signature
verified = falcon_guard.verify_detached_signature(data, detached_signature)
print(f'Detached Signature Verified (Falcon): {verified}')

assert verified, "Detached signature verification failed!"
```

### Signing and Verification with Dilithium

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'

# Initialize the CryptGuard for signing
dilithium_guard = CryptGuard(crypt_guard_py.KeyTypes.dilithium(), 5)

# Sign the data
signature = dilithium_guard.sign(data)
print(f'Signature (Dilithium): {base64.b64encode(bytes(signature))}')

# Verify the signature
verified = dilithium_guard.verify_signature(data, signature)
print(f'Signature Verified (Dilithium): {verified}')

assert verified, "Signature verification failed!"
```

### Detached Signing and Verification with Dilithium

```python
from crypt_guard import CryptGuard
import base64

data = b'hey, how are you'

# Initialize the CryptGuard for detached signing
dilithium_guard = CryptGuard(crypt_guard_py.KeyTypes.dilithium(), 5)

# Create a detached signature
detached_signature = dilithium_guard.detached_sign(data)
print(f'Detached Signature (Dilithium): {base64.b64encode(bytes(detached_signature))}')

# Verify the detached signature
verified = dilithium_guard.verify_detached_signature(data, detached_signature)
print(f'Detached Signature Verified (Dilithium): {verified}')

assert verified, "Detached signature verification failed!"
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## Author

[mm9942](https://github.com/mm9942/)


