import crypt_guard_py
import base64

class CryptGuard:
    def __init__(self, key_type, key_size):
        self.key_type = key_type
        self.key_size = key_size
        self.secret_key, self.public_key = crypt_guard_py.CryptGuardPy.keypair(key_type, key_size)

    def encrypt_a(self, data, passphrase):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.secret_key, crypt_guard_py.CryptGuardMode.a_encrypt(), self.key_size, self.key_type)
        encrypted_data, cipher = crypt_guard.a_encrypt(data, passphrase)
        return encrypted_data, cipher

    def decrypt_a(self, encrypted_data, passphrase, cipher):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.public_key, crypt_guard_py.CryptGuardMode.a_decrypt(), self.key_size, self.key_type)
        decrypted_data = crypt_guard.a_decrypt(encrypted_data, passphrase, cipher)
        return decrypted_data

    def encrypt_x(self, data, passphrase):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.secret_key, crypt_guard_py.CryptGuardMode.e_encrypt(), self.key_size, self.key_type)
        encrypted_data, cipher, nonce = crypt_guard.x_encrypt(data, passphrase)
        return encrypted_data, cipher, nonce

    def decrypt_x(self, encrypted_data, passphrase, cipher, nonce):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.public_key, crypt_guard_py.CryptGuardMode.e_decrypt(), self.key_size, self.key_type)
        decrypted_data = crypt_guard.x_decrypt(encrypted_data, passphrase, cipher, nonce)
        return decrypted_data

    def sign(self, data):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.public_key, crypt_guard_py.CryptGuardMode.sign(), self.key_size, self.key_type)
        signature = crypt_guard.sign(data)
        return signature

    def open(self, data, signature):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.secret_key, crypt_guard_py.CryptGuardMode.verify(), self.key_size, self.key_type)
        verified = crypt_guard.verify(data, signature)
        return verified

    def detached(self, data):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.public_key, crypt_guard_py.CryptGuardMode.detached(), self.key_size, self.key_type)
        signature = crypt_guard.detached(data)
        return signature

    def verify(self, data, signature):
        crypt_guard = crypt_guard_py.CryptGuardPy(self.secret_key, crypt_guard_py.CryptGuardMode.verify(), self.key_size, self.key_type)
        verified = crypt_guard.verify(data, signature)
        return verified

def main():
    data = b'hey, how are you'
    passphrase = 'password'

    # Testing AES Encryption and Decryption
    aes_guard = CryptGuard(crypt_guard_py.KeyTypes.kyber(), 1024)
    encrypted_data, cipher = aes_guard.encrypt_a(data, passphrase)
    print(f'Encrypted Data (AES): {base64.b64encode(bytes(encrypted_data))}')
    print(f'Cipher (AES): {base64.b64encode(bytes(cipher))}')
    decrypted_data = aes_guard.decrypt_a(encrypted_data, passphrase, cipher)
    print(f'Decrypted Data (AES): {decrypted_data}')
    assert data == decrypted_data, "AES Encryption/Decryption failed!"

    # Testing XChaCha20 Encryption and Decryption
    xchacha_guard = CryptGuard(crypt_guard_py.KeyTypes.kyber(), 1024)
    encrypted_data, cipher, nonce = xchacha_guard.encrypt_x(data, passphrase)
    print(f'Encrypted Data (XChaCha20): {base64.b64encode(bytes(encrypted_data))}')
    print(f'Cipher (XChaCha20): {base64.b64encode(bytes(cipher))}')
    print(f'Nonce (XChaCha20): {nonce}')
    decrypted_data = xchacha_guard.decrypt_x(encrypted_data, passphrase, cipher, nonce)
    print(f'Decrypted Data (XChaCha20): {decrypted_data}')
    assert data == decrypted_data, "XChaCha20 Encryption/Decryption failed!"
