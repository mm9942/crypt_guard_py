from crypt_guard import CryptGuardMode, KeyTypes, CryptGuardPy

class PyValueError(Exception):
    pass

def text_to_bytes(text: str) -> bytes:
    return text.encode('utf-8')

def bytes_to_text(byte_data: bytes) -> str:
    return byte_data.decode('utf-8')

def list_to_bytes(data: list) -> bytes:
    return bytes(data)

def test_a_encrypt_decrypt():
    key_type = KeyTypes.Kyber
    key_size = 1024
    public_key, secret_key = CryptGuardPy.keypair(key_type, key_size)

    mode = CryptGuardMode.AEncrypt
    guard = CryptGuardPy(public_key, mode, key_size, key_type)

    data = "This is a test text for encryption"
    byte_data = text_to_bytes(data)
    passphrase = "secret"
    encrypted_data, cipher = guard.a_encrypt(list(byte_data), passphrase)

    guard = CryptGuardPy(secret_key, mode, key_size, key_type)
    decrypted_list_data = guard.a_decrypt(encrypted_data, passphrase, cipher)
    decrypted_byte_data = list_to_bytes(decrypted_list_data)
    decrypted_data = bytes_to_text(decrypted_byte_data)

    print("Original data:", data)
    print("Encrypted data:", encrypted_data)
    print("Cipher:", cipher)
    print("Decrypted data:", decrypted_data)

def test_x_encrypt_decrypt():
    key_type = KeyTypes.Kyber
    key_size = 1024
    public_key, secret_key = CryptGuardPy.keypair(key_type, key_size)

    mode = CryptGuardMode.AEncrypt
    guard = CryptGuardPy(public_key, mode, key_size, key_type)

    data = "This is another test text for encryption"
    byte_data = text_to_bytes(data)
    passphrase = "secret"
    encrypted_data, cipher, nonce = guard.x_encrypt(list(byte_data), passphrase)

    guard = CryptGuardPy(secret_key, mode, key_size, key_type)
    decrypted_list_data = guard.x_decrypt(encrypted_data, passphrase, cipher, nonce)
    decrypted_byte_data = list_to_bytes(decrypted_list_data)
    decrypted_data = bytes_to_text(decrypted_byte_data)

    print("Original data:", data)
    print("Encrypted data:", encrypted_data)
    print("Cipher:", cipher)
    print("Nonce:", nonce)
    print("Decrypted data:", decrypted_data)

def test_sign_verify():
    key_type = KeyTypes.Falcon
    key_size = 1024
    public_key, secret_key = CryptGuardPy.keypair(key_type, key_size)

    mode = CryptGuardMode.Sign
    guard = CryptGuardPy(secret_key, mode, key_size, key_type)

    data = "hey how are you?"
    byte_data = text_to_bytes(data)
    signature = guard.sign(list(byte_data))
    print("Generated signature length:", len(signature))

    guard = CryptGuardPy(public_key, mode, key_size, key_type)
    try:
        data_opened_list = guard.open(signature)
        data_opened_bytes = list_to_bytes(data_opened_list)
        data_opened = bytes_to_text(data_opened_bytes)
        print("Opened data:", data_opened)
    except Exception as e:
        print("Verification failed:", str(e))

    print("Original data:", data)
    print("Signature:", signature)

def test_detached_verify():
    key_type = KeyTypes.Falcon
    key_size = 1024
    public_key, secret_key = CryptGuardPy.keypair(key_type, key_size)

    mode = CryptGuardMode.Detached
    guard = CryptGuardPy(secret_key, mode, key_size, key_type)

    data = "hey how are you?"
    byte_data = text_to_bytes(data)
    signature = guard.detached(list(byte_data))
    print("Generated detached signature length:", len(signature))

    guard = CryptGuardPy(public_key, mode, key_size, key_type)
    try:
        verification = guard.verify(signature, list(byte_data))
        print("Verification succeeded:", verification)
    except Exception as e:
        print("Verification failed:", str(e))

    print("Original data:", data)
    print("Signature:", signature)

if __name__ == "__main__":
    test_a_encrypt_decrypt()
    test_x_encrypt_decrypt()
    test_sign_verify()
    test_detached_verify()
