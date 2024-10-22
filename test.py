# test.py

from crypt_guard_py import (
    KeyTypes,
    CryptGuardPy,
    CipherAES,
    CipherAES_XTS,
    CipherAES_GCM_SIV,
    CipherAES_CTR,
    CipherXChaCha20
)
import os

def text_to_bytes(text: str) -> bytes:
    """Converts a string to bytes using UTF-8 encoding."""
    return text.encode('utf-8')

def bytes_to_text(byte_data: bytes) -> str:
    """Converts bytes to a string using UTF-8 decoding."""
    return byte_data.decode('utf-8')

def list_to_bytes(data: list) -> bytes:
    """Converts a list of integers to bytes."""
    return bytes(data)

def generate_symmetric_key():
    """Tests the keypair generation for different key types."""
    print("Testing Keypair Generation")

    secret_key, public_key = CryptGuardPy.keypair(KeyTypes.kyber(), 1024)

def test_a_encrypt_decrypt():
    """Tests AES encryption and decryption using CipherAES."""
    print("\nTesting AES Encryption and Decryption")

    # Define symmetric key and key_size (must match allowed sizes: 512, 768, 1024)
    key_size = 1024
    public_key, secret_key = generate_symmetric_key()

    # Instantiate CipherAES
    cipher = CipherAES(public_key, key_size)

    # Data to encrypt
    data = "This is a test text for AES encryption"
    byte_data = text_to_bytes(data)
    passphrase = "strongpassword"

    # Encrypt
    try:
        encrypted_data, cipher_data = cipher.encrypt(list(byte_data), passphrase)
        print("Encryption successful.")
        print(f"Encrypted Data (len={len(encrypted_data)}): {encrypted_data.hex()}")
        print(f"Cipher Data (len={len(cipher_data)}): {cipher_data.hex()}")
    except Exception as e:
        print(f"Encryption failed: {e}")
        return

    # Decrypt
    try:
        decrypted_list_data = cipher.decrypt(encrypted_data, passphrase, cipher_data)
        decrypted_byte_data = list_to_bytes(decrypted_list_data)
        decrypted_data = bytes_to_text(decrypted_byte_data)
        print("Decryption successful.")
        print(f"Decrypted Data: {decrypted_data}")
    except Exception as e:
        print(f"Decryption failed: {e}")

def test_x_encrypt_decrypt():
    """Tests XChaCha20 encryption and decryption using CipherXChaCha20."""
    print("\nTesting XChaCha20 Encryption and Decryption")

    # Define symmetric key and key_size
    key_size = 1024
    key = generate_symmetric_key()  # XChaCha20 typically uses 32-byte keys

    # Instantiate CipherXChaCha20
    cipher = CipherXChaCha20(key, key_size)

    # Data to encrypt
    data = "This is another test text for XChaCha20 encryption"
    byte_data = text_to_bytes(data)
    passphrase = "anotherstrongpassword"

    # Encrypt
    try:
        encrypted_data, cipher_data, nonce = cipher.encrypt(list(byte_data), passphrase)
        print("Encryption successful.")
        print(f"Encrypted Data (len={len(encrypted_data)}): {encrypted_data.hex()}")
        print(f"Cipher Data (len={len(cipher_data)}): {cipher_data.hex()}")
        print(f"Nonce: {nonce}")
    except Exception as e:
        print(f"Encryption failed: {e}")
        return

    # Decrypt
    try:
        decrypted_list_data = cipher.decrypt(encrypted_data, passphrase, cipher_data, nonce)
        decrypted_byte_data = list_to_bytes(decrypted_list_data)
        decrypted_data = bytes_to_text(decrypted_byte_data)
        print("Decryption successful.")
        print(f"Decrypted Data: {decrypted_data}")
    except Exception as e:
        print(f"Decryption failed: {e}")

def test_sign_verify():
    """Tests signing and verification using CryptGuardPy."""
    print("\nTesting Signing and Verification")

    key_type = KeyTypes.Falcon
    key_size = 1024

    # Generate keypair
    try:
        secret_key, public_key = CryptGuardPy.keypair(key_type, key_size)
        print(f"Secret Key (len={len(secret_key)}): {secret_key.hex()}")
        print(f"Public Key (len={len(public_key)}): {public_key.hex()}")
    except Exception as e:
        print(f"Keypair generation failed: {e}")
        return

    # Instantiate CryptGuardPy with secret_key for signing
    signer = CryptGuardPy(secret_key, key_size, key_type)

    # Data to sign
    data = "hey how are you?"
    byte_data = text_to_bytes(data)

    # Sign data
    try:
        signature = signer.sign(list(byte_data))
        print(f"Generated Signature (len={len(signature)}): {bytes(signature).hex()}")
    except Exception as e:
        print(f"Signing failed: {e}")
        return

    # Instantiate CryptGuardPy with public_key for verification
    verifier = CryptGuardPy(public_key, key_size, key_type)

    # Verify signature
    try:
        # Using 'open' to verify and retrieve the original message
        # 'open' is intended to verify the signature and return the message if valid
        decrypted_data = verifier.open(signature)
        decrypted_bytes = list_to_bytes(decrypted_data)
        decrypted_text = bytes_to_text(decrypted_bytes)
        print(f"Opened Data: {decrypted_text}")
    except Exception as e:
        print(f"Verification failed: {e}")

    print(f"Original Data: {data}")
    print(f"Signature: {bytes(signature).hex()}")

def test_detached_verify():
    """Tests detached signing and verification using CryptGuardPy."""
    print("\nTesting Detached Signing and Verification")

    key_type = KeyTypes.Falcon
    key_size = 1024

    # Generate keypair
    try:
        secret_key, public_key = CryptGuardPy.keypair(key_type, key_size)
        print(f"Secret Key (len={len(secret_key)}): {secret_key.hex()}")
        print(f"Public Key (len={len(public_key)}): {public_key.hex()}")
    except Exception as e:
        print(f"Keypair generation failed: {e}")
        return

    # Instantiate CryptGuardPy with secret_key for detached signing
    signer = CryptGuardPy(secret_key, key_size, key_type)

    # Data to sign
    data = "hey how are you?"
    byte_data = text_to_bytes(data)

    # Generate detached signature
    try:
        signature = signer.detached(list(byte_data))
        print(f"Generated Detached Signature (len={len(signature)}): {bytes(signature).hex()}")
    except Exception as e:
        print(f"Detached Signing failed: {e}")
        return

    # Instantiate CryptGuardPy with public_key for verification
    verifier = CryptGuardPy(public_key, key_size, key_type)

    # Verify detached signature
    try:
        verification = verifier.verify(signature, list(byte_data))
        print(f"Verification succeeded: {verification}")
    except Exception as e:
        print(f"Verification failed: {e}")

    print(f"Original Data: {data}")
    print(f"Signature: {bytes(signature).hex()}")

if __name__ == "__main__":
    test_a_encrypt_decrypt()
    test_x_encrypt_decrypt()
    test_sign_verify()
    test_detached_verify()
