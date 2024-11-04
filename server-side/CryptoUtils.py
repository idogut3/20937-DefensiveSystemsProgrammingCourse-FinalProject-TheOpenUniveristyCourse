from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def encrypt_aes_key_with_public_key(aes_key, public_key):
    """
       Encrypts an AES key using a given RSA public key.

       This function utilizes the PKCS1 OAEP padding scheme to encrypt the AES key.

       Args:
           aes_key (bytes): The AES key to encrypt.
           public_key (Crypto.PublicKey.RSA._RSAobj): The RSA public key used for encryption.

       Returns:
           bytes: The encrypted AES key.
       """
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)
    return encrypted_key


def decrypt_file_with_aes_key(encrypted_file, aes_key):
    """
        Decrypts an encrypted file using a given AES key.

        This function assumes that the initialization vector (IV) is zeroed out for the decryption process.

        Args:
            encrypted_file (bytes): The encrypted data to decrypt.
            aes_key (bytes): The AES key used for decryption.

        Returns:
            bytes: The decrypted data.

        Raises:
            ValueError: If the padding is incorrect after decryption.
        """
    iv = bytes(16)  # Reset IV to zeros for decryption
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_file), AES.block_size)
    return decrypted_data

def compute_new_aes_key(key_size=256):
    """
        Generates a new random AES key.

        The key size can be specified. The default size is 256 bits.

        Args:
            key_size (int): The size of the AES key in bits. Must be either 128, 192, or 256.

        Returns:
            bytes: A randomly generated AES key.
        """
    return get_random_bytes(key_size // 8)
