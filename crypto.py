from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECC:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())

    def GetShareKey(self, peer_public_key_pem):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem, backend=default_backend())
        return self.private_key.exchange(ec.ECDH(), peer_public_key)

    def GetPublicKey(self):
        return self.private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo)


class AESCrypto:
    def __init__(self, key):
        # key must be 32 length bytes
        self.AES_CBC_KEY = key
        print(self.AES_CBC_KEY)

    def cbc_encrypt(self, message):
        """
        use AES CBC to encrypt message, using key and init vector
        :param message: the message to encrypt
        :param key: the secret
        :return: bytes init_vector + encrypted_content
        """
        key = self.AES_CBC_KEY
        iv_len = 16
        assert type(message) in (str, bytes)
        assert type(key) in (str, bytes)
        if type(message) == str:
            message = bytes(message, 'utf-8')
        if type(key) == str:
            key = bytes(key, 'utf-8')
        backend = default_backend()
        iv = urandom(iv_len)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        enc_content = encryptor.update(padded_data) + encryptor.finalize()
        return iv + enc_content

    def cbc_decrypt(self, content):
        '''
        use AES CBC to decrypt message, using key
        :param content: the encrypted content using the above protocol
        :param key: the secret
        :return: decrypted bytes
        '''
        key = self.AES_CBC_KEY
        assert type(content) == bytes
        assert type(key) in (bytes, str)
        if type(key) == str:
            key = bytes(key, 'utf-8')
        iv_len = 16
        assert len(content) >= (iv_len + 16)
        iv = content[:iv_len]
        enc_content = content[iv_len:]
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        unpadder = padding.PKCS7(128).unpadder()
        decryptor = cipher.decryptor()
        dec_content = decryptor.update(enc_content) + decryptor.finalize()
        real_content = unpadder.update(dec_content) + unpadder.finalize()
        return real_content


def SHA512(data, len=32):
    return HKDF(algorithm=hashes.SHA256(), length=len, salt=None, info=b'Oh_my_DarkTalk',
                backend=default_backend()).derive(data)
