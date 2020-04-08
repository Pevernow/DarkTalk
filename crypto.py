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
        self.AES_CBC_IV = urandom(16)

    @classmethod
    def encrypt(self, data, mode='cbc'):
        func_name = '{}_encrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    @classmethod
    def decrypt(self, data, mode='cbc'):
        func_name = '{}_decrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    @staticmethod
    def pkcs7_padding(data):
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    def cbc_encrypt(cls, data):
        if not isinstance(data, bytes):
            data = data.encode()
        cipher = Cipher(algorithms.AES(cls.AES_CBC_KEY),
                        modes.CBC(cls.AES_CBC_IV),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = encryptor.update(cls.pkcs7_padding(data))

        return padded_data

    @classmethod
    def cbc_decrypt(self, data):
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.AES_CBC_KEY),
                        modes.CBC(self.AES_CBC_IV),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        uppaded_data = self.pkcs7_unpadding(decryptor.update(data))

        uppaded_data = uppaded_data.decode()
        return uppaded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('无效的加密信息!')
        else:
            return uppadded_data


def SHA512(data, len=32):
    return HKDF(algorithm=hashes.SHA256(), length=len, salt=None, info=b'Oh_my_DarkTalk',
                backend=default_backend()).derive(data)
