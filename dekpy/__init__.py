import base64
import hashlib
import random
import string
from typing import Any, Dict

from Crypto import Random
from Crypto.Cipher import AES


def random_str():
    # printing lowercase
    letters = string.ascii_lowercase
    _ran = ''.join([random.choice(letters) for i in range(10)])
    return _ran


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: str) -> bytes:
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc: bytes) -> str:
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def generates_kek():
    """
    For DEK encryption
    """
    key = random_str()
    return AESCipher(key)


def generates_dek():
    # for data encryption
    key = random_str()
    return AESCipher(key)


class Server:

    def __init__(self):
        self.kek = AESCipher(random_str())
        self.store = {}

    def _encrypt(self, dek_key: str) -> bytes:
        return self.kek.encrypt(dek_key)

    def get_dek(self):
        plain_key = random_str()
        encrypted = self._encrypt(plain_key)
        self.store.update({encrypted: plain_key})

        return plain_key, encrypted

    def get_plain_dek(self, encrypted_dek: bytes) -> str:
        return self.store.get(encrypted_dek)


class Client:

    def encrypt(self, txt: str, plain: str, encrypted: bytes) -> Dict[str, Any]:
        dek = AESCipher(plain)
        e = dek.encrypt(txt)
        return {"msg": e, "key": encrypted}

    def decrypt(self, msg: bytes, plain: str):
        dek = AESCipher(plain)
        e = dek.decrypt(msg)
        return e


if __name__ == "__main__":

    server = Server()
    client = Client()

    msg = "hello world"
    # 1 client request a key to encrypt
    plain, key = server.get_dek()
    # 2 client encrypt the msg and wrap with a encrypted key
    wrapped = client.encrypt(msg, plain, key)
    # 3 client ask to decypt the msg:
    plain_key = server.get_plain_dek(wrapped["key"])
    # 4 finally client decrypt the message
    original = client.decrypt(wrapped["msg"], plain_key)
    print("Original message: ", original)
