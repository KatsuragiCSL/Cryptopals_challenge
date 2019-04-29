import cryptography
from base64 import b64decode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

def XOR(x, y):
    return bytes([a^b for (a,b) in zip(x, y)])

def encryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

secret = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

def key_stream_gen(key, nonce):
    counter = 0
    while True:
        stream = nonce.to_bytes(8, byteorder="little") + counter.to_bytes(8, byteorder="little")
        key_stream = encryptAESblock(stream, key)
        yield from key_stream
        counter += 1

def AES_128_CTR_decrypt(ctxt, key, nonce):
    key_stream = key_stream_gen(key, nonce)
    return XOR(ctxt, key_stream)

print(AES_128_CTR_decrypt(b64decode(bytes(secret, 'utf-8')), b'YELLOW SUBMARINE', 0))
