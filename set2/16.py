import re
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

aes_key = urandom(16)
iv = urandom(16)
prefix = b"comment1=cooking%20MCs;userdata="
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def AES_128_CBC(plain):
    plain = re.sub(r';|=', '', plain)
    #concat
    plain = prefix + bytes(plain, 'utf-8') + suffix
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

if __name__ == '__main__':
    print(AES_128_CBC("abc;asd=true"))
