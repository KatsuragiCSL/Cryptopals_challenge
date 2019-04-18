from random import randint
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

plains = '''MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'''

plains = plains.split('\n')
aes_key = urandom(16)
iv = urandom(16)

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def checkPadding(b, block_length):
    for i in range(1, block_length):
        if (b[-i:] == bytes(chr(i)*i, 'utf-8')):
            return True
    return False

def AES_128_CBC_encrypt(plain):
    if type(plain) != bytes:
        plain = bytes(plain, 'utf-8')
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

def AES_128_CBC_decrypt(ctxt):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ctxt) + decryptor.finalize()
    oracle = checkPadding(msg, 16)
    return oracle

if __name__ == '__main__':
    plain = plains[randint(1, 10)]
    ctxt = AES_128_CBC_encrypt(plain)
    print(AES_128_CBC_decrypt(ctxt))
