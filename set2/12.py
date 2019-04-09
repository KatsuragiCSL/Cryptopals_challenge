import base64
from random import randint
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

unknown = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

key = urandom(16)

def AES_128_ECB(plain, key):
    #concat
    plain += base64.b64decode(unknown)
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def checkRepeatedBlock(cipher, keysize = 16):
    if len(cipher) % keysize != 0:
        n = len(cipher) // keysize + 1
    else:
        n = len(cipher) // keysize

    blocks = [cipher[i*keysize:(i+1)*keysize] for i in range(n)]

    if len(set(blocks)) != n:    #ECB
        return 1
    else:    #CBC
        return 0

def detectblocksize():
    #feed A's to oracle until blocks doesn't change
    for i in range(1,32):
        global key
        s1 = bytes("A"*i, 'utf-8')
        s2 = bytes("A"*(i+1), 'utf-8')
        msg_pre = AES_128_ECB(s1, key)
        msg_cur = AES_128_ECB(s2, key)
        if msg_pre[:i] == msg_cur[:i]:
            return i

def guessUnknown()

if __name__ == '__main__':
    keysize = detectblocksize()
    isECB = checkRepeatedBlock(AES_128_ECB(bytes("A"*100, 'utf-8'), key))
    if isECB:
        guessUnknown()
