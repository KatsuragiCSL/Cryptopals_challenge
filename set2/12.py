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
        s1 = bytes("A"*i, 'utf-8')
        s2 = bytes("A"*(i+1), 'utf-8')
        msg_pre = AES_128_ECB(s1, key)
        msg_cur = AES_128_ECB(s2, key)
        if msg_pre[:i] == msg_cur[:i]:
            return i

def getUnknownLength(keysize):
    #length of 'unknown' is not simply length of encrypting empty strength! That would give a number larger than the actual length becuz of Padding is attached!

    compare1 = len(AES_128_ECB(bytes("", 'utf-8'), key))
    for i in range(1, keysize):
        compare2 = len(AES_128_ECB(bytes("T"*i, 'utf-8'), key))
        #when filled up a full block and open a new block
        if compare2 != compare1:
            return (compare1 - i - 1)
    return compare1

def guessUnknown(known, keysize):
    k = len(known)
    #number of A's to leave one byte to guess
    p = keysize - (k % keysize) -1
    plain = bytes("A"*p, 'utf-8')
    block = k // keysize
    for i in range(256):
        test = AES_128_ECB(plain + known + bytes([i]), key)[block*keysize:(block+1)*keysize]
        if AES_128_ECB(plain, key)[block*keysize:(block+1)*keysize] == test:
            #bytes(5) returns five \x00. It faked me. LOL
            return bytes([i])

if __name__ == '__main__':
    keysize = detectblocksize()
    isECB = checkRepeatedBlock(AES_128_ECB(bytes("A"*100, 'utf-8'), key))
    l_unknown = getUnknownLength(keysize)
    if isECB:
        known = b''
        for r in range(l_unknown):
            new_known = guessUnknown(known, keysize)
            known = known + new_known
        print(known.decode())
