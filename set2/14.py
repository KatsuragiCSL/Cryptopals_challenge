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

#Skipping blocksize detection here for simplicity

key = urandom(16)
#length of random prefix. The case is similar when length > 15 since we will just need to deal with one more dummy block of prefix
l = randint(1,15)
random_prefix = urandom(l)

def AES_128_ECB(plain, key):
    #concat
    plain = random_prefix + plain + base64.b64decode(unknown)
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

def detect_prefix_length():
    #feed A's to oracle until the first doesn't change
    for i in range(1,16):
        s1 = bytes("A"*i, 'utf-8')
        s2 = bytes("A"*(i+1), 'utf-8')
        msg_pre = AES_128_ECB(s1, key)
        msg_cur = AES_128_ECB(s2, key)
        if msg_pre[:16] == msg_cur[:16]:
            return (16 - i)

def guessUnknown(known, keysize, prefix_size):
    k = len(known)
    f = prefix_size
    #number of A's to leave one byte to guess
    p = keysize - ((k+f) % keysize) -1
    plain = bytes("A"*p, 'utf-8')
    block = (k+f) // keysize
    for i in range(256):
        test = AES_128_ECB(plain + known + bytes([i]), key)[block*keysize:(block+1)*keysize]
        if AES_128_ECB(plain, key)[block*keysize:(block+1)*keysize] == test:
            #bytes(5) returns five \x00. It faked me. LOL
            return bytes([i])

def smashPadding(b, block_length):
    for i in range(block_length):
        if i == 0:
            pass
        elif (b[-i:] == bytes(chr(i)*i, 'utf-8')):
            return b[:-i]
    return b

if __name__ == '__main__':
    known = b''
    prefix_size = detect_prefix_length()
    for r in range(200):
        try:
            new_known = guessUnknown(known, 16, prefix_size)
            known = known + new_known
        except:
            pass
    known = smashPadding(known, 16)
    print(known.decode())

