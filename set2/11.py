from random import randint
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()


mode = 0
def encryption_oracle(plain):
    key = urandom(16)
    #choose ECB or CBC
    global mode
    mode = randint(1,2)
    if mode == 1:
        return encryptAESECB(plain, key)
    else:
        iv = urandom(16)
        return encryptAESCBC(plain, key, iv)

def encryptAESECB(plain, key):
    #simply padding the plaintext
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

def encryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def XOR(x, y):
    return bytes([a^b for (a,b) in zip(x, y)])

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def encryptAESCBC(plain, key, iv):
    if (len(plain) % len(key) == 0):
        n_blocks = len(plain) // len(key)
    else:
        n_blocks = (len(plain) // len(key)) + 1

    blocks = [plain[i*len(key):(i+1)*len(key)] for i in range(n_blocks)]

    #padding last block
    blocks[-1] = padding(blocks[-1], len(key))

    #initialize ciphertext blocks
    ciphertext_blocks = [iv]
    ciphertext = b''

    for i in range(n_blocks):
        c = encryptAESblock(XOR(blocks[i], ciphertext_blocks[i]), key)
        ciphertext += c
        ciphertext_blocks.append(c)

    return ciphertext

def checkRepeatedBlock(cipher, keysize = 16):
    if len(cipher) % keysize != 0:
        n = len(cipher) // keysize + 1
    else:
        n = len(cipher) // keysize

    blocks = [cipher[i*keysize:(i+1)*keysize] for i in range(n)]
        
    if len(set(blocks)) != n:    #ECB
        return 1
    else:    #CBC
        return 2

if __name__ == '__main__':
    msg = encryption_oracle(bytes("A"*100, 'utf-8'))
    print(mode)
    print(checkRepeatedBlock(msg))
