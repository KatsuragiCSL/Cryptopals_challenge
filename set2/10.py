import cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

def encryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def deccryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    return encryptor.update(block) + encryptor.finalize()

def XOR(x, y):
    return bytes([x^y for (x,y) in zip(s, key_tmp)])

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + chr(n)*n)

def encryptAES(plain, key, iv):
    n_blocks = (len(plain) // len(key)) + 1
    blocks = [plain[i*len(key):(i+1)*len(key)] for i in range(n_blocks)]
    #padding last block
    blocks[-1] = padding(block[-1], len(key))

    #initialize ciphertext blocks
    ciphertext_blocks = [iv]
    ciphertext = b''
    for i in range(n_blocks):
        c = encryptAESblock(XOR(blocks[i], ciphertext_blocks[i]), key)
        ciphertext += c
        ciphertext.append(c)
