import cryptography, os, random
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

def encryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def decryptAESblock(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()

def XOR(x, y):
    return bytes([a^b for (a,b) in zip(x, y)])

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def encryptAES(plain, key, iv):
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

def decryptAES(ciphertext, key, iv):
    #length of ciphertext should be multiple of len(key)
    n_blocks = len(ciphertext) // len(key)
    blocks = [ciphertext[i*len(key):(i+1)*len(key)] for i in range(n_blocks)]
    blocks_to_be_XOR = [decryptAESblock(x, key) for x in blocks]

    XOR_list = [iv] + blocks[:-1]

    plain = b''

    for i in range(n_blocks):
        p = XOR(blocks_to_be_XOR[i], XOR_list[i])
        plain += p

    return smashPadding(plain, 16)

#eliminate padding in decrypted message
def smashPadding(b, block_length):
    for i in range(block_length):
        if i == 0:
            pass
        elif (b[-i:] == bytes(chr(i)*i, 'utf-8')):
            return b[:-i]
    return b

if __name__ == '__main__':
    with open('10.txt') as f:
        msg = base64.b64decode(f.read())
        key = b'YELLOW SUBMARINE'
        iv = bytes(chr(0)*16, 'utf-8')
        msg_d = decryptAES(msg, key, iv)
        print(msg_d)
