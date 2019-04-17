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

def smashPadding(b, block_length):
    for i in range(block_length):
        if i == 0:
            pass
        elif (b[-i:] == bytes(chr(i)*i, 'utf-8')):
            return b[:-i]
    return b

def XOR(x, y):
    return bytes([a^b for (a,b) in zip(x, y)])

def AES_128_CBC(plain):
    if type(plain) != bytes:
        plain = re.sub(r';|=', '', plain) 
        plain = bytes(plain, 'utf-8')
    else:
        plain = re.sub(b';|=', b'', plain)
    #concat
    plain = prefix + plain + suffix
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

def decrypt_profile(plain):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(plain) + decryptor.finalize()
    msg = smashPadding(msg, 16)
    return msg

def check_admin(s):
    return (b';admin=true;' in s)

def attack():
    #CBC decryption XOR previos block of ciphertext after AES decipher
    #cyphertext under control starts at third block, so flip bits of second one
    c1 = AES_128_CBC("A"*16)
    c2 = XOR(b'A'*16, b';admin=true;\x04\x04\x04\x04')
    c3 = c1[:16] + XOR(c1[16:32], c2) + c1[32:]
    return decrypt_profile(c3)

if __name__ == '__main__':
    print(check_admin(attack()))
