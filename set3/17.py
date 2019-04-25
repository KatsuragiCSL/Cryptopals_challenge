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

def AES_128_CBC_decrypt(ctxt, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(ctxt) + decryptor.finalize()
    oracle = checkPadding(msg, 16)
    return oracle

def XOR(x, y):
    return bytes([a^b for (a,b) in zip(x, y)])

def guess_one_byte(ctxt, known):
    tail = len(known) // 16
    #want to make the padding become 'tail + 1' times of 'tail + 1'
    next_pad = bytes(chr(len(known)+1), 'utf-8')
    idx = - (len(known) % 16) - 1
    idx_change = idx - 16
    target = ctxt[:(len(ctxt)-tail*16)]    #[:-tail*16] fails at tail = 0 
    for i in range(256):
        pad = bytes([i]) + XOR(known, next_pad*len(known))
        test = target[:idx_change] + XOR(pad, target[idx_change:-16]) + target[-16:]
        if AES_128_CBC_decrypt(test, iv):
            return XOR(next_pad, bytes([i]))


if __name__ == '__main__':
    plain = plains[randint(0, 9)]
    ctxt = AES_128_CBC_encrypt(plain)
    print("plaintext:")
    print(plain)
    print("cyphertext:")
    print(ctxt)
    #padding length by bits flipping
    for i in range(1, 16):
        test = XOR(ctxt, (len(ctxt) - i - 16)*b'\x00' + b'\xff' + (i-1 + 16)*b'\x00')
        if AES_128_CBC_decrypt(test,iv):
            p_len = i - 1
            break
    #if no padding
    try:
        p_len
    except NameError:
        p_len = 0

    print(p_len)
    known = bytes(chr(p_len), 'utf-8')*p_len
    for i in range(len(ctxt)):
        new_known = guess_one_byte(ctxt, known)
        known = new_known + known
        print(known)
