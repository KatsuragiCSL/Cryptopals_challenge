import json, re
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + bytes(chr(n)*n, 'utf-8'))

def parser(data):
    results = {}
    #separate parameter
    params = data.split('&')
    for x in params:
        results[x.split('=')[0]] = x.split('=')[1]
    return json.dumps(results)

def profile_for(email):
    #smash up & and =
    email = re.sub(r'&|=', '', email)
    return bytes('email=' + email + '&uid=10&role=user', 'utf-8')

aes_key = urandom(16)

def AES_128_ECB(plain, key):
    plain = padding(plain, 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(plain) + encryptor.finalize()

def encrypt_profile(email):
    global aes_key
    return AES_128_ECB(profile_for(email), aes_key)

#eliminate padding in decrypted message
def smashPadding(b, block_length):
    for i in range(block_length):
        if i == 0:
            pass
        elif (b[-i:] == bytes(chr(i)*i, 'utf-8')):
            return b[:-i]
    return b

def decrypt_profile(profile):
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    msg = decryptor.update(profile) + decryptor.finalize()
    msg = smashPadding(msg, 16)
    return parser(msg.decode())

def admin():
    #create email such that value of role is in the new block
    #profile with filled up 2 blocks. value of role starts at third block
    ctxt1 = encrypt_profile("1111111@a.com")
    #create email such that padded 'admin' is sit on the second block
    ctxt2 = encrypt_profile("hey@hi.com" + 'admin' + '\x0b'*11)

    ctxt = ctxt1[:-16] + ctxt2[16:32]

    return decrypt_profile(ctxt)

if __name__ == '__main__':
    print(admin())
