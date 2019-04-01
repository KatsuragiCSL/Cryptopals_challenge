#Install package 'cryptography'. See https://cryptography.io/en/latest/ 

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
backend = default_backend()

def decryptAES(cipher, key):
    CIPHER = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = CIPHER.decryptor()
    return (decryptor.update(cipher) + decryptor.finalize())



if __name__ == '__main__':
    with open('7.txt') as data:
        cipher = base64.b64decode(data.read())
        print(decryptAES(cipher, b'YELLOW SUBMARINE'))
