from binascii import hexlify, unhexlify

def tryKey(cipher, key):
    key = key.to_bytes(1, 'big')
    key = key*len(cipher)
    plain = (bytes([x^y for (x,y) in zip(unhexlify(cipher),key)])).strip()
    ascii = list(range(97, 122)) + list(range(65, 91)) + [32] + [33] + [39] + [44] + [46] +[63]
    valid = all([x in ascii for x in plain])
    if valid:
        print(plain)


ciphers = open("4.txt", "r")
for cipher in ciphers.readlines():
    for i in range(2**8):
        tryKey(cipher.strip(), i)
