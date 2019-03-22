from binascii import hexlify, unhexlify

def tryKey(key):
    cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key = key.to_bytes(1, 'big')
    key = key*len(cipher)
    return (bytes([x^y for (x,y) in zip(unhexlify(cipher),key)]))

for i in range(2**8):
    print(tryKey(i))
