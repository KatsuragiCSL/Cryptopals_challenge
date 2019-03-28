import base64

def Hamming(s1, s2):
    #s1 = bytearray(s1,'utf-8')
    #s2 = bytearray(s2,'utf-8')
    xor = bytes([x^y for (x,y) in zip(s1,s2)]).hex()
    xor = int(xor, 16)
    ham = 0
    while(xor > 0):
        ham += xor & 1
        xor >>= 1
    return ham

#Hamming("this is a test", "wokka wokka!!!")

with open('6.txt') as ciphers:
    cipher = base64.b64decode(ciphers.read())

def guestKeySize():
    sizes = []
    for keysize in range(2,41):
        chunks = [cipher[i:i+keysize] for i in range(0,len(cipher),keysize)]
        d = 0
        for i in range(len(chunks)-1):
            d += Hamming(chunks[i],chunks[i+1])
        d = d/keysize
        sizes.append(d)
    print(sizes.index(min(sizes)))


guestKeySize()


