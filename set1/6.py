import base64
from binascii import unhexlify

def Hamming(s1, s2):
    xor = bytes([x^y for (x,y) in zip(s1,s2)]).hex()
    xor = int(xor, 16)
    ham = 0
    while(xor > 0):
        ham += xor & 1
        xor >>= 1
    return ham

#Hamming("this is a test", "wokka wokka!!!")

def guestKeySize(cipher):
    sizes = []
    for keysize in range(2,41):
        chunks = [cipher[i:i+keysize] for i in range(0,len(cipher),keysize)]
        d = []
        for i in range(len(chunks)-1):  #last one
            d.append(Hamming(chunks[i],chunks[i+1])/keysize)
        sizes.append(sum(d)/len(d))
    return sizes.index(min(sizes)) + 2  #since keysize starts with 2


def breaksinglecharXOR(s):
    results = {"score":0}
    for key in range(2**8):
        key = key.to_bytes(1, 'big')
        key_tmp = key*len(s)
        plain = bytes([x^y for (x,y) in zip(s, key_tmp)])
        asc = list(range(97, 122)) + list(range(65, 91)) + [32] + [33] + [39] + [44] + [46] +[63]
        score = sum([x in asc for x in plain]) 
        if score > results["score"]:
            results = {"key":key, "message":plain, "score":score}
    return results

def breakcipher(cipher, keysize):
    keys = bytes()
    messages = []
    
    for i in range(keysize):
        c = bytearray(cipher[i:len(cipher):keysize])
        r = breaksinglecharXOR(c)
        keys += r["key"]
        messages.append((r["message"]))

    #gluing the messages
    message = bytes()
    for i in range(max(map(len, messages))):
        message += bytes([m[i] for m in messages if len(m) > i])

    return {"key":keys, "message":message}

if __name__ == '__main__':
    with open('6.txt') as ciphers:
        cipher = base64.b64decode(ciphers.read())
        results = breakcipher(cipher, guestKeySize(cipher))
        print(results["key"])
        print(results["message"])
