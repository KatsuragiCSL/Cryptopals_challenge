from binascii import unhexlify

def checkRepeatedBlock(cipher, keysize = 16):
    if len(cipher) % keysize != 0:
        pass
    else:
        n = len(cipher) // keysize

    blocks = [cipher[i*keysize:(i+1)*keysize] for i in range(n)]
        
    if len(set(blocks)) != n:
        return True
    else:
        return False


if __name__ == '__main__':
    with open('8.txt') as f:
        data = f.readlines()
        suspicious = [x for x in data if checkRepeatedBlock(unhexlify(x.strip()))]

        print(suspicious)
