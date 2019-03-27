def ECB(plain, key):
    repeat = len(plain)//len(key) + 1
    key = (key*repeat)[:len(plain)]
    plain = bytearray(plain, 'utf-8')
    key = bytearray(key, 'utf-8')
    return bytes([x^y for (x,y) in zip(plain,key)]).hex()

plain = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key = "ICE"
print(ECB(plain,key))
