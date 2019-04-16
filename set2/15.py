class PaddingError(Exception):
    pass

def smashPadding(b, block_length):
    x = 0
    for i in range(1,block_length):
        if (bytes(b, 'utf-8')[-i:] == bytes(chr(i)*i, 'utf-8')):
            x = b[:-i]
    if x == 0:
        raise PaddingError
    else:
        return x

try:
    print(smashPadding("ICE ICE BABY\x04\x04\x04\x04", 16))
    print(smashPadding("ICE ICE BABY\x05\x05\x05\x05", 16))
    print(smashPadding("ICE ICE BABY\x01\x02\x03\x04", 16))

except PaddingError:
    print('padding error')
