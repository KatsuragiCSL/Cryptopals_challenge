def Hamming(s1, s2):
    s1 = bytearray(s1,'utf-8')
    s2 = bytearray(s2,'utf-8')
    xor = bytes([x^y for (x,y) in zip(s1,s2)]).hex()
    xor = int(xor, 16)
    ham = 0
    while(xor > 0):
        ham += xor & 1
        xor >>= 1
    return ham

#Hamming("this is a test", "wokka wokka!!!")
