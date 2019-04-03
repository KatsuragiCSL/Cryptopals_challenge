def padding(block, length):
    n = length - len(block) % length
    if n == 0:
        return block
    else:
        return (block + chr(n)*n)

