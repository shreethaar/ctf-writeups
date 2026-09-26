bitmap = [123, 5, 102, 4, 100, 22, 102, 19, 106, 28, 110, 7, 103, 24, 109, 30,
          110, 55, 105, 27, 110, 5, 106, 90, 96, 25, 33, 20, 96, 26]

# Proxy layer: XOR with document.characterSet.length ("UTF-8" -> 5)
bitmap = [b ^ len("UTF-8") for b in bitmap]

# 16-bit key: high byte for even indices, low byte for odd indices
for key in range(0x10000):
    hi, lo = key >> 8, key & 0xFF
    flag = "".join(chr(b ^ (hi if i % 2 == 0 else lo)) for i, b in enumerate(bitmap))
    if flag.endswith("@flare-on.com"):
        print(hex(key), flag)
