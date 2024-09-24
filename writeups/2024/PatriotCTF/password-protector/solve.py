# Mwahahaha you will nOcmu{9gtufever crack into my passMmQg8G0eCXWi3MY9QfZ0NjCrXhzJEj50fumttU0ympword, i'll even give you the key and the executable:::: Zfo5ibyl6t7WYtr2voUEZ0nSAJeWMcN3Qe3/+MLXoKL/p59K3jgV

import base64

string1="Ocmu{9gtuf"
string2="MmQg8G0eCXWi3MY9QfZ0NjCrXhzJEj50fumttU0ymp"
string3="Zfo5ibyl6t7WYtr2voUEZ0nSAJeWMcN3Qe3/+MLXoKL/p59K3jgV"

fourth=string1+string2
# print(fourth)

# Function to reverse flipFlops
def reverse_flip_flops(encoded_str):
    return ''.join([chr(ord(x)-1) for x in encoded_str])

# XOR decoding function
def xor_decrypt(encoded_bytes, key_bytes):
    return bytes([b1 ^ b2 for b1, b2 in zip(encoded_bytes, key_bytes)])

# zip() pairs up corresponding elements from encoded_bytes and key_bytes
# XOR operation between b1 and b2 from encoded_bytes and key_bytes

# Reverse flipFlops for the transformed base64 string
reversed_flips=reverse_flip_flops(fourth)
# print(reversed_flips)
# Nbltz8fsteLlPf7F/dBWVh2LX8PeY/MiBqWgyIDi4/etlssT/xlo
# echo "Nbltz8fsteLlPf7F/dBWVh2LX8PeY/MiBqWgyIDi4/etlssT/xlo" | base64 -d | xxd -p
# same output as decoded_bytes 

# Add padding to the reversed string if needed
while len(reversed_flips) % 4 != 0:
    reversed_flips += '='

# Base64 decode the reversed string
decoded_bytes=base64.b64decode(reversed_flips) 
print("Decoded bytes (second): \n", decoded_bytes)

# Base64 decoding of key string 
bittys=base64.b64decode(string3)
print("Decoded key (string3): \n", bittys)

# XOR decode to get back the contents of the topsneaky.txt file
original_content=xor_decrypt(decoded_bytes, bittys)
print("Original content (bytes):", original_content)
