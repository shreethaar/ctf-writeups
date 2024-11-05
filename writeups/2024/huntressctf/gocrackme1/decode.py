def decode_string(encoded_str, key):
    # Convert string to bytes
    encoded_bytes = encoded_str.encode('ascii')
    # XOR each byte with the key
    decoded_bytes = bytes([b ^ key for b in encoded_bytes])
    # Try to decode as ASCII, fallback to hex representation
    try:
        return decoded_bytes.decode('ascii')
    except UnicodeDecodeError:
        return decoded_bytes.hex()

# The encoded string from the binary
encoded = "0:71-44coc``3dg0cc3c`nf2cno0e24435f0n+"
key = 0x56

decoded = decode_string(encoded, key)
print(f"Decoded string: {decoded}")
