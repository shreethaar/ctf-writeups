---
title: Sembunyi-V2
layout: default
---

# Sembunyi V2
Tahniah, perwira! Anda telah berjaya menyelesaikan cabaran pertama dan membuat Sultan Pahang berbangga. Namun, cabaran sebenar belum berakhir. Kini, anda dihadapkan dengan ujian yang lebih sukar. Ini adalah peluang untuk membuktikan kebolehan anda dalam menghadapi cabaran yang lebih mencabar!

ini pesanan dari sultan:

"Selamat datang ke cabaran seterusnya, perwira. Saya percaya anda mempunyai kemahiran untuk mengatasi segala halangan. Teruskan usaha anda, dan tunjukkan kehebatan dalam menyelesaikan cabaran ini."

- Category: Misc
- Challenge File: bendera.txt

### Solution

##### Step 1: Check for strings 
```
$ strings bendera.txt
```

##### Step 2: View the hex dump of the file
```
$ xxd bendera.txt
```

##### Step 3: Utilize Python script to convert "." to 1 and spaces to 0
```py
def decode_ctf_challenge_from_file(file_path):
    with open(file_path, 'rb') as file:
        hex_data = file.read().hex()  # Read file content and convert to hex
    
    binary_string = ''
    ascii_output = ''
    
    # Iterate over the hex data in 2-character chunks
    for i in range(0, len(hex_data), 2):
        hex_val = hex_data[i:i+2]
        
        if hex_val == '20':  # Space
            binary_string += '0'
        elif hex_val == '09':  # Tab
            binary_string += '1'
        elif hex_val == '0a':  # Newline
            # Convert the current binary string to ASCII and reset it
            if binary_string:
                ascii_output += chr(int(binary_string, 2))
                binary_string = ''
    
    # Convert any remaining binary string
    if binary_string:
        ascii_output += chr(int(binary_string, 2))
    
    return ascii_output

# Usage
file_path = 'bendera.txt'  # Replace with the actual file path
decoded_message = decode_ctf_challenge_from_file(file_path)
print(decoded_message)
```

##### Step 4: After binary conversion from the script
```sh
$ python3 script.py
3108{putih_dan_hitam_dalam_negeri_pahang}
```

**Flag:** `3108{putih_dan_hitam_dalam_negeri_pahang}`



