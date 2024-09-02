---
title: Sembunyi
layout: default
---

# Sembunyi

Pahang, negeri terbesar di Semenanjung Malaysia, terkenal dengan keindahan alam semula jadi yang memukau, termasuk hutan hujan tropika yang luas, gunung-gunung tinggi seperti Gunung Tahan, serta pantai-pantai yang mempesonakan di Cherating dan Kuantan. Negeri ini juga kaya dengan sejarah dan budaya, menjadi rumah kepada bandar diraja Pekan dan pusat pelancongan tanah tinggi Cameron Highlands.

terdapat satu dokumen lama yang menceritakan sejarah tersembunyi negeri Pahang, bantu saya baca teks tersebut perwira sekalian!

- Category: Misc
- Challenge File: rahsia.txt

### Solution

##### Step 1: Check for strings 
```
$ strings rahsia.txt
```

##### Step 2: View the hex dump of the file
```
$ xxd rahsia.txt
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
file_path = 'rahsia.txt'  # Replace with the actual file path
decoded_message = decode_ctf_challenge_from_file(file_path)
print(decoded_message)
```

##### Step 4: After binary conversion from the script
```sh
$ python3 script.py
3108{S3jarah_Ters3mbunyi_P4hang}
```

**Flag:** `3108{S3jarah_Ters3mbunyi_P4hang}`



