---
title: Giraffical Image Format
layout: default
---

# Giraffical Image Format


A student disagreed with my pronunciation of gif. They said, snarkily, how do you pronounced Graphical Image Format. This problem is my response.

- Category: forensic
- Challenge file: flag.giraffe

### Solution:

##### 1. Analyse the challenge file

Use file and wc to get some initial info.

```bash
$ file flag.giraffe
flag.giraffe: Unicode text, UTF-8 text, with very long lines (16384), with no line terminators
```

```bash
$ wc flag.giraffe
      0       1 3774208 flag.giraffe
```

If we cat out the challenge file, it will return emojis of camel and giraffee. There are 4 total emojis used. 

##### 2. Decode the emoji into binary representation

Based on my previous CTF challenge I created, which is this [here](https://0x251e-challenge.github.io/challenges/posts/lemon-and-tangerine/), we should decode into binary representation.

So we should replace the emoji into these:
```
𓃱 = 01
🦒= 00
🐪 = 10
🐫 = 11
```

##### 3. Python script to decode to binary

The python script will the emoji and decode into the following binary values and convert it again into hex-bytes, so that we can get the file format correctly

```py

import re

# Load the input data from a file (replace with your actual file path)
input_file_path = 'flag.giraffe'  # Replace this with your input file path
output_file_path = 'giraffe-out'  # Replace this with the path to save the hex-decoded file

# Read the input file
with open(input_file_path, 'rb') as file:
    input_data = file.read().decode('utf-8', errors='ignore')

# Define the replacements
replacements = {
    "𓃱": "01",  # Symbol to binary
    "🦒": "00",
    "🐪": "10",
    "🐫": "11"
}

# Perform the replacements
for symbol, binary in replacements.items():
    input_data = re.sub(re.escape(symbol), binary, input_data)

# Convert binary string to hexadecimal
binary_string = ''.join(input_data.split())  # Remove any whitespace
hex_string = hex(int(binary_string, 2))[2:]  # Convert to hex and remove the '0x' prefix

# Ensure even-length hex string (required for proper decoding)
if len(hex_string) % 2 != 0:
    hex_string = '0' + hex_string

# Save the hex output as binary to a file
with open(output_file_path, 'wb') as file:
    file.write(bytes.fromhex(hex_string))

print(f"Hex-decoded binary data saved to {output_file_path}")
```

##### 4. Analyze the output file

```bash
$ file giraffe-out
giraffe-out: GIF image data, version 89a, 600 x 300
```

We have gotten an GIF file and referring back to the question, it mentioned some details of GIF file.

View the GIF file:

![giraffe-out.gif](giraffe-out.gif)

and we gotten the flag

**Flag:** `UDCTF{pr0n0unc3d_j1f}`


