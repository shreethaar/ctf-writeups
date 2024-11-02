---
title: No need for Brutus
layout: default
---

# No need for Brutus

A simple message for you to decipher:

squiqhyiiycfbudeduutvehrhkjki

Submit the original plaintext hashed with MD5, wrapped between the usual flag format: `flag{}`

### Solution:

Based on the title, it mention Brutus, means something related to rotation cipher

##### Step 1: Bruteforce attempt with ROT

Generate a script to perform all possible rotation and then hash it with md5

```py
import string
import hashlib

def rotate_string(text, shift):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    shifted_lower = lowercase[shift:] + lowercase[:shift]
    shifted_upper = uppercase[shift:] + uppercase[:shift]
    trans = str.maketrans(lowercase + uppercase, 
                         shifted_lower + shifted_upper)
    return text.translate(trans)

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

text = "squiqhyiiycfbudeduutvehrhkjki"
print("Original text:", text)
print("\nRotation Results:")
print("-" * 50)
for i in range(1, 27):
    rotated = rotate_string(text, i)
    hashed = md5_hash(rotated)
    flag = f"flag{{{hashed}}}"
    
    print(f"ROT-{i:2d}: {rotated}")
    print(f"Flag : {flag}")
    print("-" * 50)
```

Run the script and notice ROT10 give me meaningful text

```
--------------------------------------------------
ROT-10: caesarissimplenoneedforbrutus
Flag : flag{c945bb2173e7da5a292527bbbc825d3f}
--------------------------------------------------
```

**Flag:** `flag{d093e5bbb9be5b078de1ef6017171db8}`

