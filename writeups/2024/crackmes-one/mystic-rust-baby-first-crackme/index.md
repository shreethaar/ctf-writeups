---
title: baby's first crackme
layout: default
---

# baby's first crackme

I made it with a certain password (you would know it if you get it), but there are many passwords that work

- Category: rev
- Challenge author: mystic\_rust
- Challenge link: [crackmes.one](https://crackmes.one/crackme/66736380e7b35c09bb266f92)

### Solution:

##### 1. Use IDA to decompile the binary 

After decompile, we just have observe three functions: `main`, `encode_input` and `check_key`

main function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+14h] [rbp-Ch]
  char *s; // [rsp+18h] [rbp-8h]

  if ( argc > 2 )
  {
    s = (char *)argv[1];
    v4 = atoi(argv[2]);
    if ( strlen(s) == 12 && v4 < 0x33 )
    {
      s[strcspn(s, "\n")] = 0;
      check_key((__int64)s, v4);
      return 0;
    }
    else
    {
      puts("Access denied!");
      return -1;
    }
  }
  else
  {
    puts("usage: ./rust-1 <key> <number>");
    return -1;
  }
}
```

encode\_input function: 

```c
unsigned __int64 __fastcall check_key(__int64 a1, char a2)
{
  int v3; // [rsp+14h] [rbp-5Ch]
  int i; // [rsp+18h] [rbp-58h]
  char s[56]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  encode_input(a1, a2, (__int64)s);
  for ( i = 0; i < strlen(s); ++i )
    v3 = s[i];
  if ( v3 == 124 )
    puts("Access granted!");
  else
    puts("Access denied!");
  return v6 - __readfsqword(0x28u);
}
```

check\_key function:

```c
unsigned __int64 __fastcall check_key(__int64 a1, char a2)
{
  int v3; // [rsp+14h] [rbp-5Ch]
  int i; // [rsp+18h] [rbp-58h]
  char s[56]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v6; // [rsp+58h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  encode_input(a1, a2, (__int64)s);
  for ( i = 0; i < strlen(s); ++i )
    v3 = s[i];
  if ( v3 == 124 )
    puts("Access granted!");
  else
    puts("Access denied!");
  return v6 - __readfsqword(0x28u);
}

```

Here is how to code execution flow:
- `main` function: takes two input, first one is string with 12 characters and second one will be decoded into ascii, the condition of the second argument should less than `0x33`, also means less than `51` in ASCII. If all conditions satisfy, it will past it to `check_key`.
- `check_key`: Here it does postitional shifting by with the second argument. For each byte in the input, if the byte value is odd, it subtract `2 * a2`, if is even, it adds `a2` to byte. 

For better understanding:

| Position (i) | Character Value | Position Check (Odd/Even) | Value Check (Odd/Even) | Transformation Applied           | Result in Encoded Output (i + a3)  |
|--------------|-----------------|---------------------------|-------------------------|----------------------------------|------------------------------------|
| Odd          | Odd             | Odd                       | Odd                     | Subtract `2 * a2` from byte      | `encoded[i] = input[i] - 2 * a2`  |
| Odd          | Even            | Odd                       | Even                    | Add `2 * a2` to byte             | `encoded[i] = input[i] + 2 * a2`  |
| Even         | Odd             | Even                      | Odd                     | Add `a2` to byte                 | `encoded[i] = input[i] + a2`      |
| Even         | Even            | Even                      | Even                    | Subtract `a2` from byte          | `encoded[i] = input[i] - a2`      |

- `encode_input`: After the shifting, it check that it should end with byte `124` which is `|`.

##### Python script to bruteforce

```
import string
from itertools import product

def encode_input(s, a2):
    encoded = []
    for i in range(len(s)):
        char = ord(s[i])  # Get ASCII value of character
        if i % 2 == 1:  # Odd index
            if char % 2 == 1:  # Odd character value
                encoded_char = char - 2 * a2
            else:  # Even character value
                encoded_char = char + 2 * a2
        else:  # Even index
            if char % 2 == 1:  # Odd character value
                encoded_char = char + a2
            else:  # Even character value
                encoded_char = char - a2
        encoded.append(encoded_char % 256)  # Ensure byte range (0-255)

    return encoded

# Brute force with a limited character set to manage search space
def find_valid_key():
    # Character set (smaller subset to make search feasible)
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    
    for a2 in range(1, 51):  # Test all values for a2 from 1 to 50
        # Generate combinations of 12-character strings from charset
        for s_tuple in product(charset, repeat=12):
            s = ''.join(s_tuple)
            
            # Encode the input
            encoded = encode_input(s, a2)

            # Check if the last encoded byte equals 124 ('|')
            if encoded[-1] == 124:
                print(f"Potential key found! s: '{s}', a2: {a2}")
                return

    print("No valid key found in the current search space.")

# Run the search
find_valid_key()
```

The correct password is `AAAAAAAAAAAz 1`

