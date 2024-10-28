---
title: "Authorize by PIN"
layout: default
---

# Authorize by PIN

Small easy crackme, where you gotta guess the pin :)

- Category: rev
- Challenge author: AnanasCharles
- Challenge link: [crackmes.one](https://crackmes.one/crackme/6617d3a5cddae72ae250c556)

### Solution:

##### 1. Use IDA to decompile the binary

As the binary file is not stripped, we can notice functions like `main`, `encode_pin`,`decode_pin` and `decode_string`

![functions](functions.jpg)

##### 2. Analyze main function 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v4; // rdx
  const char *v5; // [rsp+10h] [rbp-30h]
  size_t v6; // [rsp+28h] [rbp-18h]
  char *s1; // [rsp+38h] [rbp-8h]

  if ( argc == 2 )
  {
    s1 = (char *)decode_pin(argv[1], argv, envp);
    v6 = strlen(argv[1]);
    v4 = strlen("8446");
    if ( !strncmp(s1, "8446", v4) && v6 == strlen(s1) )
    {
      puts("Correct PIN entered!");
      v5 = (const char *)decode_string("}|.wOlHtc}j@z9jf3 O Q", argv[1]);
      printf("Decoded String: %s\n", v5);
      return 0;
    }
    else
    {
      puts("This is not right");
      return 1;
    }
  }
  else
  {
    printf("Usage: %s <pin>\n", *argv);
    return 1;
  }
}
```

From the main function, there are key points would like to highlight:
- To execute the file, `./authorize <PIN>`, as it will check the second argument
- After that the `<PIN>` that was input will be use by calling `decode_pin()` -> need futher analysis
- After `decode_pin()` function, the value will be stored as s1
- v6 stores the length of the raw input of PIN
- v4 is set to the length of "8446" which is 4
- First comparison: s1 (decoded PIN) must be equal to "8446" and v6 has the length of 4

##### 3. Analyze decode\_pin function

```c
_BYTE *__fastcall decode_pin(__int64 a1)
{
  int v2; // [rsp+10h] [rbp-8h]
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; i <= 3; ++i )
  {
    v2 = *(char *)(i + a1) - 53;
    decoded_pin_1[i] = v2 + (v2 < 0 ? 0xA : 0) + 48;
  }
  byte_4089 = 0;
  return decoded_pin_1;
}
```

From decode\_pin function, it does:
- perform looping for each character and transform it by subtract 53 by ASCII value
- In short: 

```
input[0]='8'+53-48
input[1]='4'+53-48
input[2]='4'+53-48
input[3]='6'+53-48
```

Here the decoding script:

```py
def test_pin(input_pin):
    result = ""
    for c in input_pin:
        v2 = ord(c) - 53
        if v2 < 0:
            v2 += 10
        result += chr(v2 + 48)
    return result

# We know the target is "8446"
# Let's try all possible single-character inputs to find our mapping
def find_pin():
    target = "8446"
    result = ""
    
    # For each position
    for target_digit in target:
        found = False
        # Try all possible ASCII characters
        for i in range(128):  # Standard ASCII range
            test_char = chr(i)
            decoded = test_pin(test_char)
            if decoded == target_digit:
                result += test_char
                found = True
                break
        if not found:
            print(f"Could not find mapping for {target_digit}")
            return None
    return result

def decode_string(encoded_str, pin):
    result = ""
    pin_len = len(pin)
    
    for i in range(len(encoded_str)):
        v5 = ord(encoded_str[i]) - ord(pin[i % pin_len])
        if v5 <= 31 or v5 > 126:
            v5 = (v5 + 63) % 95 + 32
        result += chr(v5)
    
    return result

# Find the correct PIN
pin = find_pin()
if pin:
    print(f"Found PIN: {pin}")
    print(f"Verification (should be 8446): {test_pin(pin)}")
    
    # Decode the secret message
    encoded_message = "}|.wOlHtc}j@z9jf3 O Q"
    decoded_message = decode_string(encoded_message, pin)
    print(f"\nDecoded message: {decoded_message}")
else:
    print("Failed to find valid PIN")
```

The correct PIN will be: `3991`

##### 4. Try it with the correct PIN

```bash
$ ./authorize 3991
Correct PIN entered!
Decoded String: JCTF{3nC0D1nG_15_FuN}
```


