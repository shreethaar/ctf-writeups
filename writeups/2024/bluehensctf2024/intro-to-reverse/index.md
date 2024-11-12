---
title: Intro to Reverse
layout: default
---

# Intro to Reverse

Just a classic flagchecker

- Category: reverse
- Challenge file: flagchecker

### Solution:

##### 1. Static analysis 

```bash
$ file flagchecker
flagchecker: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dd6cc74a2be018b5759775e8e2680b4e09655910, for GNU/Linux 3.2.0, not stripped
```

The binary is not stripped and we can analyze the functions without any issues

##### 2. Decompile and view the main function

I use IDA to view the main function code, here it is:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-44h]
  char v5[32]; // [rsp+10h] [rbp-40h] BYREF
  char s[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  strcpy(v5, "ucaqbvl,n*d\\'R#!!l");
  v5[19] = 0;
  fgets(s, 19, _bss_start);
  for ( i = 0; i <= 17; ++i )
  {
    if ( s[i] - i != v5[i] )
    {
      puts("wrong");
      return 1;
    }
  }
  puts("You got it!");
  return 0;
}
```

Explaination:
- `v5[32]`: Buffer which contain the hardcorded string "ucaqbvl,n\*d'R#!!l"
- `s[24]`: Buffer to store input from user
- `v7`: Stack canary for security from `fgets`
- Main logic: Loops through each character and check `input[i] - i = v5[i]`

##### 3. Decode the logic 

Here is the python script to decode the logic operation from the binary

```py
v5 = "ucaqbvl,n*d\\'R#!!l"
s = ''.join(chr(ord(v5[i]) + i) for i in range(18))
print(s)
```

**Flag:** `udctf{r3v3ng3_101}`

Here is more readible version of the C code:

```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define MAX_INPUT_LENGTH 19
#define EXPECTED_LENGTH 18

int main(int argc, const char **argv, const char **envp) {
    char encoded_password[23] = "ucaqbvl,n*d\'R#!!l"
    encoded_password[EXPECTED_LENGTH + 1] = '\0';
    char user_input[24];
    printf("Enter password:");
    if(!fgets(user_input,MAX_INPUT_LENGTH,stdin)) {
        printf("Error reading input!\n");
        return 1;
    }

    user_input[strcspn(user_input,"\n")]=0;
    bool password_valid = true;
    for(int i=0; i<EXPECTED_LENGTH;++i){
        char decoded_char = user_input[i]-i;
        if(decoded_char!=encoded_password[i])
            password_valid=false;
            break;
        }
    }
    if(password_valid) {
        printf("You got it!\n");
        return 0;
    }
    else {
        printf("Wrong password!\n");
        return 1;
    }
}
```
