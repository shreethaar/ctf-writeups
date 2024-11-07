---
title: good_boy
layout: default
---

# good\_boy

Just find the passwork.

- Category: rev
- Challenge author: fdisotto
- Challenge link: [crackmes.one](https://crackmes.one/crackme/669a714890c4c2830c820bc0)

### Solution:

##### 1. Verify the binary build information

```bash
$ file good_boy
good_boy: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```
The debugged symbol of this binary is stripped

##### 2. Use IDA to decompile the binary

Here is the main function of the decompiled C code from the binary:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  const char *v3; // rdi
  void (*v4)(void); // rdx
  char v6[10]; // [rsp+Ah] [rbp-11Eh] BYREF
  __int16 v7; // [rsp+14h] [rbp-114h]
  unsigned __int64 v8; // [rsp+118h] [rbp-10h]

  v8 = __readfsqword(0x28u);
  strcpy(v6, "h4x0r");
  __printf_chk(1LL, "Enter the password: ");
  __isoc99_scanf("%255s", &v6[6]);
  if ( *(_DWORD *)v6 == *(_DWORD *)&v6[6] && *(_WORD *)&v6[4] == v7 )
  {
    v3 = "Good boy!";
    puts("Good boy!");
  }
  else
  {
    v3 = "Bad boy!";
    puts("Bad boy!");
  }
  if ( v8 != __readfsqword(0x28u) )
    start((__int64)v3, (__int64)&v6[6], v4);
  return 0LL;
}
```

It uses `strcmp` to validate user input against a specific memory pattern stored in the local variable v6. 
At `strcpy(v6, "h4x0r");` is the corret password that need to be input as

##### 3. Enter the correct password

```bash
$ ./good_boy
Enter the password: h4x0r
Good boy!
```

