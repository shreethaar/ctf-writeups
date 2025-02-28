---
title: Challenge 3
layout: default
---

# Challenge 3: Shellolololol

Given a binary named `such_evil`, lets inspect and get some information about it using Detect-It-Easy and PE-Studio

Here is the basic information gathered:
- File type: PE32
- Compiler: Tiny C
- Stripped to externel PDB

### Solution:
##### 1. Use IDA to decompiled to binary to view functions
At `sub_401000` which is the main function (after \_start function). We notice a lot data been declared and c function like `strncpy` and `memcpy` is used. 

![[flare-on-1-chall-3-001.png]]

##### 2. Use debugger to trace initialized values

We can set a breakpoint at the address of `401000` and step until it return and observe the behaviour. 

Here is what is returned:
![[flare-on-1-chall-3-002.png]]

At noticed that ebp is at `0019FF70`. We can then check back at memory dump value. When checking back at memory view region, notice a unique string. 
![[flare-on-1-chall-3-003.png]]

We got our flag by analyzing the memory dump after the last execution call. 

**Flag:** `such.5h311010101@flare-on.com`

