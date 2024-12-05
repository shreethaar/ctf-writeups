---
title: ex03.exe
layout: default
---
### Solution:

##### 1. Use CFF Explorer to remove .reloc data section

![]()

**Knowing what is `.reloc` data:
- It contains data which allows the PE file to be loaded at different address each time it is executed (.reloc = relocation)
- It contains pointers to functions or variables
- It also has address references for dynamic linking or imported functions

**Reason to remove `.reloc` data:
- Improving debugging behavior
- Easier to analyze 

##### 2. Use IDA to diassemble and identify suitable breakpoints




##### 3. Use x32dbg to set breakpoints
