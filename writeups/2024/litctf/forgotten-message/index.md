---
title: forgotten-message
layout: default
---

# forgotten-message
I made a cool program to show the flag, but i forgot to output it! Now that I lost the source, I can't seem to remember the flag. Can you help me find it?

- Challenge file: forgetten-message
- Category: rev

Solution:

### 1. Static Analysis

<a href="image1.png">
    <img src="image1.png" alt="Static Analysis">
</a>

Since the executable is not stripped, where we can analyze the debugging symbols which has the possibility of containing the flag string

### 2. Use $strings and $grep

<a href="image2.png">
    <img src="image2.png" alt="Debug Symbols">
</a>

We can utilize grep with the flag header "LITCTF" and get the flag. 

**Flag:** `LITCTF{y0u_found_Me_3932cc3}`

