---
title: "Simple Overflow"
layout: default"
---

# Simple Overflow

This is a very simple crackme. The goal is to get "you are logged in as admin". Patching is not allowed. The solution should contain an exact description, how this works. Have fun!

- Category: rev
- Challenge author: BitFriends
- Challenge link: [crackmes.one](https://crackmes.one/crackme/5f05ec3c33c5d42a7c66792b)

### Solution:

##### 1. Run the binary

```bash
$ ./a.out
enter password: test
uid: 1
you are logged in as user
```

The binary accept any strings and logged in as user, but our goal is to logged in as admin


##### 2. Use IDA to view its assembly code

As the binary will have some check function to validate the admin input

![pic1](pic1.jpg)


