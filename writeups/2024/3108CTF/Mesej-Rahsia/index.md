---
title: Mesej-Rahsia
layout: default
---

# Mesej Rahsia
Tak susah pun, run je script

- Category: Crypto
- Challenge file: secretMessenger.py

### Solution

##### 1. Analyze the Python script
```py
a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z='j','b','a','c','m','n','i','p','o','q','r','t','x','z','v','s','u','y','h','g','d','e','f','k','l','w'
flag=((3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}")[::-1])
```
From this code, we couldn't able the see an output as there is no `print()` and `join()` method to return the flag string

##### 2. Modify the Python script 
```py
a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z='j','b','a','c','m','n','i','p','o','q','r','t','x','z','v','s','u','y','h','g','d','e','f','k','l','w'
flag=((3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}")[::-1])
print("".join(map(str,flag))) # character mapping and print as string
```

##### 3. Run the Python script
```sh
$ python3 secretMessage.py
}txet_rehpic_etutitsbus{3108
```
It seems the flag header and flag payload string is reversed

##### 4. Reconstruct Flag String
`}txet_rehpic_etutitsbus{3108` ->  `3108{substitute_cipher_text}`\n
There you go, flag for the challenge

**Flag:** `3108{substitute_cipher_text}`









