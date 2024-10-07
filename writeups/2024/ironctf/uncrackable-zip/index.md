---
title: Uncrackable Zip
layout: default
---

# Uncrackable Zip

I forgot to ask my friend for the password to access the secret webpage, and now he's unavailable. I've tried guessing the password, but it's been unsuccessful. My friend is very security-conscious, so he wouldn't use an easy-to-guess password. He's also an Emmet enthusiast who relies heavily on code generation shortcuts. Can you help me figure out how to access the secret webpage?

- Category: forensic
- Challenge file: website zip

### Solution:

##### 1. Verify compression type and contents in archieved zip

To verify the compression method for the password-protected zip file:
```bash
$ file website.zip
website.zip: Zip archive data, at least v2.0 to extract, compression method=store
```

To check the contents in the zip file:
```bash
$ unzip -v website.zip
Archive:  website.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
     274  Stored      274   0% 2024-09-14 00:02 7a0a2e19  index.html
--------          -------  ---                            -------
     274              274   0%                            1 file
```

From here, we should take note of two things:
1. Stored compression method is used for archieving the file
2. Only one file is contained which is index.html file

exiftool able to perform such operations as well:
```sh
exiftool website.zip
ExifTool Version Number         : 12.96
File Name                       : website.zip
Directory                       : .
File Size                       : 440 bytes
File Modification Date/Time     : 2024:09:13 20:02:30+00:00
File Access Date/Time           : 2024:10:07 05:33:09+00:00
File Inode Change Date/Time     : 2024:10:06 23:18:58+00:00
File Permissions                : -rw-r--r--
File Type                       : ZIP
File Type Extension             : zip
MIME Type                       : application/zip
Zip Required Version            : 20
Zip Bit Flag                    : 0x0001
Zip Compression                 : None
Zip Modify Date                 : 2024:09:14 00:02:10
Zip CRC                         : 0x7a0a2e19
Zip Compressed Size             : 286
Zip Uncompressed Size           : 274
Zip File Name                   : index.html
```

##### 2. Use bkcrack to crack the zip file

In order to crack open the zip, it is a requirement to have a plaintext of 12-bytes from the contained file, which is index.html

Typical html file is start like this:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

```

We only required to get the first 12-bytes, which is `<!DOCTYPE html>`:
```bash
echo -n '<!DOCTYPE html>' | xxd -p
3c21444f43545950452068746d6c3e
```

and now we create a plaintext file which contain the first 12 byte of html file. 
```bash
echo -n "3c21444f43545950452068746d6c3e" | xxd -r -p > plaintext.bin
```

##### 3. Crack the zip file with plaintext html file
```bash
bkcrack -C website.zip -c index.html -p plaintext.bin
```

And then we wait for bkcrack to cook, be patient

Output of bkcrack upon successful:
```bash
bkcrack 1.7.0 - 2024-05-26
[05:55:38] Z reduction using 8 bytes of known plaintext
100.0 % (8 / 8)
[05:55:38] Attack on 809734 Z values at index 6
Keys: a18ba181 a00857dd d953d80f
71.8 % (581305 / 809734)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 581305
[06:11:41] Keys
a18ba181 a00857dd d953d80f
```

Now, we have the keys of the zip file

##### 4. Remove the password into a new zip file

```bash
bkcrack -C website.zip -k a18ba181 a00857dd d953d80f -D without-pass.zip
bkcrack 1.7.0 - 2024-05-26
[06:14:45] Writing decrypted archive without-pass.zip
100.0 % (1 / 1)
```

##### 5. String the contents of the removed password zip

Since the encryption has been removed, we can view the contents in plaintext:

```bash
strings without-pass.zip
index.html<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flag</title>
</head>
<body>
    ironCTF{Wh0_us35_Z1pCrypt0_wh3n_kn0wn_PlA1nt3xt_a7t4cks_ex1s7?}
</body>
</html>PK
index.html
```

**Flag:** `ironCTF{Wh0_us35_Z1pCrypt0_wh3n_kn0wn_PlA1nt3xt_a7t4cks_ex1s7?}`
