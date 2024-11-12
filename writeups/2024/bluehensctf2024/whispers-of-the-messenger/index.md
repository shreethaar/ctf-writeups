---
title: Whispers of the Feathered Messenger
layout: default
---

# Whispers of the Feathered Messenger

In a world where secrets flutter through the air, the bluehen carries a hidden message. A message that has been salted.... however its still a message... maybe the bluehen ignores the salt. This image holds more than meets the eye.

shasum: e717eefe9b41212b017152756b0e640f9a4f3763 bird.jpeg

- Category: forensic
- Challenge file: bird.jpeg

This is the image of bird.jpeg:

![bird](bird.jpeg)

### Solution:

##### 1. View the image metadata with exiftool

```bash
$ exiftool bird.jpeg

ExifTool Version Number         : 13.02
File Name                       : bird.jpeg
Directory                       : .
File Size                       : 323 kB
File Modification Date/Time     : 2024:11:12 06:18:37+00:00
File Access Date/Time           : 2024:11:12 06:18:32+00:00
File Inode Change Date/Time     : 2024:11:12 06:18:40+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 72
Y Resolution                    : 72
Comment                         : UGFzc3dvcmQ6IDVCNEA3cTchckVc
Image Width                     : 1080
Image Height                    : 1350
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1080x1350
Megapixels                      : 1.5
```

There is a base64 encoded string as the comment, decode it 

```bash
$ echo "UGFzc3dvcmQ6IDVCNEA3cTchckVc" | base64 -d
Password: 5B4@7q7!rE\
```
Based on the output, I suspect it uses `steghide` to embedded files with the password

##### 2. Use steghide to extract the hidden files

Here is the commmand to extract hidden files with steghide

```bash
$ steghide extract -sf bird.jpeg
Enter passphrase: {use the password from the comment}
wrote extracted data to "encrypted_flag.bin".
```

##### 3. Verify the file type of the bin

```bash
$  file encrypted_flag.bin
encrypted_flag.bin: openssl enc'd data with salted password
```

This file is encrypted, to view it we can use the same password as before

##### 4. Decrypted encrypted\_flag.bin

Here is how to decrypt with openssl

```bash
$ openssl enc -d -aes-256-cbc -in encrypted_flag.bin -out decrypted_flag.txt
```

**Flag:** `UDCTF{m0AybE_YoR3$!_a_f0recnicsEs_3xpEr^t}`


