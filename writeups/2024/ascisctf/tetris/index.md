---
title: Tetris
layout: default
---

# Tetris

Would you like to play a game?
http://183.91.11.30:1300

- Category: misc

### Solution:

##### 1. Inspect page source

From the page source, you will notice a javascript for audio play which states steganography along with `texture.jpg`

##### 2. Download the texture.jpg and view its metadata

```sh
$ exiftool texture.jpg
ExifTool Version Number         : 12.96
File Name                       : texture.jpg
Directory                       : .
File Size                       : 46 kB
File Modification Date/Time     : 2024:10:05 04:26:23+00:00
File Access Date/Time           : 2024:10:05 04:26:40+00:00
File Inode Change Date/Time     : 2024:10:05 04:26:26+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Resolution Unit                 : inches
X Resolution                    : 100
Y Resolution                    : 100
Exif Byte Order                 : Big-endian (Motorola, MM)
XP Comment                      : ASCIS{Greetings and welcome. I want to play a game}
Padding                         : (Binary data 268 bytes, use -b option to extract)
Comment                         : #��...T.0.0.T..f.4.f..@..@.@..@........9@.....@.9).@..@..)@,.@.@..@,@1...@19%%9I6Ikk�
                                                                                                                       Image Width                     : 626
Image Height                    : 800
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 626x800
Megapixels                      : 0.501
```

The flag is at XP comment, alternatively can pipe it with `grep ASCIS` for cleaner view of flag

**Flag:** `SCIS{Greetings and welcome. I want to play a game}`


