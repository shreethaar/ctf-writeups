---
title: Sarawak-Kita
layout: default
---

# Sarawak Kita
Ada pendapat yang menyatakan bahawa Kuching mendapat nama sempena sebatang sungai kecil, Sungai Kuching yang mengalir di antara Muzium Cina dan Kuil Tua Pek Kong. Sungai Kuching pula barangkali memperoleh nama daripada Kucing Hutan yang kerap mengunjunginya. Sungai tersebut juga berhampiran dengan sebuah bukit yang banyak ditumbuhi oleh pokok Buah Mata Kucing. Lantaran tersebut ianya diberi nama Bukit Mata Kucing. Tapi ini bukan tentang kisah Kuching, ini kisah bagaimana ingin mendapatkan 'flag' di dalam document yang berbahaya.

Category: Rev
Challenge File: Sarawak\_KITA.doc.bin

### Solution

##### Step 1: Analyze the file 
<img src="1.png" alt="static-analysis" style="width: 80%; height: 80%;">

##### Step 2: Extract the embedded content in the file
```sh
$ binwalk Sarawak_KITA.doc.bin
```
<img src="2.png" alt="binwalk-extract">

##### Step 3: Analyze the embedded content
```sh
$ tree _Sarawak_KITA.doc.bin.extracted
```

<img src="3.png" alt="tree" style="width: 60%; height:60%;">

##### Step 4: vbaProject.bin malicious content 
```sh
$ xxd word/vbaProject.bin
```

<img src="4.png" alt="xxd" style="width: 80%; height: 80%;">


##### Step 5: Decode base64 string from vbaProject.bin
```sh
echo "MwAxADAAOAB7AEsAdQBjAGgAMQBuAGcAXwAxAGIAdQBfAE4AMwBnADMAcgAxAF8AUwA0AHIANAB3ADQAawB9AA==" | base64 -d
3108{Kuch1ng_1bu_N3g3r1_S4r4w4k}
```

**Flag:** `3108{Kuch1ng_1bu_N3g3r1_S4r4w4k}`



