---
title: Broken Secrets
layout: default
---
# Broken Secrets

You’ve found a suspicious file, but it seems broken and cannot be opened normally. Your goal is to uncover its secrets.

- Category: Forensic
- Challenge File: Brokenfr

### Solution
##### 1. File command to gather basic information of the file
```bash
$ file Brokenfr 
Brokenfr: 7-zip archive data, version 0.4
```

The file indicates a 7-zip archive data, unzip using 7zip able to view the contents of it

##### 2. Extract using 7z command

```bash
$  7z x Brokenfr 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 10240 bytes (10 KiB)

Extracting archive: Brokenfr
--
Path = Brokenfr
Type = 7z
Physical Size = 10240
Headers Size = 451
Method = LZMA2:96k
Solid = +
Blocks = 1

Everything is Ok

Folders: 7
Files: 12
Size:       68979
Compressed: 10240 
```

After successfully extracting out the contents, it will be stored in a `_` directory. After that, using `tree` command to know what are other files are stored in the extracted directory

##### 3. Tree to view subdirectories 

```bash
$ tree
.
├── _
│   ├── [Content_Types].xml
│   ├── docProps
│   │   ├── app.xml
│   │   └── core.xml
│   ├── _rels
│   └── word
│       ├── document.xml
│       ├── fontTable.xml
│       ├── media
│       │   └── not_so_suspicious_file
│       ├── _rels
│       │   └── document.xml.rels
│       ├── settings.xml
│       ├── styles.xml
│       ├── theme
│       │   └── theme1.xml
│       └── webSettings.xml
```

This file structure is showing the contents of a Microsoft Word (.docx) file when extracted as ZIP archieve.

Here is the breakdown:
- `[Content_Types].xml`: Defines the types of contents within the documents 
- `docProps/`: Contains metadata about the documents 
	- `app.xml`: Application-specific properties 
	- `core.xml`: Core metadata (author, creation data, title)
- `_rels/`: Stores relationships between files insides the documents
- `word/`: Main Word documents contents:
	- `document.xml`: The actual document text in XML format
	- `fontTable.xml`: Font information used in the document 
	- `media/`: Stores embedded images or files (`not_so_suspicious_file`) could be the embedded object
	-  `_rels/document.xml.rels` – Relationships defining linked files (e.g., images, hyperlinks).
	- `settings.xml` – Document settings (e.g., compatibility settings, protection options).
	- `styles.xml` – Style definitions for formatting text.
	- `theme/theme1.xml` – Theme data (colors, fonts, effects).
	- `webSettings.xml` – Web-related settings (e.g., hyperlinks, browser view options).

After the discover, `media/not_so_suspicious_file` could indicate an embedded malicious object, for example OLE file, macro-enabled payload or steganographic content. 

##### 4. Analyze not_so_suspicious_file
By analyzing the hex file header of the file, it indicates a PNG file with a corrupted header. 

![[acectf-forensic1.png]]

Example of a correct PNG Header:
```
[00000000] 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52   .PNG........IHDR
```

The first four of byte offset seems incorrect, that makes it unable to determine the file format via `file` command. A simple fixed replacement able to view the PNG image. Here is the image file: 

![[acectf-forensic2.png]]

**Flag:** `ACECTF{h34d3r_15_k3y}`