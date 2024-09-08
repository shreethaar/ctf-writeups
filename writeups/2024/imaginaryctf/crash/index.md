---
title: crash
layout: default
---

# crash

Description:

I didn't save my work...

- Category: forensic
- Challenge file: dump.vmem

### Solutions:

1. windows.pslist | grep notepad

2. window.dumpfiles --pid 2216

3. strings pid.2216.dmp | grep flag -> will find flag.txt at C:\\Users\\imaginarypc\\Documents\\flag.txt 

4. windows.filescan | grep flag.txt

5. windows.dumpfiles --virtaddr 0xc60c81c70ce0

6. cat file.0xc60c81c70ce0.0xc60c83b5e650.DataSectionObject.flag.txt.dat| base64 -d


**Flag:** `ictf{aa0eb707a41b2ca6}`
