---
title: CPUsage
layout: default
---

# CPUsage

Description: My friend noticed a high usage of CPU after he opened his laptop, I just take a memory dump of his laptop, and needs you to investigate it. Q1- What is the name of the malicious process, full path of the process, parent process id? Q2- what is the ip that process communicate with, family name of the malware?

**Format flag:** `ISITDTU{processName-FullPath-ID_ip-FamilyName}` Eg: `ISITDTU{Spotify.exe-Path-141_192.168.1.1-isitdtu}`

### Solution

##### 1. Use windows.info to retrive initial information of memory dump




##### 2. Check running process with windows.pslist

From the question, it stated there is a high usage of CPU.



From the output, we will notice a suspicious process is running with PPID of `svchost.exe`. The `svchost.exe` is a system process which host and run Windows service for the OS system core functions and services. Services hosted by svchost.exe are loaded from legitimate, signed .dll files in `C:\Windows\System32` or other verified Windows directories. For this case, we notice that `dlIhost.exe` is running from `C:\Users\m4shl3\AppData\Roaming\DLL\dlIhost.exe`.



##### 3. Check network connection from dlIhost.exe




##### 4. Extract dlIhost with filescan and dumpfiles
