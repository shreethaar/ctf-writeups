---
title: social-distancing
layout: default
---

# Social Distancing

We all remember the time of social distancing and quarantines. How about some quarantined malware? Bet you can't understand what it entails!

- Category: forensic
- Challenge file: handout\_social-distancing.zip

### Solution:

##### Step 1: Unzip and check the files contains from the zip

```sh
$ sudo unzip handout_social-distancing.zip 
Archive:  handout_social-distancing.zip
   creating: Quarantine/Entries/
 extracting: Quarantine/Entries/{80008A1B-0000-0000-7091-E5797219933B}  
   creating: Quarantine/ResourceData/
   creating: Quarantine/ResourceData/95/
 extracting: Quarantine/ResourceData/95/957997B71FBF912F2A3E881A13A83E0FAB3ECB47  
   creating: Quarantine/Resources/
   creating: Quarantine/Resources/95/
 extracting: Quarantine/Resources/95/957997B71FBF912F2A3E881A13A83E0FAB3ECB47
 ```

Based on the file structure, my assumptions this malware came from Windows System. 

##### Step 2: Analyze the file hierarchy structure of Quarantine and its subfolder

- Quarantine/Entries/

This folder is likely to include metadata or logs that record the specifics of the quarantined files. The file {80008A1B-0000-0000-7091-E5797219933B} appears to be an entry, presumably represented by a unique identifier, and may include information on the quarantined file (such as its source, quarantine date, or status).

- Quarantine/ResourceData/

This folder may include extra information about the quarantined files, such as hash values, flags, or other properties specific to each confined resource. While for the file 957997B71FBF912F2A3E881A13A83E0FAB3ECB47 might be the quarantined resource itself or an identification for some component of it.

- Quarantine/Resources/

This folder likely holds the quarantined files or a part of the resources that were flagged for isolation. 


##### Step 3: Use dexray to recover the quarantine malware

```sh
$ dexray Quarantine/
```

##### Step 4: Check the strings from the malware

```sh
$ strings 957997B71FBF912F2A3E881A13A83E0FAB3ECB47.00000280_Defender.out
```

##### Step 5: Decode the base64 strings 

```sh
$ echo "UEsDBAoAAAAAAOCYuCg8z1FoRAAAAEQAAAAJABwAZWljYXIuY29tVVQJAAOUYCw5y1zNZnV4CwAB
BAAAAAAEAAAAAFg1TyFQJUBBUFs0XFBaWDU0KFBeKTdDQyk3fSRFSUNBUi1TVEFOREFSRC1BTlRJ
VklSVVMtVEVTVC1GSUxFISRIK0gqUEsDBAoAAAAAAE8HG1mJ3nc0MQAAADEAAAAEABwAZmxhZ1VU
CQAD9VzNZtVczWZ1eAsAAQQAAAAABAAAAABDU0NURnt5MHVfdW4tcXU0cmFudDFuM2RfbXlfc2Ny
MVB0IV8weDkxYTNlZGZmNn0KUEsBAh4DCgAAAAAA4Ji4KDzPUWhEAAAARAAAAAkAGAAAAAAAAQAA
AKSBAAAAAGVpY2FyLmNvbVVUBQADlGAsOXV4CwABBAAAAAAEAAAAAFBLAQIeAwoAAAAAAE8HG1mJ
3nc0MQAAADEAAAAEABgAAAAAAAEAAACkgYcAAABmbGFnVVQFAAP1XM1mdXgLAAEEAAAAAAQAAAAA
UEsFBgAAAAACAAIAmQAAAPYAAAAAAA==" | base64 -d 
```

the output:
```
PK
���(<�QhDD	eicar.comUT	�`,9�\�fux
                                          X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*PK
O��w411flagUT	�\�f�\�fux
                          CSCTF{y0u_un-qu4rant1n3d_my_scr1Pt!_0x91a3edff6}
PK
���(<�QhDD	��eicar.comUT�`,9ux
                                   PK
O��w411���flagUT�\�fux
```

**Flag:** `CSCTF{y0u_un-qu4rant1n3d_my_scr1Pt!_0x91a3edff6}`
