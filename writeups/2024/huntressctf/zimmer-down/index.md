---
title: Zimmer Down
layout: default
---

# Zimmer Down

A user interacted with a suspicious file on one of our hosts.
The only thing we managed to grab was the user's registry hive.
Are they hiding any secrets?

- Category: forensic
- Challenge file: NTUSER.DAT

### Solution:

##### 1. Use RegRipper to analyze hive file



##### 2. Analyze the output file from RegRipper



From perform analysis on the output file, we able to notice suspicious files under `recentdocs` plugin which is about the files and directories recently accessed by the user. 



##### 3. Use CyberChef to decode the suspicious string


**Flag:** `flag{4b676ccc1070be66b1a15dB601c8d500}`


