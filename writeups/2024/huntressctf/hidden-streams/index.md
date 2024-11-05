---
title: Hidden Streams
layout: default
---

# Hidden Streams

Beneath the surface, secrets glide,
A gentle flow where whispers hide.
Unseen currents, silent dreams,
Carrying tales in hidden streams.

Can you find the secrets in these Sysmon logs?

- Category: forensic
- Challenge file: Sysmon.evtx

### Solution:

##### 1. Parse the evtx to XML or CSV files

Initially, I used Event Log Explorer to view the evtx file, it has 2850 entries. It would be better to convert it to parse-able file format such as XML/CSV

Here is the Python script:

```
from Evtx.Evtx import Evtx
import sys

input_file = "Sysmon.evtx"
output_file = "eventlog.xml"

with Evtx(input_file) as evtx_log, open(output_file, "w") as xml_file:
    xml_file.write("<Events>\n")
    for record in evtx_log.records():
        xml_file.write(record.xml() + "\n")
    xml_file.write("</Events>")
```

##### 2. Use Timeline Explorer to analyze 

To use Timeline Explorer, it should be in CSV file format. After that, we can sort based on Event ID. After that, we will notice only one Event ID of 15. Checking the Event Data of Event ID 15, we notice base64 string `ZmxhZ3tiZmVmYjg5MTE4MzAzMmY0NGZhOTNkMGM3YmQ0MGRhOX0`

##### 3. Decode the base64 string 

```bash
$ echo "ZmxhZ3tiZmVmYjg5MTE4MzAzMmY0NGZhOTNkMGM3YmQ0MGRhOX0" | base64 -d
flag{bfefb891183032f44fa93d0c7bd40da9}
```

**Flag:** `flag{bfefb891183032f44fa93d0c7bd40da9}`
