---
title: Mimi
layout: default
---

# Mimi

Uh oh! Mimi forgot her password for her Windows laptop!

Luckily, she dumped one of the crucial processes running on her computer (don't ask me why, okay)... can you help her recover her password?

NOTE: This file on its own is not malware per say, but it is likely to raise antivirus alerts. Would recommend examining this inside of a virtual environment.

- Category: malware
- Challenge file: mimi.7z

### Solution:

##### 1. Use pypykatz to parsed the mimikatz dump

You can install pypykatz from this [github repo](https://github.com/skelsec/pypykatz) or if you use Arch, you can yay it `yay -S python-pypykatz`

To use it:

```bash
$ pypykatz lsa minidump mimi
```

The output:

```
INFO:pypykatz:Parsing file mimi
FILE: ======== mimi =======
== LogonSession ==
authentication_id 709786 (ad49a)
session_id 1
username mimi
domainname windows11
logon_server WINDOWS11
logon_time 2024-09-10T02:32:50.802254+00:00
sid S-1-5-21-940291183-874774319-2012240919-1002
luid 709786
	== MSV ==
		Username: mimi
		Domain: windows11
		LM: NA
		NT: 5e088b316cc30d7b2d0158cb4bd9497c
		SHA1: c1bd67cf651fdbcf27fd155f488721f52fff64fa
		DPAPI: c1bd67cf651fdbcf27fd155f488721f52fff64fa
	== WDIGEST [ad49a]==
		username mimi
		domainname windows11
		password flag{7a565a86761a2b89524bf7bb0d19bcea}
		password (hex)66006c00610067007b00370061003500360035006100380036003700360031006100320062003800390035003200340062006600370062006200300064003100390062006300650061007d0000000000
	== Kerberos ==
		Username: mimi
		Domain: windows11
	== WDIGEST [ad49a]==
		username mimi
		domainname windows11
		password flag{7a565a86761a2b89524bf7bb0d19bcea}
		password (hex)66006c00610067007b00370061003500360035006100380036003700360031006100320062003800390035003200340062006600370062006200300064003100390062006300650061007d0000000000
	== DPAPI [ad49a]==
		luid 709786
		key_guid 0432784d-4b00-4b75-83af-2cdcc9aabb23
		masterkey a862ddb9e230fd284a02322c308ee1acd85a76b672c733cdbe6492462c5ded9709d319da4c9ec96e1f4cc52650ee0122be61938eef489182fb01bf313b1a56ab
		sha1_masterkey bb1bff78b80d6d4aeb9d78502bb32d77715ccc00

== LogonSession ==
authentication_id 709744 (ad470)
session_id 1
username mimi
domainname windows11
logon_server WINDOWS11
logon_time 2024-09-10T02:32:50.802254+00:00
sid S-1-5-21-940291183-874774319-2012240919-1002
luid 709744
	== MSV ==
		Username: mimi
		Domain: windows11
		LM: NA
		NT: 5e088b316cc30d7b2d0158cb4bd9497c
		SHA1: c1bd67cf651fdbcf27fd155f488721f52fff64fa
		DPAPI: c1bd67cf651fdbcf27fd155f488721f52fff64fa
	== WDIGEST [ad470]==
		username mimi
		domainname windows11
		password flag{7a565a86761a2b89524bf7bb0d19bcea}
		password (hex)66006c00610067007b00370061003500360035006100380036003700360031006100320062003800390035003200340062006600370062006200300064003100390062006300650061007d0000000000
	== Kerberos ==
		Username: mimi
		Domain: windows11
	== WDIGEST [ad470]==
		username mimi
		domainname windows11
		password flag{7a565a86761a2b89524bf7bb0d19bcea}
		password (hex)66006c00610067007b00370061003500360035006100380036003700360031006100320062003800390035003200340062006600370062006200300064003100390062006300650061007d0000000000

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server
logon_time 2024-09-10T02:29:01.864857+00:00
sid S-1-5-19
luid 997
	== Kerberos ==
		Username:
		Domain:

== LogonSession ==
authentication_id 81191 (13d27)
session_id 1
username DWM-1
domainname Window Manager
logon_server
logon_time 2024-09-10T02:29:01.380696+00:00
sid S-1-5-90-0-1
luid 81191
	== WDIGEST [13d27]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [13d27]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 81140 (13cf4)
session_id 1
username DWM-1
domainname Window Manager
logon_server
logon_time 2024-09-10T02:29:01.380696+00:00
sid S-1-5-90-0-1
luid 81140
	== WDIGEST [13cf4]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [13cf4]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username WINDOWS11$
domainname WORKGROUP
logon_server
logon_time 2024-09-10T02:29:01.082938+00:00
sid S-1-5-20
luid 996
	== WDIGEST [3e4]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== Kerberos ==
		Username: windows11$
		Domain: WORKGROUP
	== WDIGEST [3e4]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 56302 (dbee)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server
logon_time 2024-09-10T02:29:00.973424+00:00
sid S-1-5-96-0-1
luid 56302
	== WDIGEST [dbee]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [dbee]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 56305 (dbf1)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server
logon_time 2024-09-10T02:29:00.973424+00:00
sid S-1-5-96-0-0
luid 56305
	== WDIGEST [dbf1]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [dbf1]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 55160 (d778)
session_id 0
username
domainname
logon_server
logon_time 2024-09-10T02:29:00.816542+00:00
sid None
luid 55160

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username WINDOWS11$
domainname WORKGROUP
logon_server
logon_time 2024-09-10T02:29:00.769929+00:00
sid S-1-5-18
luid 999
	== WDIGEST [3e7]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== Kerberos ==
		Username: windows11$
		Domain: WORKGROUP
	== WDIGEST [3e7]==
		username WINDOWS11$
		domainname WORKGROUP
		password None
		password (hex)
	== DPAPI [3e7]==
		luid 999
		key_guid b997b457-2400-47b0-a0fb-1d451a36d41c
		masterkey f426e3509c32d2bc67c4742ea7e7b94fcac9aff468ee73d13996e92c4c8c9866de2a3458c62f78ad40b704f550aca0d8951f8f3fd6275b0a2439d2f3f4f1b21c
		sha1_masterkey 095d12d9240b78d33587753fe13946ab7135b27a
	== DPAPI [3e7]==
		luid 999
		key_guid 3340c37d-2b78-4bea-a57a-2fe5c333b4d2
		masterkey 18d685a1fdb8464ad953592b96f9e1b3e9dff42afe09c2fb52cc7bbfe8b7af9fb0bc992aacf69983554d33b042fd04799d2635bdd6afcab2c9a7eb2d811d5616
		sha1_masterkey 72180e8d5c6e458e31d5ea974f2da2d6508bf2d0

```

To get the flag, just pipe with `flag`

```bash
$ pypykatz lsa minidump mimi | grep flag
```

**Flag:** `flag{7a565a86761a2b89524bf7bb0d19bcea}`


