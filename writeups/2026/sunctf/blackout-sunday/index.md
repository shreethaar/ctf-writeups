# Blackout Sunday

- Category: forensic

"Northstar Dynamics experienced a network blackout on 17 May 2026. A confidential archive disappeared during the incident, and several employee identities appear throughout the evidence."

Thirteen artifacts and not a single hidden byte among them — no steganography, no carving, no crypto. The whole challenge is a decoy structure: the attribution investigation the evidence invites you to run is unresolvable *by construction*, and the flag is a plaintext keyword sitting in one of 159 emails. The work is recognising which question the challenge is actually asking.

### Solution:

##### 1. Merge everything into one UTC timeline

The set is six logs, a mailbox, a chat export, two PDFs and a photo:

```
01_photo.jpg (actually AVIF)  05_authentication.log   09_lab_terminal.log      13_case_recovery.log
02_resume.pdf                 06_network_dhcp.log     10_usb_inventory.txt
03_invoice.pdf                07_chat_export.json     11_vpn_sessions.log
04_mailbox.mbox               08_lab_access.log       12_endpoint_history.log
```

Six of them carry timestamps in the incident window, in five different formats. Nothing is legible until they are one sorted stream:

```python
ev = []
for f, pat in [('05_authentication.log', r'(\S+Z) \| (.*)'),
               ('06_network_dhcp.log',   r'(\S+Z) \| (.*)'),
               ('08_lab_access.log',     r'(\S+Z) \| (.*)'),
               ('09_lab_terminal.log',   r'(\S+Z) \| (.*)'),
               ('11_vpn_sessions.log',   r'(\S+Z) \| (.*)'),
               ('12_endpoint_history.log', r'(\S+Z) \| .*COMMAND=(.*)')]:
    for line in open(f):
        m = re.match(pat, line.strip())
        if m: ev.append((m.group(1), f[3:-4], m.group(2)))

for m in json.load(open('07_chat_export.json')):          # mixed offsets - normalise
    t = datetime.datetime.fromisoformat(m['timestamp']).astimezone(datetime.timezone.utc)
    ev.append((t.strftime('%Y-%m-%dT%H:%M:%SZ'), 'chat', m['user'] + ': ' + m['message']))

ev.sort()
```

The core of the window:

```
23:09:18  lab_terminal  USB_INSERT | DEVICE=USB-7F31
23:10:02  lab_terminal  FILE_OPEN | PATH=\\WS-DWONG-17\Restricted\incident-27
23:11:16  lab_terminal  NETWORK_CONNECT | DESTINATION=10.24.8.17 | PORT=445
23:11:54  badge         BADGE=NL-4421 | USER=maya.l | DOOR=LAB-A | RESULT=GRANTED
23:12:48  dhcp          IP=10.24.8.91 | MAC=02:4C:4F:43:41:4C:91 | HOST=TEMP-LAB-01
23:16:37  cmdhist       net use \\WS-DWONG-17\Restricted
23:17:09  auth          EVENT=4624 | USER=dwong | SOURCE=10.24.8.91 | LOGON_TYPE=3
23:18:04  auth          EVENT=4663 | USER=dwong | OBJECT=incident-27
23:19:02  cmdhist       copy \\WS-DWONG-17\Restricted\incident-27.tar C:\Temp\
23:21:14  lab_terminal  FILE_CREATE | PATH=C:\Temp\incident-27.tar
23:22:06  cmdhist       copy C:\Temp\incident-27.tar E:\incident-27.tar
23:23:21  cmdhist       Remove-Item C:\Temp\incident-27.tar
23:23:37  auth          EVENT=5156 | USER=dwong | DESTINATION=185.91.44.17 | PORT=443
23:24:01  auth          EVENT=4634 | USER=dwong | SOURCE=10.24.8.91 | LOGOFF
23:24:18  lab_terminal  USB_REMOVE | DEVICE=USB-7F31
23:28:42  badge         BADGE=NL-4421 | USER=maya.l | DOOR=LAB-A | RESULT=GRANTED
```

The *mechanism* is unambiguous, and the three logs agree event-for-event: USB in, SMB share mounted from TEMP-LAB-01 (`10.24.8.91`) to WS-DWONG-17 (`10.24.8.17`), `incident-27.tar` copied share → `C:\Temp` → `E:\`, staging copy deleted, upload to `185.91.44.17`, USB out. The archive left twice — once on removable media and once over the wire. That much is settled in five minutes, which is the trap: the mechanism is free and the *identity* is the entire challenge.

##### 2. Two time-based traps, both of which are no-ops

Two artifacts wave a clock-skew flag, and neither one changes a timestamp.

The auth log's footer says `WS-DWONG-17 was configured with a local clock offset of +08:00`, and Daniel's 21:07 email repeats it — "the clock is still showing the wrong time, so keep that in mind when comparing local logs with the forwarded security events". The next line of the log defuses it: `Authentication forwarding timestamps are normalized to UTC`. The correction has already been applied; applying it again shifts a correct log eight hours off and destroys the correlation.

The chat export is the live one. Its timestamps carry *mixed* offsets, and only the messages from the night of the 17th are `+10:00`:

| as written | true UTC | who | message |
|---|---|---|---|
| `2026-05-17T23:02:41+10:00` | 13:02:41 | sng | Why is the archive showing Daniel's account? |
| `2026-05-17T23:04:17+10:00` | 13:04:17 | mayal | Daniel isn't supposed to be accessing it. |
| `2026-05-17T23:06:55+10:00` | 13:06:55 | dwong | I'm not accessing anything right now. |
| `2026-05-17T23:22:11+10:00` | 13:22:11 | mayal | I know where the report is. |

Read on the wall clock, that last line lands 2 minutes before `copy C:\Temp\incident-27.tar E:\incident-27.tar` at 23:22:06 and reads as a confession in progress. Normalised, it is ten hours earlier — mid-afternoon, before the USB was even checked out at 21:32:44Z. Every human chat message sits *outside* the window; the only accounts posting inside it are the `security` and `it` bots, whose messages are just the auth log restated.

##### 3. Every trail is signed `dwong` — and every log disclaims itself

The account attribution is total and consistent. So is the footnote under it:

| Artifact | Points at | Its own closing note |
|---|---|---|
| `05_authentication.log` — 4624 / 4672 / 4663 / 5145 / 5156 | dwong | clock offset, "normalized to UTC" |
| `11_vpn_sessions.log` — session V-88421 | dwong | "does not independently establish the physical identity of the operator" |
| `12_endpoint_history.log` — the full exfil sequence | dwong | "identifies the authenticated account... not the physical operator" |
| `09_lab_terminal.log` — console session, USB, file ops | LOCAL-LAB | "badge events... do not identify the person operating the workstation" |
| `08_lab_access.log` — badge NL-4421 on LAB-A all night | maya.l | "badge access does not establish workstation usage" |
| `06_network_dhcp.log` — lease for 10.24.8.91 | nobody | "device owner field was not populated" |
| `10_usb_inventory.txt` — USB-7F31, checkout TX-8841 | nobody | "does not include the associated employee record" |

Seven artifacts, seven different ways of saying *this is not proof of a person*. A single such disclaimer is realistic log hygiene. Seven is the author telling you the answer is not down this path.

##### 4. The operator is unidentifiable by construction

Following it anyway confirms that. The workstation is `TEMP-LAB-01`, which never had an owner to begin with, and its DHCP lease says so twice over:

```python
>>> bytes(int(x, 16) for x in '02:4C:4F:43:41:4C:91'.split(':'))
b'\x02LOCAL\x91'
```

Seven bytes where a MAC has six — locally-administered bit, the ASCII string `LOCAL`, and the host's own last IP octet. It is not a hardware address at all; there is no device to trace. The other four leases are ordinary six-byte MACs whose last octet mirrors the IP.

The rest of the path closes the same way. `USB-7F31` is checked out on record `TX-8841` — the one system that would name a person — and the export "does not include the associated employee record". Maya's badge is the only one on LAB-A, but LAB-A is a room, and the terminal ran as the shared `LOCAL-LAB` console account. The two PDFs cross-contaminate the remaining identities: Maya's `Employee Security Profile` carries `Author: Daniel Wong`, and the expense report for Maya's `NS-20491` is approved by Daniel. Everyone denies it in writing — Maya at 23:42 ("I did not access Daniel's workstation"), Daniel at 00:06 ("my credentials may have been used by someone else"), and Sarah pre-emptively at 22:03, an hour *before* the incident, flagging that the account "doesn't necessarily mean Daniel was the person using it".

Four suspects, no discriminating evidence, and every log volunteering that it can't discriminate. There is no name to be had.

##### 5. The case log is not asking for a name

`13_case_recovery.log` is the terminal artifact, and it states the actual objective:

```
2026-05-17T23:31:06Z | CASE_SESSION=C-2317 | OPERATOR=atan

Attribution has been established for CASE_SESSION C-2317.
The stolen archive was recovered from removable media.

To close the case, submit the recovery keyword associated
with CASE_SESSION C-2317.

The recovery keyword is not stored in this system.
Check the incident correspondence associated with this
case reference to recover the keyword.
```

Attribution *has been* established — past tense, by someone else, and it is never asked for. `OPERATOR=atan` is the incident responder who opened the case at 23:31, seven minutes after the exfil ended, not a fifth suspect. The deliverable is a keyword, and the log names its own location: correspondence, keyed on `C-2317`.

`C-2317` appears in exactly one of the 159 messages in the mailbox:

```bash
$ grep -n "C-2317" 04_mailbox.mbox
1778:Subject: Case C-2317 - Recovery Procedure
1786:Case reference: C-2317
1795:Use this keyword to close CASE_SESSION C-2317.
```

```
From: incident-response@northstar.local
To: security@northstar.local
Subject: Case C-2317 - Recovery Procedure
Date: Mon, 18 May 2026 00:36:12 +0000

Case reference: C-2317
Incident: 27

RECOVERY KEYWORD: NIGHTFALL

Use this keyword to close CASE_SESSION C-2317.

No other value in this message is required for case closure.
```

That last line cuts off the `NS-20491` and incident-27 side trails. `NIGHTFALL` is also the only 6+ character all-caps token in the entire mailbox other than `RECOVERY`, `KEYWORD`, `BLACKOUT` and the 159 `MAILER-DAEMON` separators — a useful one-line confirmation that there is no second candidate hiding in the other 158 messages:

```bash
$ grep -ao "\b[A-Z]\{6,\}\b" 04_mailbox.mbox | sort | uniq -c | sort -rn
    159 MAILER
    159 DAEMON
      1 RECOVERY
      1 NIGHTFALL
      1 KEYWORD
      1 BLACKOUT
```

##### 6. Confirming there is no second layer

Worth stating as a negative result, since "forensics + a photo + two PDFs" reads as a stego challenge and the temptation is to spend the whole event there. All four binary-ish artifacts are exactly what they claim:

- `01_photo.jpg` is an AVIF, not a JPEG. Its `mdat` box starts at 3432 and runs 51798 bytes; 3432 + 51798 = 55230 = the file size, so there is no appended data. The only `binwalk` hit is the sRGB profile's HP copyright string, and the image itself is a watermarked stock portrait.
- Both PDFs decompress to four streams each — a font, a content stream, an ICC profile, a font descriptor. Every text run is `TJ` under `0 Tr` (fill), so nothing is drawn in invisible render mode, and the decompressed content matches `pdftotext` exactly. The only payload is the metadata cross-contamination from step 4.
- No message in the mbox has a `Content-Disposition`, an `X-` header, or a base64 part.
- None of the ten text artifacts contains a single non-ASCII byte, which rules out zero-width encoding across the whole set.

**Flag:** `sunctf26{NIGHTFALL}`

### Takeaways

- A log footer that explains why the log cannot prove what it appears to prove is authored content, not boilerplate. One is realism; seven pointing the same way is the challenge telling you the attribution branch is a dead end. Count them before committing hours to the branch.
- Read the terminal artifact for what it *asks*, not what it *describes*. `13_case_recovery.log` says "attribution has been established" and then requests a keyword — the whole suspect drama is scenery around a lookup. Establishing the mechanism was five minutes of work and produced nothing that closes the challenge.
- Normalise every timestamp to UTC before reading a single one, and check the offsets *per record* rather than per file. The chat export mixes `+00:00` and `+10:00` inside one JSON array specifically so that a wall-clock read puts a confession two minutes before the copy-to-USB.
- A stated clock skew that the log also says has already been corrected is a no-op. Applying a correction twice is the intended failure, and it silently breaks correlation against every other source.
- Decode identifiers that look structural. `02:4C:4F:43:41:4C:91` is seven bytes where a MAC has six, and it spells `LOCAL` — the "unowned workstation" is unowned all the way down to its hardware address. Field-length and ASCII checks on IDs cost seconds and often carry the author's intent.
- In a multi-artifact forensics set, cheap negative results are worth writing down. Confirming the AVIF's `mdat` ends exactly at EOF and that no file holds a non-ASCII byte took one command each and permanently closed the stego branch.
