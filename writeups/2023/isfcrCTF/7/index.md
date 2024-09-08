---
title: challenge007
layout: default
---

# challenge007

Description:

We found the network capture of a possible honeypot attack. Can you help us find out some more information about it?

What is the victim's IP address?

- Category: forensic
- Challenge file: attack.pcap

### Solution:

1. Open the pcap file.
2. Open statistics and go to endpoints
3. See which type of endpoint has the most ip address has most data conversations
4. Under TCP, there are only two ip address, but is uneven.
5. Apply filter on the that is less
6. Use TCP stream, and there found the honeypot handshake conversation

References:[https://digitalitskills.com/cyberdefenders-honeypot-wireshark-pcap-analysis/](https://digitalitskills.com/cyberdefenders-honeypot-wireshark-pcap-analysis/)

**Flag:** `isfcr{192.150.11.111}`


