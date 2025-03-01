---
title: Fall of 2022
layout: default
---
# Fall of 2022

It was a peaceful time — schools were over, college admissions were delayed, and COVID was slowly on the decline. It seemed like the perfect time to relax and check my phone for her txts.

The funny thing is, I never got any. So I considered it just another gloomy year.

Anyways, here’s the domain for this CTF: [acectf.tech](https://acectf.tech)

What? You already knew this domain? Oh, I guess you’ll have no trouble finding the flag then.

Good Luck!

- Category: OSINT
- Challenge Link/Domain: [acectf.tech](https://acectf.tech)
### Solution:
##### 1. Acknowledge the hints from the challenge description
Based on the challenge description, it stores a flag at `txt` along with the given domain `acectf.tech`. A **TXT (Text) record lookup** is a **DNS query** used to retrieve **TXT records** associated with a domain. TXT records store arbitrary text-based data, often used for security, authentication, and verification purposes. 

##### 2. Use nslookup to query the domain
```bash
nslookup -q=txt acectf.tech
Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
acectf.tech	text = "v=spf1 include:_spf.mx.cloudflare.net ~all"
acectf.tech	text = "ACECTF{y0u_g07_7h3_73x7}"

Authoritative answers can be found from:
```

Here we found the flag.

**Flag:** `ACECTF{y0u_g07_7h3_73x7}`
