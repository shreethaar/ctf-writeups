#!/usr/bin/env python3
# Threat Invaders (Flare-On 13) -- decrypt the tag4 telemetry exfil from the pcap.
#
# The malicious apphost rewrites the JITted managed TelemetryReporter.EncodeFeedbackBuffer
# so outgoing "feedback" carries encrypted exfil, framed as feedback_length = (tag << 12) | len.
# The exfil cipher (native sub_1400c65e0) is a truncated-LCG keystream XOR, seeded from the
# 16-byte HKLM MachineGuid (the managed "_machineId" field the decoy stores but never reads).
#
#   seed = fmix( boost::hash_combine(key[0:8], key[8:16]) )        # murmur3 mults, shifts 33/29/32
#   state = seed ; keystream_byte = (state = state*MULT + INC) >> 56 ; buf[i] ^= ks[i]
#
# The LCG state is seeded ONCE and never reset, so every cipher call in the session shares one
# continuous keystream. In the pcap the order is:
#   BANANA comment(18) | tag4 dir-exfil(530) | BENIGN comment(28) | tag4 flag(46)
# -> the two flag-bearing tag4 payloads sit at keystream offsets 18 and 576.

import re, sys, json, base64
import dpkt

M     = (1 << 64) - 1
GOLD  = 0x9e3779b97f4a7c15
MULT  = 0x5851f42d4c957f2d      # Knuth/PCG MMIX LCG multiplier
INC   = 0x14057b7ef767814f

# HKLM MachineGuid 78584d61-6348-496e-8045-4964586c756c, in Windows GUID struct byte order.
KEY = bytes.fromhex('614d587848636e4980454964586c756c')

def seed_from_key(k):
    a = int.from_bytes(k[0:8], 'little')
    b = int.from_bytes(k[8:16], 'little')
    x = (((a >> 2) + GOLD + (a << 6) + b) ^ a) & M          # boost::hash_combine(a, b)
    t = ((x ^ (x >> 33)) * 0xff51afd7ed558ccd) & M
    t = ((t ^ (t >> 29)) * 0xc4ceb9fe1a85ec53) & M
    return (t ^ (t >> 32)) & M

def keystream(seed, n):
    st, out = seed, bytearray()
    for _ in range(n):
        st = (st * MULT + INC) & M
        out.append((st >> 56) & 0xff)
    return bytes(out)

def reassemble_c2s(path):
    segs = {}
    for _, buf in dpkt.pcapng.Reader(open(path, 'rb')):
        ip = dpkt.ethernet.Ethernet(buf).data
        if not isinstance(ip, dpkt.ip.IP):
            continue
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data or tcp.dport != 80:
            continue
        segs.setdefault(tcp.seq, bytes(tcp.data))
    data = bytearray()
    for seq, b in sorted(segs.items()):
        off = seq - min(segs)
        if off < len(data):
            b = b[len(data) - off:]
        data += b
    return bytes(data)

def telemetry_blobs(c2s):
    out = []
    for p in re.split(rb'(?=POST /api/v1/telemetry )', c2s):
        if not p.startswith(b'POST'):
            continue
        head, _, body = p.partition(b'\r\n\r\n')
        m = re.search(rb'Content-Length: (\d+)', head)
        j = json.loads(body[:int(m.group(1))])
        raw = base64.b64decode(j['feedback_b64'].encode().decode('unicode_escape'))
        out.append(raw.rstrip(b'\x00'))          # 4096-byte buffer, zero-padded
    return out

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else 'challenge.pcapng'
    seed = seed_from_key(KEY)
    ks   = keystream(seed, 8192)
    xor  = lambda ct, off: bytes(c ^ k for c, k in zip(ct, ks[off:off + len(ct)]))

    blobs = telemetry_blobs(reassemble_c2s(pcap))
    b4, b5 = blobs[3], blobs[4]                   # the two tag4 payloads (530 B, 46 B)

    print(f'seed = {seed:#018x}\n')
    print('tag4 #1 (530 B @ ks offset 18) -- exfiltrated `dir` of the build directory:')
    print(xor(b4, 18).decode('latin1'))
    flag = xor(b5, 576).decode('latin1')          # tag4 #2 (46 B) = flag.txt
    print(f'Flag: {flag}')

if __name__ == '__main__':
    main()
