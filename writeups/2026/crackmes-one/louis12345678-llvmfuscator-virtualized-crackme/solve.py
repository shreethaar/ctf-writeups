"""Recover the accepted key without knowing it in advance.

The checker is branch-free, so no path/timing oracle leaks anything. What it
does do is build its verdict strings on the stack -- and the expected key is
assembled in the same stack window, immediately above them. So: run the binary
under the emulator with any dummy input, and at the moment it emits its verdict,
read the key straight out of stack memory.

Usage:  CRACKME=./crackme_windows.bin python3 solve.py
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peemu import Emu, STACK, STACK_SZ

DUMMY = 'A' * 32


def run(cmdline):
    return Emu(cmdline).run(timeout=120 * 1000000).decode(errors='replace').strip()


def recover():
    """Run with a dummy key; scrape the expected key out of the stack."""
    e = Emu('crackme.exe %s' % DUMMY)
    hit = {}
    orig = Emu.api_WriteFile

    def api_WriteFile(s, uc, a, st, R):
        if 'key' not in hit:
            d = bytes(uc.mem_read(STACK, STACK_SZ))
            v = d.find(b'valid key :)')          # success string
            if v >= 0:
                # layout: <expected key>\0 .. | "invalid key"\0 | "valid key :)"
                window = d[max(0, v - 0x60):v - 0x10]
                runs = re.findall(rb'[\x20-\x7e]{8,}', window)
                if runs:
                    hit['key'] = max(runs, key=len).decode()
                    hit['addr'] = STACK + v
        orig(s, uc, a, st, R)

    Emu.api_WriteFile = api_WriteFile
    try:
        out = e.run(timeout=120 * 1000000).decode(errors='replace').strip()
    finally:
        Emu.api_WriteFile = orig
    return hit, out


if __name__ == '__main__':
    hit, out = recover()
    print('dummy input %-12r -> %s' % (DUMMY, out))
    if 'key' not in hit:
        sys.exit('could not locate the verdict strings on the stack')
    key = hit['key']
    print('success string found at 0x%x' % hit['addr'])
    print('recovered key (%d chars): %r' % (len(key), key))

    # the key contains spaces, so it must be one quoted argv[1]
    print('verify                    -> %s' % run('crackme.exe "%s"' % key))
    print('truncated by one          -> %s' % run('crackme.exe "%s"' % key[:-1]))
