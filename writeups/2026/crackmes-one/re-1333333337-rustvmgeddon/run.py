#!/usr/bin/env python3
"""Run rustvmgeddon past its anti-debug gate, without patching it.

ptrace(PTRACE_TRACEME) succeeds, which sets the process's own TracerPid to
its *parent's* PID. The check then only requires that value to end in the
digit '0' -- so the binary blocks itself unless its parent's PID happens to
end in 0. Forking until we are such a parent is enough to get through.

    ./run.py ./rustvmgeddon deadbeef
"""
import os
import subprocess
import sys


def run(binary, data=b"\n"):
    r, w = os.pipe()
    while True:
        pid = os.fork()
        if pid == 0:
            if os.getpid() % 10 == 0:            # our PID ends in 0 -> good parent
                os.close(r)
                res = subprocess.run([binary], input=data, capture_output=True)
                os.write(w, res.stdout)
                os._exit(0)
            os._exit(1)
        if os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0:
            os.close(w)
            chunks = []
            while (c := os.read(r, 4096)):
                chunks.append(c)
            os.close(r)
            return b"".join(chunks).decode(errors="replace")


if __name__ == "__main__":
    binary = sys.argv[1]
    for arg in (sys.argv[2:] or [""]):
        print(f"{arg!r:20} -> {run(binary, arg.encode() + bytes([10])).strip()!r}")
