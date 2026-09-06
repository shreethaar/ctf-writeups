#!/usr/bin/env python3
# Wasting Time - SunCTF 2026 - PyArmor 9.2.6 unwrapper
#
# challenge.py is PyArmor-obfuscated. The blob header (PY000000 \x00\x03\x0b)
# says the code objects were built for CPython 3.11, so the module only imports
# under 3.11:  uv python install 3.11
#
# PyArmor 9 leaves real function objects in the module namespace and encrypts
# only co_code, decrypting it in place on frame entry and re-encrypting on exit
# (that is what the C_ENTER_CO_OBJECT_INDEX / C_LEAVE_CO_OBJECT_INDEX consts
# bracketing every function body are for). Reading f.__code__.co_code from
# outside therefore returns ciphertext -- but reading frame.f_code.co_code from
# *inside* a running frame returns the plaintext.
#
# The runtime does not block sys.settrace, so a trace function is enough: it
# runs inside each frame, snapshots the decrypted bytes, and co.replace() glues
# them back onto the otherwise-intact code object for dis.
#
#   python3.11 unarmor.py            # trace main() -- needs C source on stdin
#   python3.11 unarmor.py vm         # trace orbit_vm/rotate_left directly
import dis, io, sys

sys.path.insert(0, ".")            # next to challenge.py + pyarmor_runtime_000000/
import challenge as c

codes = {}


def tr(frame, event, arg):
    co = frame.f_code
    if "challenge" in co.co_filename:
        codes[(co.co_name, co.co_firstlineno)] = (co, co.co_code)
    return tr


sys.settrace(tr)
try:
    if len(sys.argv) > 1 and sys.argv[1] == "vm":
        # orbit_vm/rotate_left are only reached after a round verifies, so call
        # them straight rather than driving main() all the way there.
        src = b"int main(){return 0;}\n"
        c.orbit_vm(src, bytes(len(src)), 3, 5, 12345, c.make_program())
        c.rotate_left(0x123456789ABCDEF, 7)
    else:
        c.main()
except BaseException as e:
    print("[!] %s: %s" % (type(e).__name__, e), file=sys.stderr)
sys.settrace(None)

out = io.StringIO()
for key in sorted(codes, key=lambda k: k[1]):
    co, code = codes[key]
    print("=" * 70, file=out)
    print("### %s  line %d  args=%s" % (key[0], key[1], co.co_varnames[:co.co_argcount]), file=out)
    print("# names    =", co.co_names, file=out)
    print("# varnames =", co.co_varnames, file=out)
    print("# consts   =", co.co_consts, file=out)
    dis.dis(co.replace(co_code=code), file=out, depth=0)
print(out.getvalue())
