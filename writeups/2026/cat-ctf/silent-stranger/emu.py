"""Unicorn harness for silent-stranger.

Two shapes are needed:

  * levels 1 and 2 are position-independent blobs copied into a VirtualAlloc'd
    page, so they can be mapped anywhere;
  * level 3 is decrypted straight into the .lvl3 section VA and references
    absolute addresses, so it needs the real image layout at 0x400000.

`build()` covers both: it maps launcher.exe's sections and, for the PIC blobs,
also maps a scratch CODE page.  fs: is served by a real GDT entry rather than
by patching the binary, so the anti-debug reads (PEB->BeingDebugged,
ProcessHeap Flags/ForceFlags, NtGlobalFlag) see exactly what they would in a
clean process.
"""
import struct
from unicorn import *
from unicorn.x86_const import *

IMAGE = 0x00400000
SECS = [('.text',    0x401000, 0x00400, 0x19600, 0x1a000),
        ('.rdata',   0x41b000, 0x19a00, 0x0e400, 0x0f000),
        ('.data',    0x42a000, 0x27e00, 0x00a00, 0x02000),
        ('.lvl3',    0x42c000, 0x28800, 0x01c00, 0x02000),
        ('.fptable', 0x42e000, 0x2a400, 0x00200, 0x01000)]

CODE = 0x00200000          # scratch page for the PIC blobs (levels 1 and 2)
STACK, STACK_SZ = 0x00300000, 0x40000
INPUT = 0x00500000
TEB, PEB, HEAP, GDT = 0x00600000, 0x00610000, 0x00800000, 0x00700000
RET_MAGIC = 0x00900000
SCRATCH = 0x00b00000       # CONTEXT / EXCEPTION_RECORD for the SEH dispatcher
CB = 0x00a00000            # level 2's host callback


def _gdt_entry(base, limit, access, flags):
    e = limit & 0xffff
    e |= (base & 0xffffff) << 16
    e |= (access & 0xff) << 40
    e |= ((limit >> 16) & 0xf) << 48
    e |= (flags & 0xff) << 52
    e |= ((base >> 24) & 0xff) << 56
    return struct.pack('<Q', e)


def build(exe='launcher.exe', blob=None, lvl3=None, being_debugged=0):
    d = open(exe, 'rb').read()
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(IMAGE, 0x1000)
    uc.mem_write(IMAGE, d[:0x1000])
    for _name, va, off, raw, virt in SECS:
        uc.mem_map(va, (virt + 0xfff) & ~0xfff)
        uc.mem_write(va, d[off:off + raw])
    if lvl3:
        uc.mem_write(0x42c000, lvl3)
    for a, sz in ((STACK, STACK_SZ), (INPUT, 0x1000), (TEB, 0x1000),
                  (PEB, 0x1000), (HEAP, 0x10000), (RET_MAGIC, 0x1000),
                  (SCRATCH, 0x10000), (CB, 0x1000)):
        uc.mem_map(a, sz)
    if blob:
        uc.mem_map(CODE, (len(blob) + 0x1fff) & ~0xfff)
        uc.mem_write(CODE, blob)
    uc.mem_write(RET_MAGIC, b'\xf4' * 16)

    uc.mem_write(TEB, struct.pack('<I', 0xffffffff))     # end of the SEH chain
    uc.mem_write(TEB + 0x30, struct.pack('<I', PEB))
    uc.mem_write(PEB + 2, bytes([being_debugged]))
    uc.mem_write(PEB + 8, struct.pack('<I', IMAGE))      # ImageBaseAddress
    uc.mem_write(PEB + 0x18, struct.pack('<I', HEAP))    # ProcessHeap

    uc.mem_map(GDT, 0x1000)
    uc.mem_write(GDT + 8, _gdt_entry(0, 0xfffff, 0x92, 0xc))
    uc.mem_write(GDT + 16, _gdt_entry(TEB, 0xfff, 0x92, 0x4))
    uc.mem_write(GDT + 24, _gdt_entry(0, 0xfffff, 0x9a, 0xc))
    uc.reg_write(UC_X86_REG_GDTR, (0, GDT, 0x1000, 0))
    for r in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(r, 8)
    uc.reg_write(UC_X86_REG_FS, 16)
    uc.reg_write(UC_X86_REG_CS, 24)
    return uc


def push_args(uc, args):
    """cdecl frame: args, then RET_MAGIC as the return address."""
    sp = STACK + STACK_SZ - 0x2000 - 4 * len(args)
    uc.mem_write(sp, b''.join(struct.pack('<I', a) for a in args))
    sp -= 4
    uc.mem_write(sp, struct.pack('<I', RET_MAGIC))
    uc.reg_write(UC_X86_REG_ESP, sp)


def call(uc, entry, args, hook=None):
    push_args(uc, args)
    if hook:
        uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(entry, RET_MAGIC)
    except UcError:
        if uc.reg_read(UC_X86_REG_EIP) != RET_MAGIC:
            raise
    return uc.reg_read(UC_X86_REG_EAX)
