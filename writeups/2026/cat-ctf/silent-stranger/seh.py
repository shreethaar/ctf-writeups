"""Minimal Win32 x86 SEH dispatch on top of Unicorn.

Level 3 of silent-stranger uses deliberate access violations as its control
flow: it installs a chain of fs:[0] handlers, faults, and the handler rewrites
CONTEXT.Eip and returns ExceptionContinueExecution.  Emulating it therefore
needs the dispatcher, not just the CPU.
"""
import struct
from unicorn import *
from unicorn.x86_const import *

CTX_OFF = {'SegGs': 0x8c, 'SegFs': 0x90, 'SegEs': 0x94, 'SegDs': 0x98,
           'Edi': 0x9c, 'Esi': 0xa0, 'Ebx': 0xa4, 'Edx': 0xa8, 'Ecx': 0xac,
           'Eax': 0xb0, 'Ebp': 0xb4, 'Eip': 0xb8, 'SegCs': 0xbc,
           'EFlags': 0xc0, 'Esp': 0xc4, 'SegSs': 0xc8}
CTX_SIZE = 0x2cc
REC_SIZE = 0x50

R = {'Edi': UC_X86_REG_EDI, 'Esi': UC_X86_REG_ESI, 'Ebx': UC_X86_REG_EBX,
     'Edx': UC_X86_REG_EDX, 'Ecx': UC_X86_REG_ECX, 'Eax': UC_X86_REG_EAX,
     'Ebp': UC_X86_REG_EBP, 'Eip': UC_X86_REG_EIP, 'Esp': UC_X86_REG_ESP,
     'EFlags': UC_X86_REG_EFLAGS}

STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_BREAKPOINT = 0x80000003
STATUS_PRIV_INSTRUCTION = 0xC0000096


class SehRunner:
    def __init__(self, uc, magic_ret, scratch, teb, max_exc=4000):
        self.uc = uc
        self.teb = teb
        self.magic = magic_ret
        self.scratch = scratch          # mapped page for CONTEXT/RECORD
        self.pending = None
        self.max_exc = max_exc
        self.exc_count = 0
        uc.hook_add(UC_HOOK_MEM_INVALID, self._mem)
        uc.hook_add(UC_HOOK_INSN_INVALID, self._insn)
        uc.hook_add(UC_HOOK_INTR, self._intr)

    def _mem(self, uc, typ, addr, size, val, user):
        self.pending = (STATUS_ACCESS_VIOLATION, addr,
                        0 if typ in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT) else 1)
        return False                      # stop emulation

    def _insn(self, uc, user):
        self.pending = (STATUS_ILLEGAL_INSTRUCTION, 0, 0)
        return False

    INTR_STATUS = {0: 0xC0000094,      # integer divide by zero
                   1: 0x80000004,      # single step
                   3: STATUS_BREAKPOINT,
                   4: 0xC0000095,      # integer overflow (into)
                   6: STATUS_ILLEGAL_INSTRUCTION,
                   13: STATUS_PRIV_INSTRUCTION}

    def _classify(self, eip, intno=None):
        uc = self.uc
        try:
            op = bytes(uc.mem_read(eip, 3))
        except UcError:
            op = b''
        if op[:1] in (b'\xf6', b'\xf7') and len(op) > 1 and (op[1] >> 3) & 7 in (6, 7):
            status = 0xC0000094                      # div / idiv by zero
        elif op[:2] == b'\x0f\x0b':
            status = STATUS_ILLEGAL_INSTRUCTION      # ud2
        elif op[:1] == b'\xcc' or op[:2] == b'\xcd\x03':
            status = STATUS_BREAKPOINT
        elif op[:1] == b'\xf1':
            status = 0x80000004                      # int1 -> single step
        elif op[:1] == b'\xf4':
            status = STATUS_PRIV_INSTRUCTION         # hlt in user mode
        else:
            status = self.INTR_STATUS.get(intno, STATUS_PRIV_INSTRUCTION)
        self.pending = (status, 0, 0)
        return status

    def _intr(self, uc, intno, user):
        # Unicorn's intno for a fault is not always the architectural vector
        # (a div-by-zero can surface as 0 or as 8), so classify from the
        # faulting opcode instead, and fall back to the vector map.
        self._classify(uc.reg_read(UC_X86_REG_EIP), intno)
        uc.emu_stop()

    # ---------------------------------------------------------------- context
    def _save_ctx(self, at, eip):
        uc = self.uc
        buf = bytearray(CTX_SIZE)
        struct.pack_into('<I', buf, 0, 0x10007)          # CONTEXT_FULL
        for name, off in CTX_OFF.items():
            if name in R:
                v = eip if name == 'Eip' else uc.reg_read(R[name])
                struct.pack_into('<I', buf, off, v & 0xffffffff)
        struct.pack_into('<I', buf, CTX_OFF['SegCs'], 0x1b)
        struct.pack_into('<I', buf, CTX_OFF['SegSs'], 0x23)
        struct.pack_into('<I', buf, CTX_OFF['SegDs'], 0x23)
        struct.pack_into('<I', buf, CTX_OFF['SegEs'], 0x23)
        struct.pack_into('<I', buf, CTX_OFF['SegFs'], 0x3b)
        uc.mem_write(at, bytes(buf))

    def _load_ctx(self, at):
        uc = self.uc
        buf = bytes(uc.mem_read(at, CTX_SIZE))
        for name, reg in R.items():
            uc.reg_write(reg, struct.unpack_from('<I', buf, CTX_OFF[name])[0])
        return struct.unpack_from('<I', buf, CTX_OFF['Eip'])[0]

    # ------------------------------------------------------------------- run
    def run(self, eip):
        uc = self.uc
        while True:
            self.pending = None
            try:
                uc.emu_start(eip, self.magic)
            except UcError:
                pass
            if self.pending is None:
                if uc.reg_read(UC_X86_REG_EIP) == self.magic:
                    return uc.reg_read(UC_X86_REG_EAX)  # returned to magic
                # Unicorn sometimes halts on a faulting instruction without
                # firing a hook; classify it from the opcode and go on.
                self._classify(uc.reg_read(UC_X86_REG_EIP))
            self.exc_count += 1
            if self.exc_count > self.max_exc:
                raise RuntimeError('exception storm')
            code, addr, _ = self.pending
            fault_eip = uc.reg_read(UC_X86_REG_EIP)
            eip = self._dispatch(code, addr, fault_eip)

    def _dispatch(self, code, addr, fault_eip):
        uc = self.uc
        ctx = self.scratch
        rec = self.scratch + CTX_SIZE
        self._save_ctx(ctx, fault_eip)
        r = bytearray(REC_SIZE)
        struct.pack_into('<IIIII', r, 0, code, 0, 0, fault_eip, 2)
        struct.pack_into('<II', r, 0x14, 0, addr)
        uc.mem_write(rec, bytes(r))

        node = struct.unpack('<I', uc.mem_read(self._fs_base(), 4))[0]
        while node not in (0xffffffff, 0):
            nxt, handler = struct.unpack('<II', uc.mem_read(node, 8))
            sp = (uc.reg_read(UC_X86_REG_ESP) - 0x400) & ~0xf
            sp -= 20
            uc.mem_write(sp, struct.pack('<IIIII', self.magic, rec, node, ctx, 0))
            uc.reg_write(UC_X86_REG_ESP, sp)
            try:
                uc.emu_start(handler, self.magic)
            except UcError:
                raise RuntimeError(f'fault inside SEH handler {handler:#x}')
            disp = uc.reg_read(UC_X86_REG_EAX)
            if disp == 0:                                  # ContinueExecution
                return self._load_ctx(ctx)
            node = nxt
        raise RuntimeError(f'unhandled exception {code:#x} at {fault_eip:#x}')

    def _fs_base(self):
        return self.teb
