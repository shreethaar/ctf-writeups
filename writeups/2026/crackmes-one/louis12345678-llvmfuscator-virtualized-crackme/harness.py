import os, sys, struct, time
sys.path.insert(0,'.')
from peemu import *
from unicorn import *
from unicorn.x86_const import *

MAIN = 0x140034440
REGS = [UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
        UC_X86_REG_RBP,UC_X86_REG_RSP,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,
        UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_RIP,UC_X86_REG_EFLAGS]

class Harness:
    def __init__(s, keylen, trace_blocks=True):
        s.keylen = keylen
        s.e = Emu('crackme.exe ' + 'A'*keylen)
        s.uc = s.e.uc
        sp = STACK+STACK_SZ-0x2000
        s.uc.reg_write(UC_X86_REG_RSP, sp)
        RET = HOOK+HOOK_SZ-16
        s.uc.mem_write(RET, b'\xC3'); s.uc.mem_write(sp, struct.pack('<Q',RET))
        s.e.stubs[RET]="__done__"
        s.uc.emu_start(s.e.pe.entry, MAIN, timeout=120*1000000)   # run CRT init, stop at main
        assert s.uc.reg_read(UC_X86_REG_RIP) == MAIN, hex(s.uc.reg_read(UC_X86_REG_RIP))
        rsp = s.uc.reg_read(UC_X86_REG_RSP)
        s.ret = struct.unpack('<Q', s.uc.mem_read(rsp,8))[0]      # main's return address
        argv = s.uc.reg_read(UC_X86_REG_RDX)
        s.p1  = struct.unpack('<Q', s.uc.mem_read(argv+8,8))[0]
        s.regs = [s.uc.reg_read(r) for r in REGS]
        # snapshot memory regions we might dirty
        s.snap = []
        for a,n in ((s.e.pe.base, (s.e.pe.imgsz+0xFFF)&~0xFFF),
                    (HEAP, 0x800000), (STACK, STACK_SZ), (TEB, TEB_SZ), (SCR, SCR_SZ)):
            s.snap.append((a, bytes(s.uc.mem_read(a,n))))
        s.brk0 = s.e.brk; s.scr0 = s.e.scr; s.qpc0 = s.e.qpc; s.tls0 = dict(s.e.tls)
        s.blocks = []
        s.tb = trace_blocks
        if trace_blocks:
            s.uc.hook_add(UC_HOOK_BLOCK, s._blk, begin=s.e.pe.base, end=s.e.pe.base+s.e.pe.imgsz)
        print("harness ready: keylen=%d argv1=0x%x ret=0x%x" % (keylen, s.p1, s.ret))

    def _blk(s, uc, addr, size, ud):
        s.blocks.append(addr)

    def trial(s, key, collect=True):
        assert len(key)==s.keylen, (len(key), s.keylen)
        uc = s.uc
        for a,d in s.snap: uc.mem_write(a,d)
        for r,v in zip(REGS, s.regs): uc.reg_write(r,v)
        s.e.brk=s.brk0; s.e.scr=s.scr0; s.e.qpc=s.qpc0; s.e.tls=dict(s.tls0)
        s.e.out=b''; s.e.stopped=False
        uc.mem_write(s.p1, key.encode()+b'\0')
        s.blocks = []
        s.tb_on = collect
        try:
            uc.emu_start(MAIN, s.ret, timeout=120*1000000)
        except UcError as ex:
            return s.e.out, s.blocks, ('ERR:%s@0x%x'%(ex, uc.reg_read(UC_X86_REG_RIP)))
        return s.e.out, s.blocks, None

if __name__=="__main__":
    t=time.time(); h=Harness(19); print("setup %.1fs"%(time.time()-t))
    for k in ["AAAA-BBBB-CCCC-DDDD","AAAA-BBBB-CCCC-DDDE","ZZZZ-ZZZZ-ZZZZ-ZZZZ","1234-5678-9012-3456"]:
        t=time.time(); out,blk,err=h.trial(k)
        print("%-22s out=%-14r blocks=%7d err=%s  (%.2fs)" % (k, out.decode(errors='replace').strip(), len(blk), err, time.time()-t))
