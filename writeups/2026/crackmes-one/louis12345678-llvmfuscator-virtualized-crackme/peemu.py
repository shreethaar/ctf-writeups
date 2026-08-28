"""Minimal Unicorn-based loader/emulator for a static-CRT x86-64 Windows PE.

Maps the image at its ImageBase, points every IAT slot at a one-byte RET stub
that a code hook implements by name, fakes a TEB via the GS base, and starts at
the PE entry point so the statically linked MSVC CRT initialises itself.
GetCommandLineA/W return a command line of our choosing, so the CRT builds argv.

Usage:  CRACKME=./crackme_windows.bin python3 peemu.py '"the key"'
"""
import os, struct, sys
from unicorn import *
from unicorn.x86_const import *

IMG = os.environ.get("CRACKME", "crackme_windows.bin")
STACK, STACK_SZ = 0x300000000, 0x400000
HEAP,  HEAP_SZ  = 0x400000000, 0x8000000
TEB,   TEB_SZ   = 0x500000000, 0x10000
HOOK,  HOOK_SZ  = 0x600000000, 0x10000
SCR,   SCR_SZ   = 0x700000000, 0x100000   # scratch for API-returned data

def rd(b,o,n): return int.from_bytes(b[o:o+n],'little')

class PE:
    def __init__(s, path):
        s.d = open(path,'rb').read()
        e = rd(s.d,0x3c,4)
        assert s.d[e:e+4]==b'PE\0\0'
        s.machine = rd(s.d,e+4,2)
        nsec = rd(s.d,e+6,2); optsz = rd(s.d,e+20,2)
        opt = e+24
        s.base = rd(s.d,opt+24,8)
        s.entry = s.base + rd(s.d,opt+16,4)
        s.imgsz = rd(s.d,opt+56,4)
        s.dd = opt+112
        s.impdir = rd(s.d,s.dd+8,4)
        s.secs=[]
        so = opt+optsz
        for i in range(nsec):
            o = so+i*40
            nm = s.d[o:o+8].rstrip(b'\0').decode(errors='replace')
            s.secs.append((nm, rd(s.d,o+12,4), rd(s.d,o+8,4), rd(s.d,o+16,4), rd(s.d,o+20,4)))

class Emu:
    def __init__(s, cmdline, trace=False):
        s.pe = PE(IMG); s.out=b''; s.trace=trace; s.stopped=False
        s.uc = uc = Uc(UC_ARCH_X86, UC_MODE_64)
        base, sz = s.pe.base, (s.pe.imgsz+0xFFF)&~0xFFF
        uc.mem_map(base, sz)
        uc.mem_write(base, s.pe.d[:0x400])
        for nm,va,vs,rs,ro in s.pe.secs:
            if rs: uc.mem_write(base+va, s.pe.d[ro:ro+rs])
        for a,n in ((STACK,STACK_SZ),(HEAP,HEAP_SZ),(TEB,TEB_SZ),(HOOK,HOOK_SZ),(SCR,SCR_SZ)):
            uc.mem_map(a,n)
        s.brk = HEAP+0x1000
        s.scr = SCR+0x1000
        # TEB / PEB
        PEB = TEB+0x2000
        uc.mem_write(TEB+0x30, struct.pack('<Q',TEB))
        uc.mem_write(TEB+0x60, struct.pack('<Q',PEB))
        uc.mem_write(TEB+0x08, struct.pack('<Q',STACK+STACK_SZ))
        uc.mem_write(TEB+0x10, struct.pack('<Q',STACK))
        try: uc.msr_write(0xC0000101, TEB)
        except Exception: uc.reg_write(UC_X86_REG_MSR,(0xC0000101,TEB))
        s.cmdA = s.alloc_scr((cmdline+"\0").encode())
        s.cmdW = s.alloc_scr((cmdline+"\0").encode('utf-16-le'))
        s.envW = s.alloc_scr("PATH=C:\\\0\0".encode('utf-16-le'))
        s.tls = {}
        s.imports(); s.hooks()

    def alloc_scr(s, data):
        a=s.scr; s.uc.mem_write(a,data); s.scr=(a+len(data)+0x1F)&~0xF; return a
    def malloc(s,n):
        a=s.brk; s.brk=(a+n+0x2F)&~0xF; return a

    def imports(s):
        d,base = s.pe.d, s.pe.base
        s.stubs={}; s.byname={}
        # map RVA->file offset
        def r2o(rva):
            for nm,va,vs,rs,ro in s.pe.secs:
                if va<=rva<va+max(vs,rs): return ro+(rva-va)
            return None
        o=r2o(s.pe.impdir); i=0
        while True:
            ent=o+i*20
            oft,tds,fc,nrva,ft = (rd(d,ent,4),rd(d,ent+4,4),rd(d,ent+8,4),rd(d,ent+12,4),rd(d,ent+16,4))
            if oft==0 and ft==0: break
            to=r2o(oft or ft); fo=ft
            k=0
            while True:
                t=rd(d,to+k*8,8)
                if t==0: break
                nm = "ord_%d"%(t&0xFFFF) if t>>63 else d[r2o(t)+2:].split(b'\0')[0].decode()
                stub = HOOK + len(s.stubs)*16
                s.uc.mem_write(stub, b'\xC3')
                s.stubs[stub]=nm; s.byname[nm]=stub
                s.uc.mem_write(base+fo+k*8, struct.pack('<Q',stub))
                k+=1
            i+=1

    def hooks(s):
        s.uc.hook_add(UC_HOOK_CODE, s.on_code, begin=HOOK, end=HOOK+HOOK_SZ)
        s.uc.hook_add(UC_HOOK_MEM_UNMAPPED, s.on_fault)
        if s.trace: s.uc.hook_add(UC_HOOK_CODE, s.on_trace, begin=s.pe.base, end=s.pe.base+s.pe.imgsz)

    def on_trace(s, uc, addr, size, ud):
        s.tlog.append(addr)

    def on_fault(s, uc, typ, addr, size, val, ud):
        print("!! FAULT type=%d addr=0x%x size=%d rip=0x%x" % (typ,addr,size,uc.reg_read(UC_X86_REG_RIP)))
        return False

    # ---- API stubs ----
    def on_code(s, uc, addr, size, ud):
        nm = s.stubs.get(addr)
        if nm is None: return
        a = [uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        sp = uc.reg_read(UC_X86_REG_RSP)
        st = lambda i: struct.unpack('<Q',uc.mem_read(sp+0x28+8*i,8))[0]  # 5th arg = [rsp+0x28]
        R = lambda v: uc.reg_write(UC_X86_REG_RAX, v & 0xFFFFFFFFFFFFFFFF)
        f = getattr(s, "api_"+nm, None)
        s.cur = nm
        if f:
            try: f(uc,a,st,R)
            except Exception as ex:
                print("!! stub %s raised %s args=%s" % (nm, ex, [hex(x) for x in a])); raise
        else: R(0)   # default: return 0
        if s.log_api: s.apilog.append(nm)

    log_api=True
    apilog=[]
    tlog=[]

    def api_GetCommandLineA(s,uc,a,st,R): R(s.cmdA)
    def api_GetCommandLineW(s,uc,a,st,R): R(s.cmdW)
    def api_GetEnvironmentStringsW(s,uc,a,st,R): R(s.envW)
    def api_FreeEnvironmentStringsW(s,uc,a,st,R): R(1)
    def api_GetProcessHeap(s,uc,a,st,R): R(0x1234)
    def api_HeapAlloc(s,uc,a,st,R):
        n=a[2]; p=s.malloc(n)
        if a[1]&8: uc.mem_write(p, b'\0'*n)
        R(p)
    def api_HeapFree(s,uc,a,st,R): R(1)
    def api_HeapSize(s,uc,a,st,R): R(0x1000)
    def api_HeapReAlloc(s,uc,a,st,R):
        p=s.malloc(a[3]); 
        if a[2]: uc.mem_write(p, uc.mem_read(a[2], min(a[3],0x1000)))
        R(p)
    def api_GetStdHandle(s,uc,a,st,R): R(0xF0 + (a[0]&0xFF))
    def api_WriteFile(s,uc,a,st,R):
        n=a[2]&0xFFFFFFFF; s.out += bytes(uc.mem_read(a[1],n))
        if a[3]: uc.mem_write(a[3], struct.pack('<I',n))
        R(1)
    def api_WriteConsoleW(s,uc,a,st,R):
        n=a[2]; s.out += bytes(uc.mem_read(a[1],n*2)).decode('utf-16-le',errors='replace').encode()
        if a[3]: uc.mem_write(a[3], struct.pack('<I',n))
        R(1)
    def api_GetFileType(s,uc,a,st,R): R(2)
    def api_GetConsoleMode(s,uc,a,st,R): R(0)
    def api_GetConsoleCP(s,uc,a,st,R): R(437)
    def api_GetACP(s,uc,a,st,R): R(1252)
    def api_GetOEMCP(s,uc,a,st,R): R(437)
    def api_IsValidCodePage(s,uc,a,st,R): R(1)
    def api_GetCPInfo(s,uc,a,st,R):
        if a[1]: uc.mem_write(a[1], struct.pack('<I',1)+b'?\0'+b'\0'*12)
        R(1)
    def api_IsProcessorFeaturePresent(s,uc,a,st,R): R(1)
    def api_IsDebuggerPresent(s,uc,a,st,R): R(0)
    def api_GetCurrentProcess(s,uc,a,st,R): R(0xFFFFFFFFFFFFFFFF)
    def api_GetCurrentProcessId(s,uc,a,st,R): R(0x1111)
    def api_GetCurrentThreadId(s,uc,a,st,R): R(0x2222)
    def api_GetSystemTimeAsFileTime(s,uc,a,st,R):
        if a[0]: uc.mem_write(a[0], struct.pack('<Q',0x01D8000000000000))
        R(0)
    qpc = 0x100000
    def api_QueryPerformanceCounter(s,uc,a,st,R):
        s.qpc += 10000          # advance ~1ms per query (10MHz timebase)
        if a[0]: uc.mem_write(a[0], struct.pack('<Q',s.qpc))
        R(1)
    def api_Sleep(s,uc,a,st,R):
        s.qpc += max(a[0],1)*10000
        R(0)
    def api_GetTickCount(s,uc,a,st,R): R(s.qpc//10000)
    def api_QueryPerformanceFrequency(s,uc,a,st,R):
        if a[0]: uc.mem_write(a[0], struct.pack('<Q',10000000))
        R(1)
    def api_GetStartupInfoW(s,uc,a,st,R):
        if a[0]: uc.mem_write(a[0], b'\0'*104)
        R(0)
    def api_GetModuleHandleW(s,uc,a,st,R): R(s.pe.base)
    def api_GetModuleHandleExW(s,uc,a,st,R):
        if a[2]: uc.mem_write(a[2], struct.pack('<Q',s.pe.base))
        R(1)
    def api_GetModuleFileNameA(s,uc,a,st,R):
        b=b"C:\\crackme.exe\0"; uc.mem_write(a[1],b); R(len(b)-1)
    def api_TlsAlloc(s,uc,a,st,R):
        i=len(s.tls); s.tls[i]=0; R(i)
    def api_TlsGetValue(s,uc,a,st,R): R(s.tls.get(a[0],0))
    def api_TlsSetValue(s,uc,a,st,R): s.tls[a[0]]=a[1]; R(1)
    def api_TlsFree(s,uc,a,st,R): R(1)
    def api_InitializeCriticalSectionAndSpinCount(s,uc,a,st,R): R(1)
    def api_SetUnhandledExceptionFilter(s,uc,a,st,R): R(0)
    def api_SetLastError(s,uc,a,st,R): R(0)
    def api_GetLastError(s,uc,a,st,R): R(0)
    def api_MultiByteToWideChar(s,uc,a,st,R):
        src=a[2]; n=a[3]&0xFFFFFFFF
        if n==0xFFFFFFFF:
            b=b''; p=src
            while True:
                c=uc.mem_read(p,1)
                if c==b'\0': break
                b+=c; p+=1
            b+=b'\0'
        else: b=bytes(uc.mem_read(src,n))
        w=b.decode('latin-1').encode('utf-16-le')
        dst=st(0); cch=st(1)&0xFFFFFFFF
        if dst and cch: uc.mem_write(dst, w[:cch*2])
        R(len(w)//2)
    def api_WideCharToMultiByte(s,uc,a,st,R):
        src=a[2]; n=a[3]&0xFFFFFFFF
        if n==0xFFFFFFFF:
            b=b''; p=src
            while True:
                c=bytes(uc.mem_read(p,2))
                if c==b'\0\0': break
                b+=c; p+=2
            b+=b'\0\0'
        else: b=bytes(uc.mem_read(src,n*2))
        m=b.decode('utf-16-le',errors='replace').encode('latin-1',errors='replace')
        dst=st(0); cb=st(1)&0xFFFFFFFF
        if dst and cb: uc.mem_write(dst, m[:cb])
        R(len(m))
    def api_GetStringTypeW(s,uc,a,st,R):
        typ,src,n,dst = a[0],a[1],a[2]&0xFFFFFFFF,a[3]
        if n==0xFFFFFFFF:
            n=0
            while struct.unpack('<H',uc.mem_read(src+2*n,2))[0]: n+=1
            n+=1
        if not dst: R(0); return
        o=b''
        for i in range(n):
            c=struct.unpack('<H',uc.mem_read(src+2*i,2))[0]; ch=chr(c); t=0
            if ch.isupper(): t|=0x0001
            if ch.islower(): t|=0x0002
            if ch.isdigit(): t|=0x0004
            if ch in ' \t\n\r\f\v': t|=0x0008
            if ch in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~': t|=0x0010
            if c<32 or c==127: t|=0x0020
            if ch==' ': t|=0x0040
            if ch.isalpha(): t|=0x0100
            o+=struct.pack('<H',t)
        uc.mem_write(dst,o); R(1)
    def api_LCMapStringW(s,uc,a,st,R):
        flags,src,n = a[1],a[2],a[3]&0xFFFFFFFF
        dst,cch = st(0), st(1)&0xFFFFFFFF
        if n==0xFFFFFFFF:
            n=0
            while struct.unpack('<H',uc.mem_read(src+2*n,2))[0]: n+=1
            n+=1
        w=bytes(uc.mem_read(src,2*n)).decode('utf-16-le',errors='replace')
        if flags & 0x00000100: w=w.lower()
        if flags & 0x00000200: w=w.upper()
        ob=w.encode('utf-16-le')
        if dst and cch: uc.mem_write(dst, ob[:cch*2])
        R(len(w))
    def api_GetLocaleInfoEx(s,uc,a,st,R): R(0)
    def api_CompareStringW(s,uc,a,st,R): R(2)
    def api_ExitProcess(s,uc,a,st,R): s.stopped=True; uc.emu_stop()
    def api_TerminateProcess(s,uc,a,st,R): s.stopped=True; uc.emu_stop()

    def run(s, start=None, timeout=0):
        uc=s.uc
        sp = STACK+STACK_SZ-0x2000
        uc.reg_write(UC_X86_REG_RSP, sp)
        RET = HOOK+HOOK_SZ-16
        uc.mem_write(RET, b'\xC3')
        uc.mem_write(sp, struct.pack('<Q',RET))
        s.stubs[RET]="__done__"
        try:
            uc.emu_start(start or s.pe.entry, RET, timeout=timeout)
        except UcError as e:
            print("UcError:", e, "rip=0x%x"%uc.reg_read(UC_X86_REG_RIP))
        return s.out

if __name__=="__main__":
    key = sys.argv[1] if len(sys.argv)>1 else "AAAA-BBBB-CCCC-DDDD"
    e = Emu('crackme.exe %s'%key)
    out = e.run(timeout=60*1000000)
    print("=== OUTPUT ===")
    print(out.decode(errors='replace'))
    print("=== last APIs ===", e.apilog[-25:])
