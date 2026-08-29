import struct
M=0xffffffff
def rol(v,n): v&=M; n&=31; return ((v<<n)|(v>>(32-n)))&M if n else v
def ror(v,n): v&=M; n&=31; return ((v>>n)|(v<<(32-n)))&M if n else v
def imm32(code,p):
    k = rol((p*0x9e3779b9 - 0x69cfb59a)&M,(p%29)+1)
    return (k ^ struct.unpack_from('<I',code,p)[0] ^ 0x6d2b79f5)&M

def run(code, data, maxsteps=20000):
    R=[0]*12; pc=0
    for _ in range(maxsteps):
        if pc<0 or pc>=len(code): raise Exception("pc oob")
        op=code[pc]
        if   op==0x32: R[code[pc+1]]=imm32(code,pc+2); pc+=6
        elif op==0x16: d=code[pc+1]; R[d]=(R[d]*imm32(code,pc+2))&M; pc+=6
        elif op==0x48: d=code[pc+1]; R[d]=(R[d]+imm32(code,pc+2))&M; pc+=6
        elif op==0xfe: d=code[pc+1]; R[d]^=imm32(code,pc+2); pc+=6
        elif op==0x2e: R[code[pc+1]]=(R[code[pc+1]]*R[code[pc+2]])&M; pc+=3
        elif op==0x37: R[code[pc+1]]=(R[code[pc+1]]+R[code[pc+2]])&M; pc+=3
        elif op==0x65: R[code[pc+1]]^=R[code[pc+2]]; pc+=3
        elif op==0x72: R[code[pc+1]]=R[code[pc+2]]; pc+=3
        elif op==0x6e:
            idx=R[code[pc+2]]
            if idx>=len(data): raise Exception("data oob")
            R[code[pc+1]]=data[idx]; pc+=3
        elif op==0x52: d=code[pc+1]; R[d]=rol(R[d],code[pc+2]&31); pc+=3
        elif op==0x9a: d=code[pc+1]; R[d]=ror(R[d],code[pc+2]&31); pc+=3
        elif op==0x28: R[code[pc+1]]=len(data)&M; pc+=2
        elif op==0x56: d=code[pc+1]; R[d]=(R[d]+1)&M; pc+=2
        elif op==0x24: R[code[pc+1]]=1 if R[code[pc+3]]==R[code[pc+2]] else 0; pc+=4
        elif op==0x8b: R[code[pc+1]]=1 if R[code[pc+3]]>R[code[pc+2]] else 0; pc+=4
        elif op==0xa6:
            rel=struct.unpack_from('<h',code,pc+2)[0]; pc = pc+4+rel if R[code[pc+1]] else pc+4
        elif op==0xd3:
            rel=struct.unpack_from('<h',code,pc+1)[0]; pc = pc+3+rel
        elif op==0x5f: return R[0],R[1],R[2],R[3]
        else: raise Exception("bad op 0x%02x"%op)
    raise Exception("step limit")

CODE=open("vm_bytecode.bin","rb").read()
def serial(op_id):
    r=run(CODE, op_id.encode())
    return "-".join("%08X"%x for x in r)
if __name__=="__main__":
    import sys
    for oid in (sys.argv[1:] or ["TESTOP"]):
        print(oid, "->", serial(oid))
