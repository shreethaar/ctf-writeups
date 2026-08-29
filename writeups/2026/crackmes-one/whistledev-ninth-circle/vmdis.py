import struct
M=0xffffffff
def rol(v,n): v&=M; n&=31; return ((v<<n)|(v>>(32-n)))&M if n else v
def ror(v,n): v&=M; n&=31; return ((v>>n)|(v<<(32-n)))&M if n else v
def imm32(code,p):
    k = rol((p*0x9e3779b9 - 0x69cfb59a)&M, (p%29)+1)
    return (k ^ struct.unpack_from('<I',code,p)[0] ^ 0x6d2b79f5)&M
# op -> (mnemonic, length, kind)
OPS={0x32:('MOVI',6,'ri'),0x16:('MULI',6,'ri'),0x48:('ADDI',6,'ri'),0xfe:('XORI',6,'ri'),
     0x2e:('MUL',3,'rr'),0x37:('ADD',3,'rr'),0x65:('XOR',3,'rr'),0x72:('MOV',3,'rr'),
     0x6e:('LOADB',3,'rr'),0x52:('ROL',3,'rs'),0x9a:('ROR',3,'rs'),
     0x28:('LEN',2,'r'),0x56:('INC',2,'r'),0x5f:('HALT',1,'-'),
     0x24:('EQ',4,'rrr'),0x8b:('GT',4,'rrr'),0xa6:('JNZ',4,'rj'),0xd3:('JMP',3,'j')}
def dis(code):
    p=0; out=[]
    while p < len(code):
        op=code[p]
        if op not in OPS: out.append((p,f".byte 0x{op:02x} ???")); p+=1; continue
        mn,ln,kind=OPS[op]
        if kind=='ri':   t=f"{mn} r{code[p+1]}, 0x{imm32(code,p+2):08x}"
        elif kind=='rr': t=f"{mn} r{code[p+1]}, r{code[p+2]}"
        elif kind=='rs': t=f"{mn} r{code[p+1]}, {code[p+2]&31}"
        elif kind=='r':  t=f"{mn} r{code[p+1]}"
        elif kind=='rrr':t=f"{mn} r{code[p+1]}, r{code[p+2]}, r{code[p+3]}"
        elif kind=='rj':
            rel=struct.unpack_from('<h',code,p+2)[0]; t=f"{mn} r{code[p+1]}, ->0x{p+4+rel:03x}"
        elif kind=='j':
            rel=struct.unpack_from('<h',code,p+1)[0]; t=f"{mn} ->0x{p+3+rel:03x}"
        else: t=mn
        out.append((p,t)); p+=ln
    return out
if __name__=="__main__":
    code=open("vm_bytecode.bin","rb").read()
    for p,t in dis(code): print(f"0x{p:03x}:  {t}")
