---
title: keystore-rs
layout: default
---

# keystore-rs

you wanted more pwn - so i wrote a rust rev challenge. xoxo 

- Category: rev
- Challenge file: keystore-rs

### Solution:

##### 1. Use file command to analyze the binary and try to run it
```sh
$ file keystore-rs 
keystore-rs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c9f888947f11d6f5e04e327a9b04ea6c6e322940, for GNU/Linux 3.2.0, stripped

$ ./keystore-rs 
Welcome to the flag checker!
> What's the secret password 🔑? test
The key must be 32 characters long!
```

Based on the challenge description suggest the binary is written and compile using Rust and the binary is stripped. It has the functions like a flag-checker where we have to crack it. 


##### 2. Try to perform debugging and analyze the behaviour

```sh
$ ltrace ./keystore-rs
+++ exited (status 0) +++

$ strace ./keystore-rs
execve("./keystore-rs", ["./keystore-rs"], 0x7ffd3d048620 /* 60 vars */) = 0
brk(NULL)                               = 0x5e0ca2756000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=156895, ...}) = 0
mmap(NULL, 156895, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7293f9a55000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=916136, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7293f9a53000
mmap(NULL, 184808, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7293f9a25000
mmap(0x7293f9a29000, 147456, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x4000) = 0x7293f9a29000
mmap(0x7293f9a4d000, 16384, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7293f9a4d000
mmap(0x7293f9a51000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2b000) = 0x7293f9a51000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0`v\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
fstat(3, {st_mode=S_IFREG|0755, st_size=2014520, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
mmap(NULL, 2038904, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7293f9833000
mmap(0x7293f9857000, 1511424, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x24000) = 0x7293f9857000
mmap(0x7293f99c8000, 323584, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x195000) = 0x7293f99c8000
mmap(0x7293f9a17000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e3000) = 0x7293f9a17000
mmap(0x7293f9a1d000, 31864, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7293f9a1d000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7293f9830000
arch_prctl(ARCH_SET_FS, 0x7293f9830840) = 0
set_tid_address(0x7293f9830b10)         = 16775
set_robust_list(0x7293f9830b20, 24)     = 0
rseq(0x7293f98306a0, 0x20, 0, 0x53053053) = 0
mprotect(0x7293f9a17000, 16384, PROT_READ) = 0
mprotect(0x7293f9a51000, 4096, PROT_READ) = 0
mprotect(0x5e0c93e97000, 20480, PROT_READ) = 0
mprotect(0x7293f9ab7000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7293f9a55000, 156895)          = 0
poll([{fd=0, events=0}, {fd=1, events=0}, {fd=2, events=0}], 3, 0) = 0 (Timeout)
rt_sigaction(SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[PIPE], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7293f9870cd0}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
getrandom("\x8e\xd1\x8f\xae\xe3\xc4\x32\x78", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x5e0ca2756000
brk(0x5e0ca2777000)                     = 0x5e0ca2777000
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 3
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
fstat(3, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
read(3, "5e0c93e0c000-5e0c93e14000 r--p 0"..., 1024) = 1024
read(3, ":03 5115171                   /u"..., 1024) = 1024
read(3, "0:00 0                          "..., 1024) = 855
close(3)                                = 0
sched_getaffinity(16775, 32, [0 1 2 3 4 5 6 7]) = 8
rt_sigaction(SIGSEGV, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
sigaltstack(NULL, {ss_sp=NULL, ss_flags=SS_DISABLE, ss_size=0}) = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7293f9a79000
mprotect(0x7293f9a79000, 4096, PROT_NONE) = 0
sigaltstack({ss_sp=0x7293f9a7a000, ss_flags=0, ss_size=8192}, NULL) = 0
rt_sigaction(SIGSEGV, {sa_handler=0x5e0c93e416d0, sa_mask=[], sa_flags=SA_RESTORER|SA_ONSTACK|SA_SIGINFO, sa_restorer=0x7293f9870cd0}, NULL, 8) = 0
rt_sigaction(SIGBUS, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigaction(SIGBUS, {sa_handler=0x5e0c93e416d0, sa_mask=[], sa_flags=SA_RESTORER|SA_ONSTACK|SA_SIGINFO, sa_restorer=0x7293f9870cd0}, NULL, 8) = 0
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
exit_group(0)                           = ?
+++ exited with 0 +++

$ gdb ./keystore-rs
pwndbg> r
Starting program: /home/trevorphilips/Desktop/REV-Artifacts/x3ctf/notcrypto/keystore/keystore-rs 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
[Inferior 1 (process 16836) exited normally]
pwndbg>
```

It has anti-debugging function. 

### 3. Find out the anti-debugging function

Here are the steps to find the anti-debug function:
- Use gdb/pwndbg, `start` and set a breakpoint at `_exit` and catch exit. 
- Head back the IDA, find the function exit. Identify function with xref graph. Below `main` function will be a function `sub_B9D0`.

At the function `sub_B9D0`, there is anti-debug process:
```rs 
LOBYTE(v317[0]) = sys_ptrace(0LL, 0LL, 0LL, 0LL) != 0;
  s[0].m128i_i64[0] = (__int64)v317;
  s[0].m128i_i64[1] = (__int64)src;
  s[1].m128i_i64[0] = (__int64)&v301;
  sub_A7DD(s);
  LODWORD(v317[0]) = 0;
  s[1].m128i_i64[0] = src[1].m128i_i64[0];
  s[0] = src[0];
  s[1].m128i_i64[1] = (__int64)v317;
  sub_A74F(s);
  if ( LODWORD(v317[0]) != v301.m256i_i32[0] )
    v0 = sys_exit_group(0);
```

We able to bypass `ptrace` in gdb by setting it `$rax=0`. 

##### 4. Find out the welcome message address 

With Binary Ninja, we able to xref the string of "Welcome ..." along the way to 
