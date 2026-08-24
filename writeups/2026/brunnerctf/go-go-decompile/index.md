# Go Go Decompile

- Category: rev
- Difficulty: Easy

A Go binary (`go_go_budgetmaster`) asks for input on stdin and tells you whether you got it right. No source given — just the compiled binary.

### Solution:

##### 1. Decompile `main.main`

Loaded the binary into Binary Ninja (Go decompiler). Raw decompiler output for `main.main`:

```c
004a1f80    bool main.main()

004a1f80    {
004a1f80        struct string flagb64;
004a1f8c        void* entry_r14;
004a1f8c        
004a1f8c        if (&flagb64.len <= *(uint64_t*)((char*)entry_r14 + 0x10))
004a1f8c        {
004a2267            runtime.morestack_noctxt.abi0();
004a2267            /* no return */
004a1f8c        }
004a1f8c        
004a1f9d        os.Stdout;
004a1fb0        int64_t entry_s;
004a1fb0        struct os.File* entry_f;
004a1fb0        struct bufio.Scanner* ~r0_3 = os.(*File).WriteString(entry_f, entry_s);
004a1fbc        flagb64.str = "YnJ1bm5lcntnMF9kM2MwbXAxbDNkX2cwX2Jycn0=Correct!\nThis is way better "
004a1fbc        "than Excel!\ninvalid span in heapArena for user arenabulkBarrierPreWrite: unaligned "
004a1fbc        "argumentsruntime: typeBitsBulkBarrier wi";
004a1fc1        flagb64.len = 0x28;
004a1fcd        struct os.File* os.Stdin_1 = os.Stdin;
004a1fe0        void r;
004a1fe0        struct internal/abi.Type* scanner_1;
004a1fe0        bool ~r0_2;
004a1fe0        struct bufio.Scanner* s_1;
004a1fe0        scanner_1 = bufio.NewScanner(r, ~r0_3);
004a1fe5        struct internal/abi.Type* scanner = scanner_1;
004a1fea        bool result;
004a1fea        struct bufio.Scanner* s_2;
004a1fea        result = bufio.(*Scanner).Scan(s_1, ~r0_2);
004a1fef        bool result_1 = result;
004a1fef        
004a1ff5        if (!result)
004a2001            return result;
004a2001        
004a2001        void* rax_3;
004a2001        int ~r0_1;
004a2001        int rsi;
004a2001        struct encoding/base64.Encoding* rdi;
004a2001        rax_3 = bufio.(*Scanner).Text(s_2);
004a2006        struct string input;
004a2006        input.str = rax_3;
004a200b        input.len = os.Stdin_1;
004a2018        int len = flagb64.len;
004a201d        encoding/base64.StdEncoding;
004a2024        int64_t ~r0;
004a2024        int cap_1;
004a2024        ~r0 = encoding/base64.(*Encoding).DecodedLen(rdi, rsi, ~r0_1);
004a2040        struct internal/abi.Type* rax_6;
004a2040        int128_t zmm15;
004a2040        rax_6 = runtime.makeslice(rdi, rsi, cap_1, ~r0);
004a204f        struct internal/abi.Type* var_58 = rax_6;
004a2057        int64_t ~r0_4 = ~r0;
004a205f        int64_t ~r0_5 = ~r0;
004a2067        struct []uint8 data;
004a2067        data.array = rax_6;
004a206f        data.len = ~r0;
004a2077        data.cap = ~r0;
004a207f        struct internal/godebug.runtimeStderr* str = flagb64.str;
004a2084        int len_1 = flagb64.len;
004a2084        
004a208f        if (!str)
004a2095            str = &internal/godebug.stderr;
004a2095        
004a20a6        int len_2 = len_1;
004a20ae        int len_3 = len_1;
004a20b6        int128_t var_30 = zmm15;
004a20bf        void* array = data.array;
004a20c7        encoding/base64.StdEncoding;
004a20f6        int rax_8;
004a20f6        int64_t rcx_4;
004a20f6        struct os.File* f;
004a20f6        rax_8 = encoding/base64.(*Encoding).Decode(data.cap, str);
004a2100        (uint64_t)var_30 = array;
004a2108        *(uint64_t*)((char*)&var_30 + 8) = rcx_4;
004a211a        void* array_2 = array;
004a2122        int64_t var_80 = rcx_4;
004a2134        error err;
004a2134        err.tab = array;
004a213c        err.data = rcx_4;
004a213c        
004a2147        if (array)
004a2147        {
004a214b            *(uint8_t*)array;
004a2156            int64_t var_40_1 = (*(uint64_t*)((char*)array + 0x18))();
004a215e            void* array_4 = array;
004a217a            int64_t rax_12;
004a217a            int64_t s;
004a217a            struct os.File* f_1;
004a217a            rax_12 = runtime.concatstring2(&data_4d0020);
004a217f            int64_t var_68_1 = rax_12;
004a2187            int64_t s_3 = s;
004a218f            os.Stderr;
004a21a5            f = os.(*File).WriteString(f_1, s);
004a2147        }
004a2147        
004a21b3        uint8* array_1 = data.array;
004a21bb        int cap = data.cap;
004a21bb        
004a21c6        if (cap < rax_8)
004a21c6        {
004a21cf            runtime.panicBounds();
004a2261            /* no return */
004a21c6        }
004a21c6        
004a21cf        struct []uint8 flag;
004a21cf        flag.array = array_1;
004a21d7        flag.len = rax_8;
004a21df        flag.cap = cap;
004a21e7        uint8* array_3 = array_1;
004a21ef        int var_70 = rax_8;
004a21ef        
004a21fc        if (input.len == rax_8)
004a21fc        {
004a220c            char rax_15;
004a220c            rax_15 = runtime.memequal();
004a220c            
004a2213            if (rax_15)
004a2213            {
004a2217                os.Stdout;
004a222a                return os.(*File).WriteString(f, cap);
004a2213            }
004a21fc        }
004a21fc        
004a2235        os.Stdout;
004a2248        return os.(*File).WriteString(f, cap);
004a1f80    }
```

##### 2. Filter the Go noise

Most of that is runtime scaffolding — `morestack_noctxt` stack-growth checks, slice/string header splits, SSA temp variables (`~r0`, `rax_N`). Filtering it down to the actual logic:

```go
func main() {
    flagb64 := "YnJ1bm5lcntnMF9kM2MwbXAxbDNkX2cwX2Jycn0=" // len = 0x28 (40 bytes)

    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    input := scanner.Text()

    flag, err := base64.StdEncoding.Decode(flagb64)
    if len(input) == len(flag) && bytes.Equal(input, flag) {
        os.Stdout.WriteString("Correct!\n")
    } else {
        os.Stdout.WriteString("...\n")
    }
}
```

The decompiler concatenates the real 40-byte base64 literal with adjacent entries from Go's read-only string table (`"Correct!\nThis is way better than Excel!..."`, runtime panic strings) since they sit contiguously in `.rodata`. The `flagb64.len = 0x28` field is what tells you exactly where the real string ends.

##### 3. Confirm there's no transformation

The rest of `main.main` is just: read a line from stdin, base64-decode the hardcoded constant, then `len` check + `runtime.memequal` against the input. No hashing, XOR, or per-byte scrambling — the flag *is* the decoded constant, and the "check" is cosmetic.

##### 4. Decode

```
$ echo "YnJ1bm5lcntnMF9kM2MwbXAxbDNkX2cwX2Jycn0=" | base64 -d
brunner{g0_d3c0mp1l3d_g0_brr}
```

No dynamic analysis, debugger, or input crafting required — static extraction of the constant was enough.

**Flag:** `brunner{g0_d3c0mp1l3d_g0_brr}`
