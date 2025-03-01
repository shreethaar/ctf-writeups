---
title: Trust Issues
layout: default
---
# Trust Issues

A program is checking your input against a hidden value, but the comparison is far from straightforward. Something’s been altered to obscure the truth. Your goal is to uncover the transformation behind the check and reveal the original content.

- Category: Rev
- Challenge file: trust.exe

### Solution:
##### 1. Use IDA to perform static analysis
Decompile the binary with IDA and finding out user-implement functions. Here is the main function:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __main();
  if ( argc > 1 )
  {
    if ( !strcmp(argv[1], "GRX14YcKLzXOlW5iaSlBIrN7") )
      puts("Correct!!");
    else
      puts("Wrong!!");
    return 0;
  }
  else
  {
    puts("Wrong!!");
    return 1;
  }
}
```

However, for `strcmp` which is part of C function, it was different and looks like custom implemented by the user. Here is the part of `strcmp`:

```c
int __cdecl strcmp(const char *Str1, const char *Str2)
{
  char v3[10]; // [esp+4h] [ebp-1Ch]
  char v4[12]; // [esp+Eh] [ebp-12h] BYREF
  _WORD v5[3]; // [esp+1Ah] [ebp-6h] BYREF

  v3[0] = 6;
  v3[1] = 17;
  v3[2] = 29;
  v3[3] = 114;
  v3[4] = 96;
  v3[5] = 31;
  v3[6] = 24;
  v3[7] = 124;
  v3[8] = 62;
  v3[9] = 15;
  qmemcpy(v4, "mx35@^>%_0x", 11);
  v4[11] = 20;
  strcpy((char *)v5, "7J");
  HIBYTE(v5[1]) = 0;
  v5[2] = 0;
  while ( *(_DWORD *)&v5[1] <= 0x17u )
  {
    if ( !Str1[*(_DWORD *)&v5[1]] || !Str2[*(_DWORD *)&v5[1]] )
      return 1;
    if ( ((unsigned __int8)v3[*(_DWORD *)&v5[1]] ^ Str1[*(_DWORD *)&v5[1]]) != Str2[*(_DWORD *)&v5[1]] )
      return 1;
    ++*(_DWORD *)&v5[1];
  }
  return 0;
}
```

From here, we know the custom `strcmp` function compares each character of input string with the target string using XOR operations against a predefined array (`v3`) and other variables (`v4` and `v5`). The XOR key is constructed from the array `v3`, `v4` and the first two bytes of `v5` in the custom `strcmp` function. These arrays are combined to form a 24-byte key. For each character in the target string `"GRX14YcKLzXOlW5iaSlBIrN7"` compute the corresponding input character by XORing it with the corresponding byte in the XOR key

Here is the code to reverse it: 
```go 
package main

import (
	"fmt"
)

func main() {
	// Construct the XOR key based on v3, v4, and v5 from the custom strcmp
	xorKey := []byte{
		// v3 array elements
		6, 17, 29, 114, 96, 31, 24, 124, 62, 15,
		// v4 array elements: "mx35@^>%_0x" followed by 20
		'm', 'x', '3', '5', '@', '^', '>', '%', '_', '0', 'x', 20,
		// First two bytes from v5 after initialization
		55, 74,
	}

	// The target string from the main function
	targetStr := "GRX14YcKLzXOlW5iaSlBIrN7"

	// Ensure the lengths are correct
	if len(xorKey) != 24 || len(targetStr) != 24 {
		panic("Key or target string length mismatch")
	}

	// Compute each character of the correct input
	input := make([]byte, 24)
	for i := 0; i < 24; i++ {
		input[i] = xorKey[i] ^ targetStr[i]
	}

	// Output the result
	fmt.Println(string(input))
}
```

**Flag:** `ACECTF{7ru57_bu7_v3r1fy}`
