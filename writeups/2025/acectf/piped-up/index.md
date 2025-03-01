---
title: Piped UP
layout: default
---
# Piped Up

A sequence of transformations twists and distorts the truth, layer by layer, before it reaches its final destination. By the time it’s checked, the original meaning is deeply buried. Can you trace the pipeline, reverse the modifications, and uncover what was hidden?

- Category: rev
- Challenge File: piped_up.exe

### Solution:
##### 1. Use IDA to decompile the binary 
After decompile the binary, analyze the main function
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char Buffer[39]; // [esp+1h] [ebp-95h] BYREF
  char v6[31]; // [esp+28h] [ebp-6Eh] BYREF
  char Buf2[31]; // [esp+47h] [ebp-4Fh] BYREF
  DWORD NumberOfBytesWritten; // [esp+66h] [ebp-30h] BYREF
  DWORD nNumberOfBytesToWrite; // [esp+6Ah] [ebp-2Ch] BYREF
  HANDLE hFile; // [esp+6Eh] [ebp-28h]
  HANDLE StdHandle; // [esp+72h] [ebp-24h]
  int v12; // [esp+76h] [ebp-20h]
  DWORD k; // [esp+7Ah] [ebp-1Ch]
  int v14; // [esp+7Eh] [ebp-18h]
  DWORD j; // [esp+82h] [ebp-14h]
  DWORD i; // [esp+86h] [ebp-10h]
  char v17; // [esp+8Dh] [ebp-9h]
  int *p_argc; // [esp+8Eh] [ebp-8h]

  p_argc = &argc;
  __main();
  if ( argc == 3 )
  {
    v12 = atoi(argv[1]);
    StdHandle = GetStdHandle(0xFFFFFFF6);
    hFile = GetStdHandle(0xFFFFFFF5);
    switch ( v12 )
    {
      case 1:
        v17 = 0;
        while ( ReadFile(StdHandle, Buffer, 0x27u, &nNumberOfBytesToWrite, 0) && nNumberOfBytesToWrite )
        {
          for ( i = 0; i < nNumberOfBytesToWrite; ++i )
          {
            Buffer[i] ^= v17;
            v17 = Buffer[i];
          }
          WriteFile(hFile, Buffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0);
        }
        break;
      case 2:
        qmemcpy(Buf2, "l,", 2);
        Buf2[2] = -32;
        Buf2[3] = -17;
        Buf2[4] = -115;
        Buf2[5] = 96;
        Buf2[6] = -36;
        Buf2[7] = 117;
        Buf2[8] = 13;
        Buf2[9] = -1;
        Buf2[10] = -42;
        Buf2[11] = 89;
        Buf2[12] = -12;
        Buf2[13] = 93;
        Buf2[14] = -34;
        Buf2[15] = -101;
        Buf2[16] = -29;
        Buf2[17] = -41;
        Buf2[18] = 82;
        Buf2[19] = -103;
        Buf2[20] = 90;
        Buf2[21] = 124;
        Buf2[22] = -93;
        Buf2[23] = -55;
        Buf2[24] = 78;
        Buf2[25] = 27;
        Buf2[26] = 69;
        Buf2[27] = -27;
        Buf2[28] = -64;
        Buf2[29] = 41;
        Buf2[30] = -102;
        ReadFile(StdHandle, Buffer, 0x27u, &nNumberOfBytesToWrite, 0);
        if ( !memcmp(Buffer, Buf2, 0x27u) )
          puts("Correct!!");
        else
          puts("Wrong!!");
        break;
      case 3:
        while ( ReadFile(StdHandle, Buffer, 0x27u, &nNumberOfBytesToWrite, 0) && nNumberOfBytesToWrite )
        {
          for ( j = 0; j < nNumberOfBytesToWrite; ++j )
            Buffer[j] ^= 0x56u;
          WriteFile(hFile, Buffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0);
        }
        break;
      case 4:
        WriteFile(hFile, argv[2], 0x27u, &NumberOfBytesWritten, 0);
        break;
      case 5:
        qmemcpy(v6, "{.", 2);
        v6[2] = -15;
        v6[3] = -21;
        v6[4] = -117;
        v6[5] = 118;
        v6[6] = -25;
        v6[7] = 104;
        v6[8] = 119;
        v6[9] = -93;
        v6[10] = -17;
        v6[11] = 82;
        v6[12] = -10;
        v6[13] = 60;
        v6[14] = -38;
        v6[15] = -86;
        v6[16] = -10;
        v6[17] = -89;
        v6[18] = 67;
        v6[19] = -21;
        v6[20] = 33;
        v6[21] = 36;
        v6[22] = -61;
        v6[23] = -100;
        v6[24] = 125;
        v6[25] = 8;
        v6[26] = 51;
        v6[27] = -73;
        v6[28] = -9;
        v6[29] = 44;
        v6[30] = -76;
        v14 = 0;
        while ( ReadFile(StdHandle, Buffer, 0x27u, &nNumberOfBytesToWrite, 0) && nNumberOfBytesToWrite )
        {
          for ( k = 0; k < nNumberOfBytesToWrite; ++k )
          {
            v3 = v14++;
            Buffer[k] ^= v6[v3];
            if ( v14 == 31 )
              v14 = 0;
          }
          WriteFile(hFile, Buffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0);
        }
        break;
    }
    return 0;
  }
  else if ( argc > 1 && strlen(argv[1]) == 39 )
  {
    return 0;
  }
  else
  {
    puts("Wrong!!");
    return 1;
  }
}
```

From the main function, it implement some use cases based off the command line arguments. The key case is the second one where it will read input and compare with a the `Buf2`. 

##### 2. Find match input for Buf2
Next, we have to extract Buf2 and v6 hardcoded value and XOR with possible keys. Here is the go code for it:

```go

package main

import (
	"fmt"
)

func main() {
	encryptedBytes := []byte{
		0x6c, 0x2c, 0xe0, 0xef, 0x8d, 0x60, 0xdc, 0x75, 0x0d, 0xff,
		0xd6, 0x59, 0xf4, 0x5d, 0xde, 0x9b, 0xe3, 0xd7, 0x52, 0x99,
		0x5a, 0x7c, 0xa3, 0xc9, 0x4e, 0x1b, 0x45, 0xe5, 0xc0, 0x29, 0x9a,
	}

	xorKey := []byte{
		0x7b, 0x2e, 0xf1, 0xeb, 0x8b, 0x76, 0xe7, 0x68, 0x77, 0xa3,
		0xef, 0x52, 0xf6, 0x3c, 0xda, 0xaa, 0xf6, 0xa7, 0x43, 0xeb,
		0x21, 0x24, 0xc3, 0x9c, 0x7d, 0x08, 0x33, 0xb7, 0xf7, 0x2c, 0xb4,
	}

	// Step 1: XOR decryption with the key
	step1 := make([]byte, len(encryptedBytes))
	for i := range encryptedBytes {
		step1[i] = encryptedBytes[i] ^ xorKey[i%len(xorKey)]
	}

	// Step 2: Reverse custom XOR propagation
	step2 := reverseMode1(step1, 0)

	// Step 3: XOR with 0x56
	step3 := make([]byte, len(step2))
	for i, b := range step2 {
		step3[i] = b ^ 0x56
	}

	// Convert to string and print flag
	fmt.Println(string(step3))
}

func reverseMode1(bytesArray []byte, initialByte byte) []byte {
	result := make([]byte, len(bytesArray))
	prevCipherByte := initialByte

	for i := range bytesArray {
		plaintextByte := bytesArray[i] ^ prevCipherByte
		result[i] = plaintextByte
		prevCipherByte = bytesArray[i]
	}

	return result
}
```

**Flag:** `ACECTF{p1p3d_53cr375_unc0v3r3d}`