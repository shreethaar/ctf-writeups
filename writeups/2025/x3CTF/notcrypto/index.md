---
title: notcrypto
layout: default
---

# notcrypto

You shouldn't need to call your crypto teammate for this challenge lol.

- Category: Rev
- Challenge file: spn


### Solution:

##### 1. Use file command to analyze the binary

```sh 
$ file spn
spn: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=99edb33d421b346c96dbca0bafc6b36f72aa75aa, for GNU/Linux 3.2.0, stripped
```

The binary is stripped, where symbol table of the binary is removed. 


##### 2. Decompile with IDA 

Here is the entry point (main function) of the binary

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  __int64 v3; // rcx
  _BYTE *v4; // rbx
  char v5; // al
  unsigned __int8 v6; // bp
  int v7; // r12d
  _BYTE *v8; // rax
  unsigned __int64 v9; // rcx
  __int64 v10; // r14
  __int64 v11; // r13
  unsigned __int64 v12; // rcx
  unsigned __int8 v13; // r14
  unsigned __int8 v14; // r10
  unsigned __int8 v15; // r8
  unsigned __int8 v16; // bl
  unsigned __int8 v17; // di
  unsigned __int8 v18; // r9
  unsigned __int8 v19; // r15
  unsigned __int8 v20; // bp
  int i; // r11d
  __int64 v22; // r12
  __int64 v23; // r13
  __int64 v24; // rbp
  __int64 v25; // rsi
  __int64 v26; // rax
  void *v27; // [rsp+0h] [rbp-58h] BYREF
  __int64 v28; // [rsp+8h] [rbp-50h]
  _QWORD v29[2]; // [rsp+10h] [rbp-48h] BYREF
  _BYTE *v30; // [rsp+20h] [rbp-38h]

  v27 = v29;
  v28 = 0LL;
  LOBYTE(v29[0]) = 0;
  v3 = *(_QWORD *)(std::cin - 24LL);
  v4 = *(_BYTE **)((char *)&std::cin + v3 + 240);
  if ( !v4 )
    std::__throw_bad_cast();
  if ( v4[56] )
  {
    v5 = v4[67];
  }
  else
  {
    std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cin + v3 + 240), a2, a3);
    v5 = (*(__int64 (__fastcall **)(_BYTE *, __int64))(*(_QWORD *)v4 + 48LL))(v4, 10LL);
  }
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v27, (unsigned int)v5);
  v6 = 8;
  if ( (v28 & 7) != 0 )
    v6 = 8 - (v28 & 7);
  v7 = v6;
  while ( 1 )
  {
    v8 = v27;
    v9 = 15LL;
    if ( v27 != v29 )
      v9 = v29[0];
    v10 = v28;
    v11 = v28 + 1;
    if ( v28 + 1 > v9 )
    {
      std::string::_M_mutate(&v27, v28, 0LL, 0LL, 1LL);
      v8 = v27;
    }
    v8[v10] = v6;
    v28 = v11;
    *((_BYTE *)v27 + v10 + 1) = 0;
    if ( !--v7 )
    {
      if ( v28 == 56 )
      {
        v30 = v27;
        v12 = 0LL;
        while ( 1 )
        {
          v13 = v30[v12];
          v14 = v30[v12 + 1];
          v15 = v30[v12 + 2];
          v16 = v30[v12 + 3];
          v17 = v30[v12 + 4];
          v18 = v30[v12 + 5];
          v19 = v30[v12 + 6];
          v20 = v30[v12 + 7];
          for ( i = 0; i != 4096; ++i )
          {
            v22 = v13;
            v23 = v20;
            v24 = v14;
            v25 = v15;
            v26 = v17;
            v13 = i ^ byte_4050[v19];
            v14 = i ^ byte_4050[v22];
            v15 = i ^ byte_4050[v23];
            v16 = i ^ byte_4050[v16];
            v17 = i ^ byte_4050[v24];
            v18 = i ^ byte_4050[v18];
            v19 = i ^ byte_4050[v25];
            v20 = i ^ byte_4050[v26];
          }
          if ( v13 != byte_2010[v12]
            || v14 != byte_2010[v12 + 1]
            || v15 != byte_2010[v12 + 2]
            || v16 != byte_2010[v12 + 3]
            || v17 != byte_2010[v12 + 4]
            || v18 != byte_2010[v12 + 5]
            || v19 != byte_2010[v12 + 6]
            || v20 != byte_2010[v12 + 7] )
          {
            break;
          }
          v12 += 8LL;
          if ( v12 >= 0x38 )
          {
            puts("Correct flag methinks.");
            exit(0);
          }
        }
      }
      puts("Wronk flag methinks.");
      exit(1);
    }
  }
}
```

From the decompiled code, it suggest that it uses C++ to compile and it takes string as input and returns `Correct flag methinks` if is correct or `Wronk flag methinks` if is wrong. 


##### 3. Reverse string verification function

```cpp
std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v27, (unsigned int)v5);
```

At this part, it will reads input and the value of string input is holded by `v27` (we can rename this variable in IDA for more readability)

```cpp
v6 = 8;
if ( (v28 & 7) != 0 )
    v6 = 8 - (v28 & 7);
```
After the input is entered, it apply 8 bytes of padding. Next, it will perform byte-wise transformation and XORing with `byte_4050`. 

```cpp
for ( i = 0; i != 4096; ++i )
{
    v22 = v13;
    v23 = v20;
    v24 = v14;
    v25 = v15;
    v26 = v17;
    v13 = i ^ byte_4050[v19];
    v14 = i ^ byte_4050[v22];
    v15 = i ^ byte_4050[v23];
    v16 = i ^ byte_4050[v16];
    v17 = i ^ byte_4050[v24];
    v18 = i ^ byte_4050[v18];
    v19 = i ^ byte_4050[v25];
    v20 = i ^ byte_4050[v26];
}
```

This loop runs for 4096 times with iterating over 8-byte blocks of data. Then, XORing with the values from `byte_4050`. 

```cpp
if ( v13 != byte_2010[v12]
     || v14 != byte_2010[v12 + 1]
     || v15 != byte_2010[v12 + 2]
     || v16 != byte_2010[v12 + 3]
     || v17 != byte_2010[v12 + 4]
     || v18 != byte_2010[v12 + 5]
     || v19 != byte_2010[v12 + 6]
     || v20 != byte_2010[v12 + 7] )
```

After transformation proces, the bytes are checked against a predefined array byte `byte_2010`. If any of the values do not match, the process breaks.


##### 3. Reversing the function checking algorithm
In order to reverse it, we need to carefully handle the bytes as it requires byte padding and handle by 8-byte of chunks. So here is the process and flow:

- `byte_4050[]`: XOR key for transformation
- `byte_2010[]`: Stores expected final values for verification
- XORing backward from `byte_2010[]` using `byte_4050[]` with 4096 times per chunks
- Decode hex to string

```go
package main

import (
	"fmt"
)

func main() {
	encryptedData := []byte{
		22, 45, 121, 202, 86, 198, 101, 233, 233, 22, 102, 35, 9, 45, 27, 9,
		28, 9, 198, 28, 31, 173, 233, 218, 160, 198, 26, 102, 9, 173, 129, 28,
		128, 57, 160, 33, 9, 101, 45, 48, 246, 87, 246, 162, 101, 101, 33, 162,
		120, 120, 120, 120, 120, 120, 120, 120,
	}

	data4050 := []byte{
		99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
		202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
		183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
		4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
		9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
		83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
		208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
		81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
		205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
		96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
		224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
		231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
		186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
		112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
		225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
		140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
	}

	inverseData4050 := make([]byte, 256)
	for i, val := range data4050 {
		inverseData4050[val] = byte(i)
	}
	reverseTransformation := func(chunk []byte) []byte {
		currentState := make([]byte, 8)
		copy(currentState, chunk)
		for i := 4095; i >= 0; i-- {
			r14 := currentState[0]
			r10 := currentState[1]
			r8 := currentState[2]
			rbx := currentState[3]
			rdi := currentState[4]
			r9 := currentState[5]
			r15 := currentState[6]
			rbp := currentState[7]
			oldR15 := inverseData4050[byte((int(r14)^i)%256)]
			oldR14 := inverseData4050[byte((int(r10)^i)%256)]
			oldRbp := inverseData4050[byte((int(r8)^i)%256)]
			oldRbx := inverseData4050[byte((int(rbx)^i)%256)]
			oldRdi := inverseData4050[byte((int(rbp)^i)%256)]
			oldR10 := inverseData4050[byte((int(rdi)^i)%256)]
			oldR8 := inverseData4050[byte((int(r15)^i)%256)]
			oldR9 := inverseData4050[byte((int(r9)^i)%256)]
			currentState = []byte{
				oldR14,
				oldR10,
				oldR8,
				oldRbx,
				oldRdi,
				oldR9,
				oldR15,
				oldRbp,
			}
		}
		return currentState
	}
	var chunks [][]byte
	for i := 0; i < len(encryptedData); i += 8 {
		end := i + 8
		if end > len(encryptedData) {
			end = len(encryptedData)
		}
		chunks = append(chunks, encryptedData[i:end])
	}
	var flag []byte
	for _, chunk := range chunks {
		reversedChunk := reverseTransformation(chunk)
		flag = append(flag, reversedChunk...)
	}
	flagStr := string(flag)
	fmt.Println("Flag:", flagStr)
}
```
Here is decryption code in golang. 

**Flag:** `x3c{pwndbg_and_pwntools_my_belowed_573498532832}`
