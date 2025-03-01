---
title: Challenge 2
layout: default
---
# Challenge 2

Challenge File: very_success.exe

### Solution:
##### 1. Analyze with Detect-It-Easy
Here is the output from Detect-It-Easy, it is the same as first challenge
![[ctf-writeups/writeups/2025/flare-on-2/chall-2/flareon2-3.png]]

##### 2. Decompile it using IDA
At the function list, there are only two user-defined function:
![[flareon2-4.png]]
`sub_401000` is most likely the "main function" and then it will use `sub_401084` to process arguments passed in the previous function. 

##### 3. Analyzing the sub_401084 function
Here is the assembly code:
```nasm
sub_401084      proc near

var_C           = byte ptr -0Ch
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

push    ebp
mov     ebp, esp
sub     esp, 0
push    edi
push    esi
xor     ebx, ebx
mov     ecx, 25h ; '%'
cmp     [ebp+arg_8], ecx

loc_401096:
jl      short loc_4010D7
mov     esi, [ebp+arg_4]
mov     edi, [ebp+arg_0]
lea     edi, [edi+ecx-1]

loc_4010A2:
mov     dx, bx
and     dx, 3
mov     ax, 1C7h
push    eax
sahf
lodsb
pushf
xor     al, [esp+10h+var_C]
xchg    cl, dl
rol     ah, cl
popf
adc     al, ah
xchg    cl, dl
xor     edx, edx
and     eax, 0FFh
add     bx, ax
scasb
cmovnz  cx, dx
pop     eax
jecxz   short loc_4010D7
sub     edi, 2
loop    loc_4010A2
jmp     short loc_4010D9

loc_4010D7:
; (additional logic may follow)

sub_401084      endp
```

At `loc_401096`, it loads the arguments into ESI (our input) and EDI (check against). To take closer attention at `lea edi, [edi+ecx-1]`, it basically loading the value from the end of the array bytes. Here is an illustration for better understanding:
```
EDI: "EXAMPLESTRING"
LEA edi, [edi+ecx-1]: "GNIRTSELPMAXE"  //reversed
```

After that, at `loc_4010A2`, it processes each input by byte and applies XOR, rotation and addition with loop. Here is a simplified pseudocode:
```
al ^= *(esp + 0x10 - 0xC);
swap(cl, dl);
ah = rol(ah, cl);
al += ah;
swap(cl, dl);
```

##### Use x32dbg to debug
In order to find out the value of EDI, we need to check the memory dump after hitting the breakpoint at `mov edi, [ebp+arg_0]`. In order to have the code execute at that address, we have to make sure our input string contains 37 characters. Here is the test strings used: `ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!`

![[flareon2-5.png]]

Here is the hex array bytes, we have to used this to craft our reverse script. In order to make the reverse script solution, here are the considerations:
- Read EDI backwards
- Rotate left per byte from DX 
- XOR with `0xC7` (Explaination of the XOR key will continue)
- AND 3 for lower 2 bits

The reason why we use the XOR key is because at `xor al, [esp+10h+var_C]`in the debugger showed this:
![[flareon2-6.png]]

With all information required, we can generate the script. Here is it:
```go 
package main

import (
	"fmt"
)

// Rotate left implementation (circular left shift)
func rol(b byte, count byte) byte {
	return byte((uint(b) << count) | (uint(b) >> (8 - count)) & 0xFF)
}

func main() {
	// Target buffer (in memory)
	email := []byte{
		0xAF, 0xAA, 0xAD, 0xEB, 0xAE, 0xAA, 0xEC, 0xA4,
		0xBA, 0xAF, 0xAE, 0xAA, 0x8A, 0xC0, 0xA7, 0xB0,
		0xBC, 0x9A, 0xBA, 0xA5, 0xA5, 0xBA, 0xAF, 0xB8,
		0x9D, 0xB8, 0xF9, 0xAE, 0x9D, 0xAB, 0xB4, 0xBC,
		0xB6, 0xB3, 0x90, 0x9A, 0xA8,
	}

	// Reverse the buffer (since original code processes it backward)
	for i, j := 0, len(email)-1; i < j; i, j = i+1, j-1 {
		email[i], email[j] = email[j], email[i]
	}

	// Initialize registers
	var AH, AL byte
	var BX, DX uint16
	var result []byte

	// Process each byte
	for i := 0; i < len(email); i++ {
		// Rotate left AH by DX bits
		AH = rol(1, byte(DX))

		// Reverse the transformation:
		// In forward: AL = input[i] XOR 0xC7, then AL = AL + AH (with carry)
		// In reverse: input[i] = (target - AH - 1) XOR 0xC7
		AL = (email[i] - AH - 1) ^ 0xC7

		// Update accumulator BX
		BX = BX + uint16(email[i])

		// Calculate new DX (lower 2 bits of BX)
		DX = BX & 3

		// Add the calculated original input byte to our result
		result = append(result, AL)
	}

	// Print the result as string
	fmt.Println(string(result))

	// Print the result as hex values
	fmt.Print("Hex: ")
	for _, b := range result {
		fmt.Printf("%02X ", b)
	}
	fmt.Println()

	// Verify our solution by encoding it back
	verified := verifyResult(result)
	fmt.Println("Verification matches target:", compareBuffers(verified, reverseBuffer(email)))
}

// Forward transform to verify our solution
func verifyResult(input []byte) []byte {
	var BX, DX uint16
	var AH, AL byte
	result := make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		// Get lower 2 bits of BX
		DX = BX & 3

		// Calculate AH by rotating 1 left by DX bits
		AH = rol(1, byte(DX))

		// XOR input with 0xC7
		AL = input[i] ^ 0xC7

		// Add AH to AL (with carry)
		AL = AL + AH

		// Update BX
		BX = BX + uint16(AL)

		// Store in result
		result[i] = AL
	}

	return result
}

// Helper function to reverse a buffer
func reverseBuffer(buf []byte) []byte {
	result := make([]byte, len(buf))
	copy(result, buf)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// Helper function to compare two buffers
func compareBuffers(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

**Flag:** `a_Little_b1t_harder_plez@flare-on.com`
