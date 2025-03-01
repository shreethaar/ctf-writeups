---
title: Significance of Reversing
layout: default
---
# Significance of Reversing

Over the years, we hackers have been reversing stuff, thinking we understand how everything works and feel good about it. But, sometimes it feels like do we really understand what reversing means in mordern days? Anyways, here's a PNG, let's see if you can reverse your way out of this one.

- Category: Rev
- Challenge file: Reverseme.png

### Solution:
##### 1. Analyze the file with file command and its hex data 
```
$ file Reverseme.png 
Reverseme.png: data

$ xxd Reverseme.png | head
00000000: 8950 4e47 0d0a 1a0a 0000 0000 0000 0000  .PNG............
00000010: 0000 0000 0100 0000 0000 0000 0000 0000  ................
00000020: 0000 0001 1a00 0000 0000 0035 9b00 0000  ...........5....
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0300 0000 1100 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0100 0000 0000 0000 0000 0000  ................
00000060: 0000 0001 eb00 0000 0000 0033 b000 0000  ...........3....

$ xxd Reverseme.png | tail
00003de0: 0000 0000 1c00 0000 0000 0003 1800 0000  ................
00003df0: 0000 0003 1800 0000 0000 0003 1800 0000  ................
00003e00: 0400 0000 0300 0000 0000 0000 0800 0000  ................
00003e10: 0000 0002 d800 0000 0000 0002 d800 0000  ................
00003e20: 0000 0000 4000 0000 0000 0000 4000 0000  ....@.......@...
00003e30: 0000 0000 4000 0000 0400 0000 0600 1e00  ....@...........
00003e40: 1f00 4000 0d00 3800 4000 0000 0000 0000  ..@...8.@.......
00003e50: 0000 0036 b800 0000 0000 0000 4000 0000  ...6........@...
00003e60: 0000 0010 5000 0000 0100 3e00 0300 0000  ....P.....>.....
00003e70: 0000 0000 0000 0101 0246 4c45 7f         .........FLE.
```

The challenge file appears to be a malformed or corrupted PNG image (only with the header), also with missing critical PNG chunks. However, at the of the hex dump, there is `FLE`, reverse of `ELF` which is the correct header for ELF binary. Now we have to reverse the bytes arrangement.

##### 2. Reverse the hex bytes of ELF
Here is the script to reverse the hex bytes arrangement:
```go
package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func reverseFile(inputFile, outputFile string) {
	// Read the input file
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Reverse the data
	reversed := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		reversed[i] = data[len(data)-1-i]
	}

	// Write to output file
	err = ioutil.WriteFile(outputFile, reversed, 0644)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully reversed '%s' and saved as '%s'\n", inputFile, outputFile)
}

func main() {
	inputFile := "Reverseme.png"
	outputFile := "reverse"

	// Check for command line arguments
	args := os.Args
	if len(args) > 2 {
		inputFile = args[1]
		outputFile = args[2]
	}

	reverseFile(inputFile, outputFile)
}
```

Here is the output:
```sh
$ ./reverse

Decrypted string: ACECTF{w3_74lk_4b0u7_r3v3r53}
```

**Flag:** `ACECTF{w3_74lk_4b0u7_r3v3r53}`


