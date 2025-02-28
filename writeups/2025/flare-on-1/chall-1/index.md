---
title: Bob Doge
layout: default
---

# Challenge 1: Bob Doge

Executing the challenge binary will open a GUI application with Bob Ross image and with a `DECODE !` button. 

![[Pasted image 20250228093056.png]]

After pressing the decode button, it showed this:

![[Pasted image 20250228093230.png]]

### Solution:
##### 1. Use Detect-It-Easy and CFF Explorer gather information
![[Pasted image 20250228093540.png]]

From here, the executable is compiled with .NET assembly. Next, we can use dnSpy to decompiled the executable and look through the functions used. 

##### 2. Use dnSpy to identify function that encode string when click
After opening it with dnSpy, we able to a function `btnDecode_Click` under Form1 classes and also `dat_secret` under resources section. 

Here is the function of `btnDecode_Click`: 

```c#
// XXXXXXXXXXXXXXX.Form1
// Token: 0x06000002 RID: 2 RVA: 0x00002060 File Offset: 0x00000260
private void btnDecode_Click(object sender, EventArgs e)
{
	this.pbRoge.Image = Resources.bob_roge;
	byte[] dat_secret = Resources.dat_secret;
	string text = "";
	foreach (byte b in dat_secret)
	{
		text += (char)(((b >> 4) | (((int)b << 4) & 240)) ^ 41);
	}
	text += "\0";
	string text2 = "";
	for (int j = 0; j < text.Length; j += 2)
	{
		text2 += text[j + 1];
		text2 += text[j];
	}
	string text3 = "";
	for (int k = 0; k < text2.Length; k++)
	{
		char c = text2[k];
		text3 += (char)((byte)text2[k] ^ 102);
	}
	this.lbl_title.Text = text3;
}

```

This function is triggered by clicking the `Decode !` button, which it will encode a hidden message stored in `Resources.dat_Secret`. It first modifies each byte by swapping its nibbles and XORing with `41` with appending a null terminator. Next, it swaps adjacent characters in the resulting string. Finally, it XORs each characters with `102` to produce the encoded text. 

##### Script to decode the dat_secret 

Here is the steps to decode `dat_secret`:
- Swapping bytes and XORing with 41 for `dat_secret`
- Swap adjacent characters in the resulting string
- XORing each characters with 102 to get the final decoded output

```go 
package main

import (
    "fmt"
)

func main() {
    datSecret := []byte{0xA1, 0xB5, 0x44, 0x84, 0x14, 0xE4, 0xA1, 0xB5, 0xD4, 0x70, 0xB4, 0x91, 0xB4, 0x70, 0xD4, 0x91, 0xE4, 0xC4, 0x96, 0xF4, 0x54, 0x84, 0x4B, 0x5C, 0x44, 0x06, 0x47, 0x47, 0x0A, 0x46, 0x44}
    
    // Step 1: Transform each byte
    text := ""
    for _, b := range datSecret {
        transformed := ((b >> 4) | ((b << 4) & 0xF0)) ^ 41
        text += string(transformed)
    }
    text += "\x00"
    fmt.Println("Text 1:", text)
    
    // Step 2: Swap adjacent characters
    text2 := ""
    for j := 0; j < len(text); j += 2 {
        if j+1 < len(text) {
            text2 += string(text[j+1]) + string(text[j])
        } else {
            // Handle odd length (though with null terminator, length should be even)
            text2 += string(text[j])
        }
    }
    fmt.Println("Text 2:", text2)
    
    // Step 3: XOR each byte with 102
    text3 := ""
    for i := 0; i < len(text2); i++ {
        text3 += string(text2[i] ^ 102)
    }
    fmt.Println("Final result:", text3)
}
```

The output: 
```bash
$ go run solve.go 
Text 1: 3rmahg3rd.b0b.d0ge@flaìmI]]Mm
Text 2: r3amghr3.d0b.b0degf@alÂ¬ÃIm]]ÂmM
Final result: U
               UHVHV&
¤û¥ä¤Ê¥å/
         ;;¤ï¥ä
               +f
```

I may have messed up some byte padding but the flag of Flare-On challenge always ended like an email address with `@flare-on.com`. We are close enough to identify the flag. 

**Flag:** `3rmahg3rd.b0b.d0ge@flare-on.com`

