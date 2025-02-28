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
