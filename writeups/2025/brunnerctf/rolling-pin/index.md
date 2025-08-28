# Rolling Pin 

- Category: reverse
- Difficulty: beginner 
- Author: rvsmvs

The head baker's gone rogue and locked up the recipe for the perfect pastry swirl inside a secret code. Can you knead your way through layers of fluffy obfuscation and figure out the exact mix of bytes to make it rise just right?

# Solution:

To solve this challenge, we need to reverse the encryption process:
- forward operation: `rotl(input[i], i & 7) == baked[i]`
- reverse operation: `input[i] = rotr(baked[i], i & 7)`
- decypt each byte in the `baked` array

```c 

#include <stdio.h>
#include <stdint.h>

// The encrypted data from the binary
const uint8_t baked[25] = {
    98, 228, 213, 115, 230, 172, 156, 189, 114, 96, 209, 161, 71, 102, 215,
    58, 104, 102, 125, 35, 3, 174, 217, 52, 125
};

// Forward rotation function (same as in original)
uint8_t rotl(uint8_t x, int k) {
    return (x << k) | ((int)x >> (8 - k));
}

// Reverse rotation function (right rotate)
uint8_t rotr(uint8_t x, int k) {
    return (x >> k) | (x << (8 - k));
}

int main() {
    char flag[26];
    
    printf("Encrypted bytes: ");
    for (int i = 0; i < 25; i++) {
        printf("%d ", baked[i]);
    }
    printf("\n\n");
    
    printf("Decrypting...\n");
    
    // Decrypt each byte
    for (int i = 0; i < 25; i++) {
        // The original does: rotl(input[i], i & 7) == baked[i]
        // So to reverse: input[i] = rotr(baked[i], i & 7)
        int shift = i & 7;  // Same as i % 8
        flag[i] = rotr(baked[i], shift);
        
        printf("Position %d: encrypted=0x%02x (%d), shift=%d, decrypted=0x%02x ('%c')\n", 
               i, baked[i], baked[i], shift, (uint8_t)flag[i], 
               (flag[i] >= 32 && flag[i] <= 126) ? flag[i] : '?');
    }
    
    flag[25] = '\0';  // Null terminate
    
    printf("\nDecrypted flag: %s\n", flag);
    
    // Verify our solution by encrypting it back
    printf("\nVerification (re-encrypting):\n");
    int correct = 1;
    for (int i = 0; i < 25; i++) {
        uint8_t re_encrypted = rotl((uint8_t)flag[i], i & 7);
        printf("Position %d: original=0x%02x, re-encrypted=0x%02x %s\n", 
               i, baked[i], re_encrypted, (re_encrypted == baked[i]) ? "✓" : "✗");
        if (re_encrypted != baked[i]) {
            correct = 0;
        }
    }
    
    if (correct) {
        printf("\n✓ Verification successful! The decrypted flag is correct.\n");
    } else {
        printf("\n✗ Verification failed! Check the decryption logic.\n");
    }
    
    return 0;
}
```

**Flag:** `brunner{r0t4t3_th3_d0ugh}`
