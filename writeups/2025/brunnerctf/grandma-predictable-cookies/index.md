# Grandma's Predictable Cookie

- Category: reverse
- Difficulty: easy-medium
- Author: H4N5

Grandma encrypted her secret cookie recipe using her "special ingredient" a random number generator seeded with the exact time she baked it.

She thought it was uncrackable. But little did she know: Using the same oven clock every time makes your cookies easy to reverse-engineer.

Can you recover her delicious secret?

### Solution:

1. Pre-analysis of binary 

```
$ file brunner 
brunner: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5921cf888d3426176894905d8f1a04fda5f8f451, for GNU/Linux 3.2.0, with debug_info, not stripped
```

The binary is zipped together with a flag.enc and flag.txt. The flag.txt containing string value of `brunner{REDACTED}` as a placeholder and flag.enc contain two value of encrypted flag in hex and encryption time. 


2. Analyze the decompiled main function of the binary

```c 
00401287    int32_t main(int32_t argc, char** argv, char** envp)

00401287    {
00401287        FILE* fp = fopen("flag.txt", "rb");
00401287        
004012b1        if (!fp)
004012b1        {
004012e2            perror("Error opening flag.txt");
004012bd            return 1;
004012b1        }
004012b1        
004012e2        char buf[0x104];
004012e2        uint64_t rax_1 = fread(&buf, 1, 0xff, fp);
004012f2        fclose(fp);
00401305        buf[rax_1] = 0;
0040130d        time_t rax_6 = get_current_time_danish();
00401349        srand((uint32_t)rax_6);
00401349        
00401367        for (int32_t i = 0; i <= 0x3e7; i += 1)
00401367            rand();
00401367        
00401374        int64_t var_58_1 = rax_1 - 1;
00401395        void* rsp_1 = &buf - COMBINE(0, rax_1 + 0xf) / 0x10 * 0x10;
00401395        
004013f4        for (void* i_1 = nullptr; i_1 < rax_1; i_1 += 1)
004013f4        {
004013f4            int32_t rax_19 = rand();
004013e5            *(uint8_t*)((char*)i_1 + rsp_1) =
004013e5                *(uint8_t*)((char*)i_1 + &buf) ^ (uint8_t)rax_19;
004013f4        }
004013f4        
00401400        printf("Encrypted flag: ");
00401400        
0040143e        for (void* i_2 = nullptr; i_2 < rax_1; i_2 += 1)
0040143e            printf("%02x", (uint64_t)*(uint8_t*)((char*)i_2 + rsp_1));
0040143e        
0040144f        printf("\nEncryption time (approx): %ld\n", 
0040144f            (uint64_t)((int32_t)(rax_6 / 0x2710) * 0x2710));
00401454        return 0;
00401287    }
```
From the main function code analysis, the binary implements a simple XOR encryption with a time-based seed.

- Open flag.txt and reads the contents
- Uses `get_current_time_danish()` function to get current time in Europe/Copenhagen timezone
- Creates approximate time (`appprox = 10000 * seed_time/10000`)
- Uses the exact timestamp as seed for `srand()`
- Calls `rand()` 1000 times to advance the generator 
- XOR each flag byte with a random value from the seeded generator 

THe key vulnerability is the binary reveals the approximate encryption time, we able to bruteforce this. 


3. Generate bruteforce script 
Here is the bruteforce script to attack time-based encryption

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Function to set timezone to Danish time (same as original)
time_t get_current_time_danish() {
    char *old_tz = getenv("TZ");
    setenv("TZ", "Europe/Copenhagen", 1);
    tzset();
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    time_t result = mktime(t);
    
    if (old_tz) {
        setenv("TZ", old_tz, 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
    
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <encrypted_flag_hex> <approx_time>\n", argv[0]);
        printf("Example: %s 41424344... 1640000000\n", argv[0]);
        return 1;
    }
    
    char *hex_string = argv[1];
    long approx_time = atol(argv[2]);
    
    // Convert hex string to bytes
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0) {
        printf("Error: Hex string must have even length\n");
        return 1;
    }
    
    size_t len = hex_len / 2;
    unsigned char *encrypted = malloc(len);
    
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex_string + 2*i, "%2hhx", &encrypted[i]) != 1) {
            printf("Error: Invalid hex character at position %ld\n", i*2);
            free(encrypted);
            return 1;
        }
    }
    
    printf("Trying to decrypt %ld bytes with approximate time %ld\n", len, approx_time);
    
    // The original code uses: approx = 10000 * (seed_time / 10000);
    // This rounds down to nearest 10000, so we need to try the full range
    long base_time = 10000 * (approx_time / 10000);
    
    printf("Searching from %ld to %ld (range of 10000)\n", base_time, base_time + 9999);
    
    // Try all possible seeds in the 10000-second window
    for (long candidate_seed = base_time; candidate_seed <= base_time + 9999; candidate_seed++) {
        srand(candidate_seed);
        
        // Advance rand() exactly 1000 times as in original
        for (int i = 0; i < 1000; i++) {
            rand();
        }
        
        // Decrypt
        unsigned char *decrypted = malloc(len + 1);
        int looks_good = 1;
        
        for (size_t i = 0; i < len; i++) {
            int rand_val = rand();
            // The original XOR operation is: flag[i] ^ rand_val
            // So to decrypt: encrypted[i] ^ rand_val
            decrypted[i] = encrypted[i] ^ (rand_val & 0xFF);
            
            // Basic printability check
            if (decrypted[i] < 32 || decrypted[i] > 126) {
                if (decrypted[i] != '\n' && decrypted[i] != '\r' && decrypted[i] != '\t') {
                    looks_good = 0;
                    break;
                }
            }
        }
        
        if (looks_good) {
            decrypted[len] = '\0';
            
            // Print any potentially valid result
            printf("Seed %ld produces: ", candidate_seed);
            for (size_t i = 0; i < len; i++) {
                if (decrypted[i] >= 32 && decrypted[i] <= 126) {
                    printf("%c", decrypted[i]);
                } else {
                    printf("\\x%02x", decrypted[i]);
                }
            }
            printf("\n");
            
            // Check for common flag patterns
            char *flag_str = (char *)decrypted;
            if (strstr(flag_str, "flag{") || strstr(flag_str, "FLAG{") ||
                strstr(flag_str, "CTF{") || strstr(flag_str, "ctf{") ||
                (len >= 5 && strncmp(flag_str, "flag{", 5) == 0)) {
                printf("*** FOUND FLAG with seed %ld: %s ***\n", candidate_seed, flag_str);
            }
        }
        
        free(decrypted);
        
        // Progress indicator
        if ((candidate_seed - base_time) % 1000 == 0) {
            printf("Progress: %ld/%ld\n", candidate_seed - base_time, 9999L);
        }
    }
    
    printf("Search completed.\n");
    free(encrypted);
    return 0;
}
```

4. Run the bruteforce script with flag.enc values

```
$ ./a.out 3ec63cc41f1ac1980651726ab3ce2948882b879c19671269963e39103c83ebd6ef173d60c76ee5 1755860000
Trying to decrypt 39 bytes with approximate time 1755860000
Searching from 1755860000 to 1755869999 (range of 10000)
Progress: 0/9999
Progress: 1000/9999
Progress: 2000/9999
Progress: 3000/9999
Seed 1755864000 produces: brunner{t1me_wr4p_prng_1s_pred1ct4ble}\x0a
Progress: 4000/9999
Progress: 5000/9999
Progress: 6000/9999
Progress: 7000/9999
Progress: 8000/9999
Progress: 9000/9999
Search completed.
```

**Flag:** `brunner{t1me_wr4p_prng_1s_pred1ct4ble}`
