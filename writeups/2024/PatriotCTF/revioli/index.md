---
title: Revioli, Revioli, give me the formeoli
layout: default
---

# Revioli, Revioli, give me the formeoli	

### Description:

Can you unlock the secret formula?

- Challenge File: revioli

Solutions from: 0x251e, @Monsieur Thomas, @Muthra

### Solution 1:

#### 1. Use `ltrace` to get the flag in clear text as an argument of `strcmp()` function

```bash
ltrace ./revioli
snprintf("0", 20, "%llu", 0) = 1
strcat("", "0") = "0"
snprintf("1", 20, "%llu", 1) = 1
strcat("0", "1") = "01"
snprintf("1", 20, "%llu", 1) = 1
strcat("01", "1") = "011"
snprintf("2", 20, "%llu", 2) = 1
strcat("011", "2") = "0112"
snprintf("3", 20, "%llu", 3) = 1
strcat("0112", "3") = "01123"
snprintf("5", 20, "%llu", 5) = 1
strcat("01123", "5") = "011235"
...
```

### Solution 3:

With IDA, disassemble the program to view the pseudocode of the main function:

#### Main function:

```c
int __fastcall main(int argc, const char **argv, const char **envp) {
  char s[256]; // [rsp+0h] [rbp-310h] BYREF
  char s2[256]; // [rsp+100h] [rbp-210h] BYREF
  char v6[264]; // [rsp+200h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+308h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  gen_correct_flag(s2, argv, envp); // gen_correct_flag function
  assemble_flag(s2, v6);            // assemble_flag function
  printf("Enter-a the password-a: ");
  fgets(s, 256, _bss_start);
  s[strcspn(s, "\n")] = 0; // compare input
  if (!strcmp(s, s2))
    printf("Congratulations! The flag is: %s\n", v6);
  else
    puts("No toucha my spaget!");
  return 0;
}
```

#### `gen_correct_flag` function:

```c
v38 = __readfsqword(0x28u);
for (i = 0; i <= 14; ++i)
  v4[i] = calc((unsigned int)i);  // calc function
*(_QWORD *)dest = 0LL;

for (j = 0; j <= 14; ++j) {
  snprintf(s, 0x14uLL, "%llu", v4[j]);
  strcat(dest, s);
}
snprintf(a1, 0x100uLL, "ITALY_%s", dest); // append input with ITALY_
return v38 - __readfsqword(0x28u);
```

#### `calc` function:

```c
if (!a1)      // base case
  return 0LL;
if (a1 == 1)
  return 1LL;  // base case
v3 = 0LL;
v4 = 1LL;
for (i = 2; i <= a1; ++i) {  // recursive case
  v5 = v3 + v4;   // Fibonacci 
  v3 = v4;
  v4 = v5;
}
return v4;
```

So, we need to calculate the Fibonacci sequence from 0 to 14 and append it with "ITALY_". This will return the flag.

#### Python Solution:

```python
a, b = 0, 1
fibb = str(a)
for _ in range(14):
    fibb += str(b)
    a, b = b, a + b
print(fibb)
```

```bash
./revioli
Enter-a the password-a: ITALY_01123581321345589144233377
Congratulations! The flag is: PCTF{ITALY_01123581321345589144233377}
```

**Flag:** `PCTF{out_0f_0ffic3_out_0f_M1nd}`
