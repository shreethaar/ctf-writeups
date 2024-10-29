---
title: Base64by32
layout: default
---

# Base64by32

This is a dumb challenge. I'm sorry.

- Category: scripting
- Challenge file: base64by32.zip

### Solutions

##### 1. Analyze the file 

Use `file` and `wc -l` to get some information of the file, based on the challenge name, it is clear that the flag string is base64 32 times, which appear to be a super long string where Python does not have the capability to store it as string value.

```bash
$ file base64by32
base64by32: ASCII text

$ wc -l base64by32
8524 base64by32
```

##### 2. Chuck it to bash script 

I used claude, I named her Claudia (treat your AI as your friend) to create the bash script so it can have some error handling as it has to digest long string before it goes kaput

```bash
#!/bin/bash

# Check if input file is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <input_file>"
    echo "This script decodes base64-encoded content 32 times"
    exit 1
fi

input_file="$1"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' does not exist"
    exit 1
fi

# Check if input file is readable
if [ ! -r "$input_file" ]; then
    echo "Error: Cannot read input file '$input_file'"
    exit 1
fi

# Create a temporary file to store intermediate results
temp_file=$(mktemp)
trap 'rm -f $temp_file' EXIT

# Copy initial content to temp file
cp "$input_file" "$temp_file"

# Perform base64 decoding 32 times
for ((i=1; i<=32; i++)); do
    echo "Performing decode iteration $i..."
    
    # Try to decode and save to a new temp file
    if ! base64 -d "$temp_file" > "$temp_file.new" 2>/dev/null; then
        echo "Error: Failed at iteration $i - content might not be base64 encoded"
        exit 1
    fi
    
    # Move new file to original temp file
    mv "$temp_file.new" "$temp_file"
    
    # Optional: Display first few characters of current result
    echo "Current result (first 50 chars):"
    head -c 50 "$temp_file" | tr -cd '[:print:]\n'
    echo
done

# Save final result to output file
output_file="decoded_output.txt"
mv "$temp_file" "$output_file"

echo "Decoding complete! Result saved to $output_file"
# Powered by Claudia
```

Her code is just so efficient, the output:

```bash
$ ./base64by32.sh base64by32
Performing decode iteration 1...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 2...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 3...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 4...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 5...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 6...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 7...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 8...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 9...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 10...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 11...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 12...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 13...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 14...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 15...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVj
Performing decode iteration 16...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTV0
Performing decode iteration 17...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSWFJteFZVMjA1Vj
Performing decode iteration 18...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4V1YwZDRXRmxVU205V01WbDNXa2M1Vj
Performing decode iteration 19...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxWV0d4WFlUSm9WMVl3Wkc5V2JHeDBaVVYwVj
Performing decode iteration 20...
Current result (first 50 chars):
Vm0wd2QyUXlVWGxXYTJoV1YwZG9WbGx0ZUV0V01WbDNXa1JTV0
Performing decode iteration 21...
Current result (first 50 chars):
Vm0wd2QyUXlWa2hWV0doVllteEtWMVl3WkRSWFJteFZVbTVrVm
Performing decode iteration 22...
Current result (first 50 chars):
Vm0wd2QyVkhVWGhVYmxKV1YwZDRXRmxVUm5kVlJscHpXa2M1Vj
Performing decode iteration 23...
Current result (first 50 chars):
Vm0wd2VHUXhUblJWV0d4WFlURndVRlpzWkc5V1JteFZVMnhPYW
Performing decode iteration 24...
Current result (first 50 chars):
Vm0weGQxTnRVWGxXYTFwUFZsZG9WRmxVU2xOalJsSlZWR3RPYW
Performing decode iteration 25...
Current result (first 50 chars):
Vm0xd1NtUXlWa1pPVldoVFlUSlNjRlJVVGtOalZuQllaVVYwV2
Performing decode iteration 26...
Current result (first 50 chars):
Vm1wSmQyVkZOVWhTYTJScFRUTkNjVnBYZUV0WlZteFlZek5rVG
Performing decode iteration 27...
Current result (first 50 chars):
VmpJd2VFNUhSa2RpTTNCcVpXeEtZVmxYYzNkTlZsRjNWV3RPYV
Performing decode iteration 28...
Current result (first 50 chars):
VjIweE5HRkdiM3BqZWxKYVlXc3dNVlF3VWtOaVZUQjVWVmh3VG
Performing decode iteration 29...
Current result (first 50 chars):
V20xNGFGb3pjelJaYWswMVQwUkNiVTB5VVhwTk1sbDVXVmRSZV
Performing decode iteration 30...
Current result (first 50 chars):
Wm14aFozczRZak01T0RCbU0yUXpNMll5WVdReVpqVXpNV1kxTX
Performing decode iteration 31...
Current result (first 50 chars):
ZmxhZ3s4YjM5ODBmM2QzM2YyYWQyZjUzMWY1MzY1ZDBlMzk3MH
Performing decode iteration 32...
Current result (first 50 chars):
flag{8b3980f3d33f2ad2f531f5365d0e3970}
```

**Flag:** `flag{8b3980f3d33f2ad2f531f5365d0e3970}`


### Lesson Learned (I took granted of base64 command):

This is what happens when we run `$ base64 -d file.txt`:

**Bash:**
1. It parses the command
2. Use fork() -> syscall to create new process
3. Use exec() -> syscall to run base64 (compiled c program, thanks to Linus Torvalds)

**base64 C program:**
1. Opens the input file (with open() syscall)
2. Reads the contents from file (with read() syscall)
3. Decodes in userspace
4. Writes output (with write() syscall)


