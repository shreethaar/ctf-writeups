---
title: challenge006
layout: default
---

# challenge006

Description: 
Apparently the flag I received this file from Elliot contains a flag. But the file seems to be corrupted, help me fix it and find the flag! Hints ● Have you tried opening the file in a hex editor? ● Read up on file signatures for image files. ● Inspect the 1st 4 bytes of the file - D8 FF E0 FF

### Solution:

1. Used ghex hex editor, manipulate the first 4 bytes the file, from D8 FF E0 FF -> FF D8 FF E0 (JPG File Header Signature)

**Flag:** `isfcr{h34d3r_c0rr3c710n_f7w}`


