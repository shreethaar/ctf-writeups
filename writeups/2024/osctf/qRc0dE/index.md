### Category: Forensic
### Description: This is a QRCODE, but I can not scan it, whyyyyy????
### Author: @Deit
### Challenge File:

![](./342657695-a44bb302-4a00-4667-ae22-d6c1919992fc%20(1).jpg)

**Reference:** <a href="https://github.com/pwning/public-writeup/blob/master/mma2015/misc400-qr/writeup.md">https://github.com/pwning/public-writeup/blob/master/mma2015/misc400-qr/writeup.md</a>.

1. Based on the reference, I use GIMP to cut the top right (clear) alignment pattern set of the QR code and replace with the left top (marked with red)
2. Using highlight and contrast to reduce the red marked pixels. Repeat the process until the Version Info, Format Info and Timing Info of the QR code is clear off the red marked pixels.
3. Referring to the guide, replace the clear pixels of Version Info and Format Info with black. 
Outcome:

![](./Pasted%20image%2020240714020154.png)

4. <a href="https://merri.cx/qrazybox/">qrazybox</a> to extract the QR code Information using the tools (tired mobile scanning & zbarimg doesn't work)
   
![](./Pasted%20image%2020240714021106.png)

5. After extracting the information, you will received the flag string. 

![](./2024-07-13-061137_hyprshot.png)

Flag: **OSCTF{r3c0v3R_qR_C0de_1s_s0_fUn}**, i might damage some bits while recovering it, so manage to get back the correct flag string with assumptions.
