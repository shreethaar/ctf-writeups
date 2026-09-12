# etch-a-sketch

- Category: rev

"I drew you a picture, hope you like it <3"

The picture the binary actually prints is a solid rectangle of `#`. Nothing is hidden or encrypted — the drawing is right there in `.rodata`, it is just being rendered with a brush so fat that every stroke smears into its neighbours.

### Solution:

##### 1. A pen plotter with no input

The binary is small, unstripped, and reads nothing:

```
$ nm -C etchasketch | grep -vE ' (U|w) '
0000000000004020 D brush_r
0000000000004060 b canvas
0000000000001149 t dab
00000000000011e5 t line
00000000000012df T main
0000000000002020 r points
```

`main` walks `points`, calls `line` between consecutive entries, then prints `canvas` as `#`/space. The canvas bounds fall out of the loop conditions — `0x77` and `0x51`, so 120x82:

```asm
1186:  cmp    DWORD PTR [rbp-0x10],0x0     ; px >= 0
118c:  cmp    DWORD PTR [rbp-0x10],0x77    ; px <= 119
1192:  cmp    DWORD PTR [rbp-0x14],0x0     ; py >= 0
1198:  cmp    DWORD PTR [rbp-0x14],0x51    ; py <= 81
11ad:  shl    rax,0x4                      ; py*16
11b1:  sub    rax,rdx                      ;    - py     = py*15
11b4:  shl    rax,0x3                      ;    * 8      = py*120
11c6:  mov    BYTE PTR [rax],0x1           ; canvas[py*120 + px] = 1
```

##### 2. `points` is a packed pen path

Each element is one 32-bit word holding two `int16`, and `main` splits them with `movzx`/`cwde` — low half is x, high half is y:

```asm
12fd:  mov    rax,QWORD PTR [rbp-0x8]
1309:  lea    rax,[rip+0xd10]           ; points
1310:  mov    eax,DWORD PTR [rdx+rax*1] ; one packed point
1316:  movzx  eax,WORD PTR [rbp-0x18]
131a:  cmp    ax,0xfffe                 ; x == -2  -> end of drawing
131e:  je     1358
1324:  test   ax,ax                     ; x < 0    -> pen up
1327:  js     1341
134c:  cmp    QWORD PTR [rbp-0x8],0x144 ; at most 325 points
```

So `(-1,-1)` lifts the pen and `(-2,*)` terminates. The array is `0x1300` bytes — 1216 points — but the loop caps at index `0x144` and the first `-2` sentinel sits at exactly index 324, so only the first drawing is ever used. (There is a second sentinel at 964; the points between them have coordinates like `x=31233`, i.e. dead junk that would have been clipped away anyway.)

##### 3. The brush is the whole challenge

`dab` does not set one pixel. It stamps a square of side `2*brush_r+1` centred on the point:

```asm
1153:  mov    eax,DWORD PTR [rip+0x2ec7]   ; brush_r
1159:  mov    DWORD PTR [rbp-0xc],eax
115c:  mov    eax,DWORD PTR [rbp-0xc]
115f:  neg    eax                          ; for (dy = -r; dy <= r; dy++)
1166:  mov    eax,DWORD PTR [rbp-0xc]
1169:  neg    eax                          ;   for (dx = -r; dx <= r; dx++)
```

And `brush_r` is a plain initialised global:

```
$ objdump -s -j .data --start-address=0x4020 --stop-address=0x4024 etchasketch
 4020 0a000000                             ....
```

`r = 10`, so every plotted pixel paints 21x21 = 441 cells on a 120x82 canvas. Strokes that are 16 apart cannot help but merge:

```
#########################################################################
###########################################################################################################
###########################################################################################################
###########################################################################################################
                                     ... etc ...
```

##### 4. Replot at radius 0

Nothing else needs touching — same path, same Bresenham, radius 0:

```
    #           #         #         #############         #####
    #         ##         ##                    #         #
    #        #          # #                    #        #
    #      ##          #  #                   #         #
    #     #           #   #                   #         #
    #   ##                #                  #          #
    #  #                  #                  #          #
    ###                   #                 #         ##
    #                     #                 #       ##              # ###   ###     #           #
    ###                   #                #         ##             ##   # #   #     #         #
    #  #                  #                #           ##           #     #     #     #       #
    #   ##                #               #             #           #     #     #     #       #
    #     #               #               #             #           #     #     #      #     #
    #      ##             #              #              #           #     #     #       #   #
    #        #            #              #              #           #     #     #        # #
    #         ##          #             #                #          #     #     #        # #
    #           #   #############       #                 #####     #     #     #         #
                                                                                         #
                                                                                        #
                                                                                       #
                                                                                    ###             #############

                                                          #
                                                          #
    # ###   ###     ###########       ###########   #############     #########     #   #######
    ##   # #   #               #     #                    #          #         #    #  #       #
    #     #     #               #   #                     #         #           #   # #         #
    #     #     #               #    #                    #         #           #   ##
    #     #     #     ###########     #########           #         #############   #
    #     #     #    #          #              #          #         #               #
    #     #     #   #           #               #         #         #               #
    #     #     #    #          #              #           #         #              #
    #     #     #     ###########   ###########             #####     ###########   #

    ###########       #####           #########       ###########     #########                ##
    #          #          #          #         #     #               #         #              ##
    #           #         #         #           #   #               #           #           ##
    #           #         #         #           #   #               #           #           #
    #           #         #         #############   #               #############           #
    #           #         #         #               #               #                       #
    #           #         #         #               #               #                       #
    #          #          #          #               #               #                     #
    ###########       #########       ###########     ###########     ###########     #####
    #
    #
    #
```

Three rows of hand-drawn glyphs on a 16-pixel grid: `K 1 7 { m y _` / `m a s t e r` / `p i e c e }`.

Full script: [solve.py](solve.py)

**Flag:** `K17{my_masterpiece}`
