# Branch Tables and Jump Tables
> This repo covers Branch and Jump Tables in C and x86 assembly. Branch Tables handle jumps within a subroutine, while Jump Tables facilitate dynamic subroutine calls. Examples and step-by-step explanations are provided for a deeper understanding.

- snowcra5h@icloud.com
- https://twitter.com/snowcra5h

## Branch Table
A branch table represents an array of relative or absolute addresses used for jumping within the **same subroutine** or function. It allows a program to navigate to different code sections within the same subroutine based on a condition or index. For instance, this can be useful for simplifying code or implementing state machines.

**Typical C implementation**
```c
 ... validate x                    /* transform x to 0 (invalid) or 1,2,3, according to value..)    */
       y = x * 4;                  /* multiply by branch instruction length (e.g. 4 )               */
       goto next + y;              /* branch into 'table' of branch instructions                    */
 /* start of branch table */
 next: goto codebad;               /* x= 0  (invalid)                                               */
       goto codeone;               /* x= 1                                                          */
       goto codetwo;               /* x= 2                                                          */
 ... rest of branch table
 codebad:                          /* deal with invalid input                                       */
```

**Typical x86 implementation**
<div align="center">
  <img src="https://user-images.githubusercontent.com/90065760/231896993-73e976ad-035e-48a2-a6c2-60c15110929f.png" alt="Start Block for Branch Table" width="50%" height="50%">
</div>

<div align="center">
  <img src="https://user-images.githubusercontent.com/90065760/231896627-0e0b9185-719c-442a-a864-77b602b70eed.png" width="50%" height="50%">
</div>

```c
.text:0056CD12
.text:0056CD12 loc_56CD12:
.text:0056CD12 mov     edx, [ebp+OPCODE]
.text:0056CD18 sub     edx, 518h       ; switch 60 cases
.text:0056CD1E mov     [ebp+OPCODE], edx
.text:0056CD24 cmp     [ebp+OPCODE], 3Bh ; Compare Two Operands
.text:0056CD2B ja      def_56CD0B      ; jumptable 0056CD0B default case, cases 1290-1295,1297-1299
.text:0056CD2B                         ; jumptable 0056CD3F default case, cases 1306-1311,1322-1327,1337-1359
.text:0056CD2B                         ; jumptable 0056CDD2 default case, cases 1368-1535
.text:0056CD2B                         ; jumptable 0056CE8B default case, cases 1800-2047
.text:0056CD2B                         ; jumptable 0056CF39 default case, cases 2314-2319
.text:0056CD2B                         ; jumptable 0056CF65 default case, cases 4106-4111
.text:0056CD2B                         ; jumptable 0056CFF4 default case, cases 4122-4175,4180-4191,4194-4207,4209-4223,4225-4239
.text:0056CD2B                         ; jumptable 0056D027 default case, cases 4362-4367,4369-4383
.text:0056CD2B                         ; jumptable 0056D079 default case, cases 4388-4399,4402-4415,4417-4431,4435-4447,4449-4607
.text:0056CD2B                         ; jumptable 0056D0A4 default case, cases 4682-4687
.text:0056CD2B                         ; jumptable 0056D0F7 default case, cases 4695-4719,4725-4751,4762-4863,4866-4895,4899-4927
.text:0056CD2B                         ; jumptable 0056D147 default case, cases 4932-4943,4946-4959,4961-4975,4981-4991
.text:0056CD2B                         ; jumptable 0056D197 default case, cases 4998-5007,5009-5119
```

**Assume**: [ebp+OPCODE] = `0x534`. 
1. `edx = 0x534`
2. `sub edx ,518h` -> `edx = 1c`
3. [ebp+OPCODE] = 0x1c
4. `0x1c < 0x3b`. Thus the jump is not taken.

**After jump not taken we follow the execution to this block**
```d
.text:0056CD31 mov     ecx, [ebp+OPCODE]
.text:0056CD37 xor     eax, eax        ; Logical Exclusive OR
.text:0056CD39 mov     al, ds:byte_575F6E[ecx]
.text:0056CD3F jmp     ds:jpt_56CD3F[eax*4] ; switch jump
```
1. `ecx = 1c`
2. `eax = 0`

3. The value at `*(&(575f6e + 1c))` is moved into the low byte of `eax` which is `al`. (Highlighted in brackets below)
```c
.text:00575F6E byte_575F6E     db      0,     1,   19h,   19h
.text:00575F6E                                         ; DATA XREF: _FXCLI_OraBR_Exec_Command+883↑r
.text:00575F6E                 db    19h,   19h,   19h,   19h ; indirect table for switch statement
.text:00575F6E                 db      2,     3,     4,     5
.text:00575F6E                 db      6,     7,     8,     9
.text:00575F6E                 db    0Ah,   0Bh,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    0Ch,   0Dh,   0Eh,   0Fh
.text:00575F6E                 db   [10h],  11h,   12h,   13h
.text:00575F6E                 db    14h,   19h,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    19h,   19h,   19h,   19h
.text:00575F6E                 db    15h,   16h,   17h,   18h
```
>If we count `1c` bytes into this table we get the value `10h`. Therefore `al = 10h`

4. `al` is now used as an index to the jump table at `56cd3f`.  (`&00575F06[0 ] .. &00575F06[25]` have been added for ease of reading)
	1. We scale `eax * 4` to account for the sizes of an address in x86, which is 4 bytes. After scaling `eax = 40h`.
	2. The value at the base address `jpt_56CD3F[0]` gives us `00575F06`, and `00575f06 + 40h = 575F46`. We can either get the value we will jump to using dynamic analysis in WinDBG, which means we will dereference the address 575F46, or continue using static analysis in IDA with our original offset of `10h`, using the entry `&00575F06[16] .text:00575F06 dd offset loc_572E27`. So the address we jump to is `572E27`.
```c
&00575F06[0 ] .text:00575F06 jpt_56CD3F      dd offset loc_56FAD9    ; DATA XREF: _FXCLI_OraBR_Exec_Command+889↑r
&00575F06[1 ] .text:00575F06                 dd offset loc_56FC21    ; jump table for switch statement
&00575F06[2 ] .text:00575F06                 dd offset loc_570E30
&00575F06[3 ] .text:00575F06                 dd offset loc_570F3C
&00575F06[4 ] .text:00575F06                 dd offset loc_571012
&00575F06[5 ] .text:00575F06                 dd offset loc_570C40
&00575F06[6 ] .text:00575F06                 dd offset loc_570612
&00575F06[7 ] .text:00575F06                 dd offset loc_56E5B3
&00575F06[8 ] .text:00575F06                 dd offset loc_5710CF
&00575F06[9 ] .text:00575F06                 dd offset loc_57117A
&00575F06[10] .text:00575F06                 dd offset loc_570D00
&00575F06[11] .text:00575F06                 dd offset loc_570CD0
&00575F06[12] .text:00575F06                 dd offset loc_572ED8
&00575F06[13] .text:00575F06                 dd offset loc_572E74
&00575F06[14] .text:00575F06                 dd offset loc_572C44
&00575F06[15] .text:00575F06                 dd offset loc_572D1C
&00575F06[16] .text:00575F06                 dd offset loc_572E27
&00575F06[17] .text:00575F06                 dd offset loc_56DFF6
&00575F06[18] .text:00575F06                 dd offset loc_56E060
&00575F06[19] .text:00575F06                 dd offset loc_572FB9
&00575F06[20] .text:00575F06                 dd offset loc_571785
&00575F06[21] .text:00575F06                 dd offset loc_56FC53
&00575F06[22] .text:00575F06                 dd offset loc_56FCC2
&00575F06[23] .text:00575F06                 dd offset loc_56FD30
&00575F06[24] .text:00575F06                 dd offset loc_56FDD9
&00575F06[25] .text:00575F06                 dd offset def_56CD0B
```

5. Finally, we jmp to `572E27`.
```c
.text:00572E27
.text:00572E27 loc_572E27:             ; jumptable 0056CD3F case 1332
.text:00572E27 mov     ax, [ebp+var_12554]
...
...
```

## Jump Table
A jump table is an array of pointers or addresses used to jump to **different subroutines** in a program. It allows the program to dynamically call various subroutines based on an index typically calculated at runtime.

**Example in c**
```c
#include <stdio.h>
#include <stdlib.h>

void f0 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f1 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f2 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f3 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f4 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f5 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f6 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f7 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }
void f8 (int x, int y) { printf("Val: %d jumped to f%d(%d)\n", y, x, x); }

void (*jmpTable[9])(int, int) = {f0, f1, f2, f3, f4, f5, f6, f7, f8};

int
main(int argc, char *argv[])
{
  int i, j;

  j = atoi(argv[1]);
  i = j % 9;

  jmpTable[i](i, j);

  return 0;
}
```