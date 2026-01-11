# Arithmetic Pass

Transforms arithmetic operations through LEA displacement obfuscation and constant splitting.

## Example

### Before (Original)
```asm
.text:00000001400127D5                 lea     rcx, j__RTC_Terminate ; function
```

### After (Obfuscated)
```asm
.vasie:000000014002856E                 lea     rcx, aTheValueOfEspW+10h
.vasie:0000000140028575                 lea     rcx, [rcx-21FCh]
.vasie:000000014002857C                 lea     rcx, [rcx-3231h]
.vasie:0000000140028583                 lea     rcx, [rcx-0E0Fh]
.vasie:000000014002858A                 lea     rcx, [rcx-129Ah]
.vasie:0000000140028591                 lea     rcx, [rcx-137Bh]
.vasie:0000000140028598                 lea     rcx, [rcx+24F8h]
.vasie:000000014002859F                 lea     rcx, [rcx-1684h]
.vasie:00000001400285C6                 lea     rcx, [rcx-242Dh]
```
