# Opaque Predicates Pass

Inserts computational noise that doesn't affect program semantics but complicates analysis.

## Example

### Before (Original)
```asm
.text:00000001400127DC                 call    j_atexit
.text:00000001400127E1                 nop
```

### After (Obfuscated)
```asm
.vasie:00000001400285CD                 call    sub_140011159
.vasie:00000001400285D2                 nop
; Opaque predicate: useless stack address calculations
.vasie:00000001400285A6                 mov     [rsp+28h+var_30], rax    ; Save rax
.vasie:00000001400285AB                 lea     rax, [rsp+28h+arg_16A]   ; Calculate invalid stack address
.vasie:00000001400285B3                 lea     rax, [rax+16Ch]          ; More useless arithmetic
.vasie:00000001400285BA                 lea     rax, [rax-306h]          ; The result is never used
.vasie:00000001400285C1                 mov     rax, [rsp+28h+var_30]    ; Restore rax (no net effect)
```

### Another Example
```asm
; Between actual operations, insert dead calculations
.vasie:0000000140028620                 mov     [rsp+28h+var_30], rax
.vasie:0000000140028625                 lea     rax, [rsp+28h+arg_4B8E]  ; arg_4B8E is out of bounds
.vasie:000000014002862D                 lea     rax, [rax-3345h]
.vasie:0000000140028634                 lea     rax, [rax-134Ch]
.vasie:000000014002863B                 lea     rax, [rax+3EABh]
.vasie:0000000140028642                 lea     rax, [rax-38DAh]
.vasie:0000000140028649                 lea     rax, [rax-0AFEh]
.vasie:0000000140028650                 mov     rax, [rsp+28h+var_30]    ; Restore original value
```
