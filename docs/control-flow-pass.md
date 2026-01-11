# Control Flow Pass

Obfuscates control flow by transforming direct calls into indirect jumps through return address manipulation.

## Example

### Before (Original)
```asm
.text:00000001400127A4                 call    j_?set_app_type@__scrt_main_policy@@SAXXZ
.text:00000001400127A9                 call    j_?set_fmode@__scrt_file_policy@@SAXXZ
.text:00000001400127AE                 call    j_?set_commode@__scrt_file_policy@@SAXXZ
```

### After (Obfuscated)
```asm
; Direct calls are transformed
.vasie:000000014002853D                 call    sub_1400110C3
.vasie:0000000140028542                 call    sub_140011339
.vasie:0000000140028547                 call    sub_14001100F
```

**Alternative transformation** (lea + push + jmp pattern):
```asm
; call target
; becomes:
lea     rax, [rip + next_instruction]
push    rax
jmp     target
; next_instruction:
```
