# Stack Pass

Expands stack operations (PUSH/POP) into equivalent sequences using MOV and LEA instructions.

## Example

### Before (Original)
```asm
; Typical function prologue/epilogue
push    rbp
mov     rbp, rsp
; ... function body ...
pop     rbp
ret
```

### After (Obfuscated)
```asm
; Expanded PUSH
lea     rsp, [rsp-8]
mov     [rsp], rbp
mov     rbp, rsp
; ... function body ...
; Expanded POP
mov     rbp, [rsp]
lea     rsp, [rsp+8]
ret
```
