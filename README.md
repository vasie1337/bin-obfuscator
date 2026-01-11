# Binary Obfuscator

x86-64 PE binary obfuscation tool. Transforms executable code to resist reverse engineering while preserving functionality.

## Before & After

### Original
```asm
.text:00000001400127A0 ; int __fastcall pre_c_initialization()
.text:00000001400127A0 pre_c_initialization proc near          ; DATA XREF: .rdata:pre_c_initializer↓o
.text:00000001400127A0                                         ; .pdata:0000000140020974↓o
.text:00000001400127A0                 sub     rsp, 28h
.text:00000001400127A4                 call    j_?set_app_type@__scrt_main_policy@@SAXXZ ; __scrt_main_policy::set_app_type(void)
.text:00000001400127A9                 call    j_?set_fmode@__scrt_file_policy@@SAXXZ ; __scrt_file_policy::set_fmode(void)
.text:00000001400127AE                 call    j_?set_commode@__scrt_file_policy@@SAXXZ ; __scrt_file_policy::set_commode(void)
.text:00000001400127B3                 nop
.text:00000001400127B4                 mov     ecx, 1          ; module_type
.text:00000001400127B9                 call    j___scrt_initialize_onexit_tables
.text:00000001400127BE                 movzx   eax, al
.text:00000001400127C1                 test    eax, eax
.text:00000001400127C3                 jnz     short loc_1400127D0
.text:00000001400127C5                 mov     ecx, 7          ; code
.text:00000001400127CA                 call    j___scrt_fastfail
.text:00000001400127CF                 nop
.text:00000001400127D0
.text:00000001400127D0 loc_1400127D0:                          ; CODE XREF: pre_c_initialization+23↑j
.text:00000001400127D0                 call    j__RTC_Initialize
.text:00000001400127D5                 lea     rcx, j__RTC_Terminate ; function
.text:00000001400127DC                 call    j_atexit
.text:00000001400127E1                 nop
.text:00000001400127E2                 call    j_?configure_argv@__scrt_narrow_argv_policy@@SAHXZ ; __scrt_narrow_argv_policy::configure_argv(void)
.text:00000001400127E7                 test    eax, eax
.text:00000001400127E9                 jz      short loc_1400127F6
.text:00000001400127EB                 mov     ecx, 7          ; code
.text:00000001400127F0                 call    j___scrt_fastfail
.text:00000001400127F5                 nop
.text:00000001400127F6
.text:00000001400127F6 loc_1400127F6:                          ; CODE XREF: pre_c_initialization+49↑j
.text:00000001400127F6                 call    j_?__scrt_initialize_type_info@@YAXXZ ; __scrt_initialize_type_info(void)
.text:00000001400127FB                 nop
.text:00000001400127FC                 call    j___scrt_is_user_matherr_present
.text:0000000140012801                 test    eax, eax
.text:0000000140012803                 jz      short loc_140012812
.text:0000000140012805                 lea     rcx, j__matherr ; UserMathErrorFunction
.text:000000014001280C                 call    j___setusermatherr_0
.text:0000000140012811                 nop
.text:0000000140012812
.text:0000000140012812 loc_140012812:                          ; CODE XREF: pre_c_initialization+63↑j
.text:0000000140012812                 call    j__initialize_invalid_parameter_handler
.text:0000000140012817                 call    j__initialize_denormal_control
.text:000000014001281C                 call    j__get_startup_thread_locale_mode
.text:0000000140012821                 mov     ecx, eax        ; Flag
.text:0000000140012823                 call    j__configthreadlocale_0
.text:0000000140012828                 nop
.text:0000000140012829                 call    j__should_initialize_environment
.text:000000014001282E                 movzx   eax, al
.text:0000000140012831                 test    eax, eax
.text:0000000140012833                 jz      short loc_14001283B
.text:0000000140012835                 call    j_?initialize_environment@__scrt_narrow_environment_policy@@SAHXZ ; __scrt_narrow_environment_policy::initialize_environment(void)
.text:000000014001283A                 nop
.text:000000014001283B
.text:000000014001283B loc_14001283B:                          ; CODE XREF: pre_c_initialization+93↑j
.text:000000014001283B                 call    j___scrt_initialize_winrt
.text:0000000140012840                 nop
.text:0000000140012841                 call    j___scrt_initialize_mta
.text:0000000140012846                 test    eax, eax
.text:0000000140012848                 jz      short loc_140012855
.text:000000014001284A                 mov     ecx, 7          ; code
.text:000000014001284F                 call    j___scrt_fastfail
.text:0000000140012854                 nop
.text:0000000140012855
.text:0000000140012855 loc_140012855:                          ; CODE XREF: pre_c_initialization+A8↑j
.text:0000000140012855                 xor     eax, eax
.text:0000000140012857                 add     rsp, 28h
.text:000000014001285B                 retn
.text:000000014001285B pre_c_initialization endp
```

### Obfuscated
```asm
.vasie:0000000140028539 sub_140028539   proc near               ; CODE XREF: sub_1400127A0↑j
.vasie:0000000140028539
.vasie:0000000140028539 var_30          = qword ptr -30h
.vasie:0000000140028539 arg_16A         = byte ptr  172h
.vasie:0000000140028539 arg_77F         = byte ptr  787h
.vasie:0000000140028539 arg_4B8E        = byte ptr  4B96h
.vasie:0000000140028539
.vasie:0000000140028539                 sub     rsp, 28h
.vasie:000000014002853D                 call    sub_1400110C3
.vasie:0000000140028542                 call    sub_140011339
.vasie:0000000140028547                 call    sub_14001100F
.vasie:000000014002854C                 nop
.vasie:000000014002854D                 mov     ecx, 1
.vasie:0000000140028552                 call    sub_1400110E6
.vasie:0000000140028557                 movzx   eax, al
.vasie:000000014002855A                 test    eax, eax
.vasie:000000014002855C                 jnz     short loc_140028569
.vasie:000000014002855E                 mov     ecx, 7
.vasie:0000000140028563                 call    sub_14001131B
.vasie:0000000140028568                 nop
.vasie:0000000140028569
.vasie:0000000140028569 loc_140028569:                          ; CODE XREF: sub_140028539+23↑j
.vasie:0000000140028569                 call    sub_1400111F9
.vasie:000000014002856E                 lea     rcx, aTheValueOfEspW+10h ; " was not properly saved across a functi"...
.vasie:0000000140028575                 lea     rcx, [rcx-21FCh]
.vasie:000000014002857C                 lea     rcx, [rcx-3231h]
.vasie:0000000140028583                 lea     rcx, [rcx-0E0Fh]
.vasie:000000014002858A                 lea     rcx, [rcx-129Ah]
.vasie:0000000140028591                 lea     rcx, [rcx-137Bh]
.vasie:0000000140028598                 lea     rcx, [rcx+24F8h]
.vasie:000000014002859F                 lea     rcx, [rcx-1684h]
.vasie:00000001400285A6                 mov     [rsp+28h+var_30], rax
.vasie:00000001400285AB                 lea     rax, [rsp+28h+arg_16A]
.vasie:00000001400285B3                 lea     rax, [rax+16Ch]
.vasie:00000001400285BA                 lea     rax, [rax-306h]
.vasie:00000001400285C1                 mov     rax, [rsp+28h+var_30]
.vasie:00000001400285C6                 lea     rcx, [rcx-242Dh]
.vasie:00000001400285CD                 call    sub_140011159
.vasie:00000001400285D2                 nop
.vasie:00000001400285D3                 call    sub_14001121C
.vasie:00000001400285D8                 test    eax, eax
.vasie:00000001400285DA                 jz      short loc_1400285E7
.vasie:00000001400285DC                 mov     ecx, 7
.vasie:00000001400285E1                 call    sub_14001131B
.vasie:00000001400285E6                 nop
.vasie:00000001400285E7
.vasie:00000001400285E7 loc_1400285E7:                          ; CODE XREF: sub_140028539+A1↑j
.vasie:00000001400285E7                 call    sub_1400110AF
.vasie:00000001400285EC                 nop
.vasie:00000001400285ED                 call    sub_140011230
.vasie:00000001400285F2                 test    eax, eax
.vasie:00000001400285F4                 jz      short loc_140028670
.vasie:00000001400285F6                 lea     rcx, loc_140015AD4
.vasie:00000001400285FD                 lea     rcx, [rcx-14B4h]
.vasie:0000000140028604                 lea     rcx, [rcx-12E1h]
.vasie:000000014002860B                 lea     rcx, [rcx+21BEh]
.vasie:0000000140028612                 lea     rcx, [rcx-29A4h]
.vasie:0000000140028619                 lea     rcx, [rcx-0A32h]
.vasie:0000000140028620                 mov     [rsp+28h+var_30], rax
.vasie:0000000140028625                 lea     rax, [rsp+28h+arg_4B8E]
.vasie:000000014002862D                 lea     rax, [rax-3345h]
.vasie:0000000140028634                 lea     rax, [rax-134Ch]
.vasie:000000014002863B                 lea     rax, [rax+3EABh]
.vasie:0000000140028642                 lea     rax, [rax-38DAh]
.vasie:0000000140028649                 lea     rax, [rax-0AFEh]
.vasie:0000000140028650                 mov     rax, [rsp+28h+var_30]
.vasie:0000000140028655                 lea     rcx, [rcx+889h]
.vasie:000000014002865C                 lea     rcx, [rcx-464h]
.vasie:0000000140028663                 lea     rcx, [rcx-14A2h] ; UserMathErrorFunction
.vasie:000000014002866A                 call    j___setusermatherr
.vasie:000000014002866F                 nop
.vasie:0000000140028670
.vasie:0000000140028670 loc_140028670:                          ; CODE XREF: sub_140028539+BB↑j
.vasie:0000000140028670                 call    j_nullsub_2
.vasie:0000000140028675                 call    j_nullsub_1
.vasie:000000014002867A                 call    sub_140011073
.vasie:000000014002867F                 mov     ecx, eax        ; Flag
.vasie:0000000140028681                 call    j__configthreadlocale
.vasie:0000000140028686                 nop
.vasie:0000000140028687                 call    sub_1400111AE
.vasie:000000014002868C                 movzx   eax, al
.vasie:000000014002868F                 test    eax, eax
.vasie:0000000140028691                 jz      short loc_1400286B2
.vasie:0000000140028693                 call    sub_14001113B
.vasie:0000000140028698                 nop
.vasie:0000000140028699                 mov     [rsp+28h+var_30], rax
.vasie:000000014002869E                 lea     rax, [rsp+28h+arg_77F]
.vasie:00000001400286A6                 lea     rax, [rax-7AFh]
.vasie:00000001400286AD                 mov     rax, [rsp+28h+var_30]
.vasie:00000001400286B2
.vasie:00000001400286B2 loc_1400286B2:                          ; CODE XREF: sub_140028539+158↑j
.vasie:00000001400286B2                 call    sub_1400111EF
.vasie:00000001400286B7                 nop
.vasie:00000001400286B8                 call    sub_140011389
.vasie:00000001400286BD                 test    eax, eax
.vasie:00000001400286BF                 jz      short loc_1400286CC
.vasie:00000001400286C1                 mov     ecx, 7
.vasie:00000001400286C6                 call    sub_14001131B
.vasie:00000001400286CB                 nop
.vasie:00000001400286CC
.vasie:00000001400286CC loc_1400286CC:                          ; CODE XREF: sub_140028539+186↑j
.vasie:00000001400286CC                 xor     eax, eax
.vasie:00000001400286CE                 add     rsp, 28h
.vasie:00000001400286D2                 retn
.vasie:00000001400286D2 sub_140028539   endp
```

## Passes

- **[Arithmetic](docs/arithmetic-pass.md)** - LEA displacement obfuscation, constant splitting
- **[Stack](docs/stack-pass.md)** - PUSH/POP expansion to MOV + LEA
- **[Control Flow](docs/control-flow-pass.md)** - Call obfuscation (call → lea + push + jmp)
- **[Opaque Predicates](docs/opaque-predicates-pass.md)** - Computational noise insertion

## Usage

```
bin-obfuscator <BINARY> <PDB> [-o OUTPUT] [-v]
```

## Build

```
cargo build --release
```

## Test

```
cargo test
```

## Requirements

- Windows x64 PE binary
- Corresponding PDB file

## Limitations

- Functions with exception handlers are skipped
- No jump table support
