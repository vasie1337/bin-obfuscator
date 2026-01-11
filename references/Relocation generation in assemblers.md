
Relocation generation in assemblers
===================================

This post explores how GNU Assembler and LLVM integrated assembler generate relocations, an important step to generate a relocatable file. Relocations identify parts of instructions or data that cannot be fully determined during assembly because they depend on the final memory layout, which is only established at link time or load time. These are essentially placeholders that will be filled in (typically with absolute addresses or PC-relative offsets) during the linking process.

Relocation generation: the basics
---------------------------------

Symbol references are the primary candidates for relocations. For instance, in the x86-64 instruction `movl sym(%rip), %eax` (GNU syntax), the assembler calculates the displacement between the program counter (PC) and `sym`. This distance affects the instruction's encoding and typically triggers a `R_X86_64_PC32` relocation, unless `sym` is a local symbol defined within the current section.

Both the GNU assembler and LLVM integrated assembler utilize multiple passes during assembly, with several key phases relevant to relocation generation:

Parsing phase
-------------

During parsing, the assembler builds section fragments that contain instructions and other directives. It parses each instruction into its opcode (e.g., `movl`) and operands (e.g., `sym(%rip), %eax`). It identifies registers, immediate values (like 3 in `movl $3, %eax`), and expressions.

Expressions can be constants, symbol refereces (like `sym`), or unary and binary operators (`-sym`, `sym0-sym1`). Those unresolvable at parse time-potential relocation candidates-turn into "fixups". These often skip immediate operand range checks, as shown here:

1  
2  
3  
4  
5  
6  
7  

% echo 'addi a0, a0, 2048' | llvm-mc -triple=riscv64  
<stdin>:1:14: error: operand must be a symbol with %lo/%pcrel\_lo/%tprel\_lo modifier or an integer in the range \[-2048, 2047\]  
addi a0, a0, 2048  
             ^  
% echo 'addi a0, a0, %lo(x)' | llvm-mc -triple riscv64 -show-encoding  
        addi    a0, a0, %lo(x)                  # encoding: \[0x13,0x05,0bAAAA0101,A\]  
                                        #   fixup A - offset: 0, value: %lo(x), kind: fixup\_riscv\_lo12\_i  

A fixup ties to a specific location (an offset within a fragment), with its value being the expression (which must eventually evaluate to a relocatable expression).

Meanwhile, the assembler tracks defined and referenced symbols, and for ELF, it tracks symbol bindings (`STB_LOCAL, STB_GLOBAL, STB_WEAK`) from directives like `.globl`, `.weak`, or the rarely used `.local`.

Section layout phase
--------------------

After parsing, the assembler arranges each section by assigning precise offsets to its fragments-instructions, data, or other directives (e.g., `.line`, `.uleb128`). It calculates sizes and adjusts for alignment. This phase finalizes symbol offsets (e.g., `start:` at offset 0x10) while leaving external ones for the linker.

This phase, which employs a fixed-point iteration, is quite complex. I won't go into details, but you might find [Clang's -O0 output: branch displacement and size increase](/blog/2024-04-27-clang-o0-output-branch-displacement-and-size-increase) interesting.

Relocation decision phase
-------------------------

Then the assembler evaluates each fixup to determine if it can be resolved directly or requires a relocation entry. This process starts by attempting to convert fixups into relocatable expressions.

### Evaluating relocatable expressions

In their most general form, relocatable expressions follow the pattern `relocation_specifier(sym_a - sym_b + offset)`, where

*   `relocation_specifier`: This may or may not be absent. I will explain this concept later.
*   `sym_a` is a symbol reference (the "addend")
*   `sym_b` is an optional symbol reference (the "subtrahend")
*   `offset` is a constant value

Most common cases involve only `sym_a` or `offset` (e.g., `movl sym(%rip), %eax` or `movl $3, %eax`). Only a few target architectures support the subtrahend term (`sym_b`). Notable exceptions include AVR and RISC-V, as explored in [The dark side of RISC-V linker relaxation](/blog/2021-03-14-the-dark-side-of-riscv-linker-relaxation.md).

Attempting to use unsupported expression forms will result in assembly errors:

1  
2  
3  
4  
5  
6  
7  

% echo -e 'movl a+b, %eax\\nmovl a-b, %eax' | clang -c -xassembler -  
<stdin>:1:1: error: expected relocatable expression  
movl a+b, %eax  
^  
<stdin>:2:1: error: symbol 'b' can not be undefined in a subtraction expression  
movl a-b, %eax  
^  

Let's use some notations from the AArch64 psABI.

*   `S` is the address of the symbol.
*   `A` is the addend for the relocation.
*   `P` is the address of the place being relocated (derived from `r_offset`).
*   `GOT` is the address of the Global Offset Table, the table of code and data addresses to be resolved at dynamic link time.
*   `GDAT(S+A)` represents a pointer-sized entry in the `GOT` for address `S+A`.

### PC-relative fixups

PC-relative fixups compute their values as `sym_a - current_location + offset` (`S - P + A`) and can be seen as a special case that uses `sym_b`. (I’ve skipped `- sym_b`, since no target I know permits a subtrahend here.)

When `sym_a` is a non-ifunc local symbol defined within the current section, these PC-relative fixups evaluate to constants. But if `sym_a` is a global or weak symbol in the same section, a relocation entry is generated. This ensures [ELF symbol interposition](/blog/2021-05-16-elf-interposition-and-bsymbolic) stays in play.

In contrast, label differences (e.g. `.quad g-f`) can be resolved even if `f` and `g` are global.

On some targets (e.g., AArch64, PowerPC, RISC-V), the PC-relative offset is relative to the start of the instruction (P), while others (e.g., AArch32, x86) are relative to P plus a constant.

### Resolution Outcomes

The assembler's evaluation of fixups leads to one of three outcomes:

*   Error: When the expression isn't supported.
*   Resolved fixups: The assembler updates the relevant bits in the instruction directly. No relocation entry is needed.
    *   There are target-specific exceptions that make the fixup unresolved. In AArch64 `adrp x0, l0; l0:`, the immediate might be either 0 or 1, dependant on the instruction address. In RISC-V, linker relaxation might make fixups unresolved.
*   Unresolved fixups: When the fixup evaluates to a relocatable expression but not a constant, the assembler
    *   Generates an appropriate relocation (offset, type, symbol, addend).
    *   For targets that use RELA, usually zeros out the bits in the instruction field that will be modified by the linker.
    *   For targets that use REL, leave the addend in the instruction field.
    *   If the referenced symbol is defined and local, and the relocation type is not in exceptions (gas `tc_fix_adjustable`), the relocation references the section symbol instead of the local symbol.

Fixup resolution depends on the fixup type:

*   PC-relative fixups that describe the symbol itself (the relocation operation looks like `S - P + A`) resolve to a constant if `sym_a` is a non-ifunc local symbol defined in the current section.
*   `relocation_specifier(S + A)` style fixups resolve when `S` refers to an absolute symbol.
*   Other fixups, including TLS and GOT related ones, remain unresolved.

For ELF targets, if a non-TLS relocation operation references the symbol itself `S` (not `GDAT`), it may be adjusted to reference the section symbol instead.

If you are interested in relocation representations in different object file formats, please check out my post [Exploring object file formats](/blog/2024-01-14-exploring-object-file-formats).

If an equated symbol `sym` is resolved relative to a section, relocations are generated against `sym`. Otherwise, if it resolves to a constant or an undefined symbol, relocations are generated against that constant or undefined symbol.

Examples in action
------------------

**Branches**

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  
12  

% echo -e 'call fun\\njmp fun' | clang -c -xassembler - -o - | fob -dr -  
...  
       0: e8 00 00 00 00                callq   0x5 <.text+0x5>  
                0000000000000001:  R\_X86\_64\_PLT32       fun-0x4  
       5: e9 00 00 00 00                jmp     0xa <.text+0xa>  
                0000000000000006:  R\_X86\_64\_PLT32       fun-0x4  
% echo -e 'bl fun\\nb fun' | clang --target=aarch64 -c -xassembler - -o - | fob -dr -  
...  
       0: 94000000      bl      0x0 <.text>  
                0000000000000000:  R\_AARCH64\_CALL26     fun  
       4: 14000000      b       0x4 <.text+0x4>  
                0000000000000004:  R\_AARCH64\_JUMP26     fun  

**Absolute and PC-relative symbol references**

1  
2  
3  
4  
5  
6  

% echo -e 'movl a, %eax\\nmovl a(%rip), %eax' | clang -c -xassembler - -o - | llvm-objdump -dr -  
...  
       0: 8b 04 25 00 00 00 00          movl    0x0, %eax  
                0000000000000003:  R\_X86\_64\_32S a  
       7: 8b 05 00 00 00 00             movl    (%rip), %eax            # 0xd <.text+0xd>  
                0000000000000009:  R\_X86\_64\_PC32        a-0x4  

`(a-.)(%rip)` would probably be more semantically correct but is not adopted by GNU Assembler.

Relocation specifiers
---------------------

Relocation specifiers guide the assembler on how to resolve and encode expressions into instructions. They specify details like:

*   Whether to reference the symbol itself, its Procedure Linkage Table (PLT) entry, or its Global Offset Table (GOT) entry.
*   Which part of a symbol's address to use (e.g., lower or upper bits).
*   Whether to use an absolute address or a PC-relative one.

This concept appears across various architectures but with inconsistent terminology. The Arm architecture refers to elements like `:lo12:` and `:lower16:` as "relocation specifiers". IBM's AIX documentation also uses this term. Many GNU Binutils target documents simply call these "modifiers", while AVR documentation uses "relocatable expression modifiers".

Picking the right term was tricky. "Relocatable expression modifier" nails the idea of tweaking relocatable expressions but feels overly verbose. "Relocation modifier", though concise, suggests adjustments happen during the linker's relocation step rather than the assembler's expression evaluation. I landed on "relocation specifier" as the winner. It's clear, aligns with Arm and IBM’s usage, and fits the assembler's role seamlessly.

For example, RISC-V `addi` can be used with either an absolute address or a PC-relative address. Relocation specifiers `%lo` and `%pcrel_lo` could differentiate the two uses. Similarly, `%hi`, `%pcrel_hi`, and `%got_pcrel_hi` could differentiate the uses of `lui` and `auipc`.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  

\# Position-dependent code (PDC) - absolute addressing  
lui     a0, %hi(var)                    # Load upper immediate with high bits of symbol address  
addi    a0, a0, %lo(var)                # Add lower 12 bits of symbol address  
  
\# Position-independent code (PIC) - PC-relative addressing  
auipc   a0, %pcrel\_hi(var)              # Add upper PC-relative offset to PC  
addi    a0, a0, %pcrel\_lo(.Lpcrel\_hi1)  # Add lower 12 bits of PC-relative offset  
  
\# Position-independent code via Global Offset Table (GOT)  
auipc   a0, %got\_pcrel\_hi(var)          # Calculate address of GOT entry relative to PC  
ld      a0, %pcrel\_lo(.Lpcrel\_hi1)(a0)  # Load var's address from GOT  

Why use `%hi` with `lui` if it's always paired? It's about clarify and explicitness. `%hi` ensures consistency with `%lo` and cleanly distinguishes it from from `%pcrel_hi`. Since both `lui` and `auipc` share the U-type instruction format, tying relocation specifiers to formats rather than specific instructions is a smart, flexible design choice.

Relocation specifier flavors
----------------------------

Assemblers use various syntaxes for relocation specifiers, reflecting architectural quirks and historical conventions. Below, we explore the main flavors, their usage across architectures, and some of their peculiarities.

**`expr@specifier`**

This is likely the most widespread syntax, adopted by many binutils targets, including ARC, C-SKY, Power, M68K, SuperH, SystemZ, and x86, among others. It's also used in Mach-O object files, e.g., `adrp x8, _bar@GOTPAGE`.

This suffix style puts the specifier after an `@`. It's intuitive—think `sym@got`. In PowerPC, operators can get elaborate, such as `sym@toc@l(9)`. Here, `@toc@l` is a single, indivisible operator-not two separate `@` pieces-indicating a TOC-relative reference with a low 16-bit extraction.

Parsing is loose: while both `expr@specifier+expr` and `expr+expr@specifier` are accepted (by many targets), conceptually it's just `specifier(expr+expr)`. For example, x86 accepts `sym@got+4` or `sym+4@got`, but don't misread—`@got` applies to `sym+4`, not just `sym`.

**`%specifier(expr)`**

MIPS, SPARC, RISC-V, and LoongArch favor this prefix style, wrapping the expression in parentheses for clarity. In MIPS, parentheses are optional, and operators can nest, like

1  
2  
3  
4  
5  

\# MIPS  
addiu   $2, $2, %lo(0x12345)  
addiu   $2, $2, %lo 0x12345  
lui     $1, %hi(%neg(%gp\_rel(main)))  
ld      $1, %got\_page($.str)($gp)  

Like `expr@specifier`, the specifier applies to the whole expression. Don't misinterpret `%lo(3)+sym`\-it resolves as `sym+3` with an `R_MIPS_LO16` relocation.

1  
2  
3  

\# MIPS  
addiu   $2, $2, %lo(3)+sym  # R\_MIPS\_LO16  sym+0x3  
addiu   $2, $2, %lo 3+sym   # R\_MIPS\_LO16  sym+0x3  

SPARC has an anti-pattern. Its `%lo` and `%hi` expand to different relocation types depending on whether gas's `-KPIC` option (`llvm-mc -position-independent`) is specified.

**`expr(specifier)`**

A simpler suffix style, this is used by AArch32 for data directives. It's less common but straightforward, placing the operator in parentheses after the expression.

1  
2  
3  
4  

.word sym(gotoff)  
.long f(FUNCDESC)  
  
.long f(got)+3    // allowed b GNU assembler and LLVM integrated assembler, but probably not used in the wild  

**`:specifier:expr`**

AArch32 and AArch64 adopt this colon-framed prefix notation, avoiding the confusion that parentheses might introduce.

1  
2  
3  
4  
5  
6  
7  
8  

// AArch32  
movw    r0, :lower16:x  
  
// AArch64  
add     x8, x8, :lo12:sym  
  
adrp    x0, :got:var  
ldr     x0, \[x0, :got\_lo12:var\]  

Applying this syntax to data directives or instructions' first operands, however, could create parsing ambiguity. In both GNU Assembler and LLVM, `.word :plt:fun` would be interpreted as `.word: plt: fun`, treating `.word` and `plt` as labels, rather than achieving the intended meaning.

One idea is to `#` for disambiguitation:

1  

.word #:gotpcrel:var  

**Recommendation**

For new architectures, I'd suggest adopting `%specifier(expr)`, and never use `@specifier`. The `%` symbol works seamlessly with data directives, and during operand parsing, the parser can simply peek at the first token to check for a relocation specifier.

I favor `%specifier(expr)` over `%specifier expr` because it provides clearer scoping, especially in data directives with multiple operands, such as `.long %lo(a), %lo(b)`.

( `%specifier(...)` resembles `%` expansion in GNU Assembler's altmacro mode.

1  
2  
3  

.altmacro  
.macro m arg; .long \\arg; .endm  
.data; m %(1+2)  

)

**Inelegance**

RISC-V favors `%specifier(expr)` but clings to `call sym@plt` for [legacy reasons](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/issues/98).

AArch64 uses `:specifier:expr`, yet `R_AARCH64_PLT32` (`.word foo@plt - .`) and PAuth ABI (`.quad (g + 7)@AUTH(ia,0)`) cannot use `:` after data directives due to parsing ambiguity. [https://github.com/llvm/llvm-project/issues/132570](https://github.com/llvm/llvm-project/issues/132570)

TLS symbols
-----------

When a symbol is defined in a section with the `SHF_TLS` flag (Thread-Local Storage), GNU assembler assigns it the type `STT_TLS` in the symbol table. For undefined TLS symbols, the process differs: GCC and Clang don’t emit explicit labels. Instead, assemblers identify these symbols through TLS-specific relocation specifiers in the code, deduce their thread-local nature, and set their type to `STT_TLS` accordingly.

1  
2  
3  
4  
5  

// AArch64  
add     x8, x8, :tprel\_hi12:tls  
  
// x86  
movl    %fs:tls@TPOFF, %eax  

Composed relocations
--------------------

Most instructions trigger zero or one relocation, but some generate two. Often, one acts as a marker, paired with a standard relocation. For example:

*   PPC64 [`bl __tls_get_addr(x@tlsgd)`](/blog/2021-02-14-all-about-thread-local-storage#:~:text=R_PPC64_TLSGD) pairs a marker `R_PPC64_TLSGD` with `R_PPC64_REL24`
*   PPC64's link-time GOT-indirect to PC-relative optimization (with Power10's prefixed instruction) generates a `R_PPC64_PCREL_OPT` relocation following a GOT relocation. [https://reviews.llvm.org/D79864](https://reviews.llvm.org/D79864)
*   RISC-V linker relaxation uses `R_RISCV_RELAX` alongside another relocation, and `R_RISCV_ADD*`/`R_RISCV_SUB*` pairs.
*   Mach-O scattered relocations for label differences.
*   XCOFF represents a label difference with a pair of [`R_POS` and `R_NEG` relocations](https://reviews.llvm.org/D77424).

These marker cases tie into "composed relocations", as outlined in the Generic ABI:

> If multiple consecutive relocation records are applied to the same relocation location (`r_offset`), they are composed instead of being applied independently, as described above. By consecutive, we mean that the relocation records are contiguous within a single relocation section. By composed, we mean that the standard application described above is modified as follows:
> 
> *   In all but the last relocation operation of a composed sequence, the result of the relocation expression is retained, rather than having part extracted and placed in the relocated field. The result is retained at full pointer precision of the applicable ABI processor supplement.
>     
> *   In all but the first relocation operation of a composed sequence, the addend used is the retained result of the previous relocation operation, rather than that implied by the relocation type.
>     
> 
> Note that a consequence of the above rules is that the location specified by a relocation type is relevant for the first element of a composed sequence (and then only for relocation records that do not contain an explicit addend field) and for the last element, where the location determines where the relocated value will be placed. For all other relocation operands in a composed sequence, the location specified is ignored.
> 
> An ABI processor supplement may specify individual relocation types that always stop a composition sequence, or always start a new one.

Implicit addends
----------------

ELF `SHT_REL` and Mach-O utilize implicit addends. TODO

*   `R_MIPS_HI16` (https://reviews.llvm.org/D101773)

GNU Assembler internals
-----------------------

GNU Assembler utilizes `struct fixup` to represent both the fixup and the relocatable expression.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  

struct fix {  
  ...  
  /\* NULL or Symbol whose value we add in.  \*/  
  symbolS \*fx\_addsy;  
  
  /\* NULL or Symbol whose value we subtract.  \*/  
  symbolS \*fx\_subsy;  
  
  /\* Absolute number we add in.  \*/  
  valueT fx\_offset;  
};  

The relocation specifier is part of the instruction instead of part of `struct fix`. Targets have different internal representations of instructions.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  
12  
13  
14  
15  
16  
17  
18  
19  
20  
21  
22  
23  
24  
25  
26  
27  

// gas/config/tc-aarch64.c  
struct reloc  
{  
  bfd\_reloc\_code\_real\_type type;  
  expressionS exp;  
  int pc\_rel;  
  enum aarch64\_opnd opnd;  
  uint32\_t flags;  
  unsigned need\_libopcodes\_p : 1;  
};  
  
struct aarch64\_instruction  
{  
  aarch64\_inst base;  
  aarch64\_operand\_error parsing\_error;  
  int cond;  
  struct reloc reloc;  
  unsigned gen\_lit\_pool : 1;  
};  
  
// gas/config/tc-ppc.c  
struct ppc\_fixup  
 {  
   expressionS exp;  
   int opindex;  
   bfd\_reloc\_code\_real\_type reloc;  
 };  

The 2002 message [stage one of gas reloc rewrite](https://sourceware.org/pipermail/binutils/2002-August/021813.html) describes the passes.

In PPC, the result of `@l` and `@ha` can be either signed or unsigned, determined by the instruction opcode.

In `md_apply_fix`, TLS-related relocation specifiers call `S_SET_THREAD_LOCAL (fixP->fx_addsy);`.

LLVM internals
--------------

LLVM integrated assembler encodes fixups and relocatable expressions separately.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  
12  
13  
14  
15  
16  

class MCFixup {  
  /// The value to put into the fixup location. The exact interpretation of the  
  /// expression is target dependent, usually it will be one of the operands to  
  /// an instruction or an assembler directive.  
  const MCExpr \*Value = nullptr;  
  
  /// The byte index of start of the relocation inside the MCFragment.  
  uint32\_t Offset = 0;  
  
  /// The target dependent kind of fixup item this is. The kind is used to  
  /// determine how the operand value should be encoded into the instruction.  
  MCFixupKind Kind = FK\_NONE;  
  
  /// The source location which gave rise to the fixup, if any.  
  SMLoc Loc;  
};  

LLVM encodes relocatable expressions as `MCValue`,

1  
2  
3  
4  
5  

class MCValue {  
  const MCSymbol \*SymA = nullptr, \*SymB = nullptr;  
  int64\_t Cst = 0;  
  uint32\_t Specifier = 0;  
};  

with:

*   `Specifier` as an optional relocation specifier (named `RefKind` before LLVM 21)
*   `SymA` as an optional symbol reference (addend)
*   `SymB` as an optional symbol reference (subtrahend)
*   `Cst` as a constant value

This mirrors the relocatable expression concept, but `Specifier`—[added in 2014 for AArch64 as `RefKind`](https://github.com/llvm/llvm-project/commit/0999cbd0b9ed8aa893cce10d681dec6d54b200ad)—remains rare among targets. (I've recently made some cleanup to some targets. For instance, I migrated PowerPC's [@l and @ha folding to use `Specifier`](https://github.com/llvm/llvm-project/commit/89812985358784b16fb66928ad4da411386f4720).)

AArch64 implements a clean approach to select the relocation type. It dispatches on the fixup kind (an operand within a specific instruction format), then refines it with the relocation specifier.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  
12  
13  
14  
15  
16  

// AArch64ELFObjectWriter::getRelocType  
unsigned Kind = Fixup.getTargetKind();  
switch (Kind) {  
// Handle generic MCFixupKind.  
case FK\_Data\_1:  
case FK\_Data\_2:  
  ...  
  
// Handle target-specific MCFixupKind.  
case AArch64::fixup\_aarch64\_add\_imm12:  
  if (RefKind == AArch64::S\_DTPREL\_HI12)  
    return R\_CLS(TLSLD\_ADD\_DTPREL\_HI12);  
  if (RefKind == AArch64::S\_TPREL\_HI12)  
    return R\_CLS(TLSLE\_ADD\_TPREL\_HI12);  
  ...  
}  

`MCAssembler::evaluateFixup` and `ELFObjectWriter::recordRelocation` record a relocation.

1  
2  
3  
4  
5  
6  
7  
8  
9  
10  
11  
12  
13  
14  
15  
16  
17  
18  
19  
20  
21  
22  

// MCAssembler::evaluateFixup  
Evaluate \`const MCExpr \*Fixup::Value\` to a relocatable expression.  
Determine the fixup value. Adjust the value if FKF\_IsPCRel.  
If the relocatable expression is a constant, treat this fixup as resolved.  
  
if (IsResolved && is\_reloc\_directive)  
  IsResolved = false;  
Backend.applyFixup(...)  
  
  
  
// applyFixup  
if (...)  
  IsResolved = false;  
if (!IsResolved) {  
  // For exposition I've inlined ELFObjectWriter::recordRelocation here.  
  // the function roughly maps to GNU Assembler's \`md\_apply\_fix\` and \`tc\_gen\_reloc\`,  
  Type = TargetObjectWriter->getRelocType(Ctx, Target, Fixup, IsPCRel)  
  Determine whether SymA can be converted to a section symbol.  
  Relocations.push\_back(...)  
}  
// Write a value to the relocated location. When using relocations with explicit addends, the function is a no-op when \`IsResolved\` is true.  

`FKF_IsPCRel` applies to fixups whose relocation operations look like `S - P + A`, like branches and PC-relative operations, but not to GOT-related operations (e.g., `GDAT - P + A`).

### `MCSymbolRefExpr` issues

The expression structure follows a traditional object-oriented hierarchy:

1  
2  
3  
4  
5  
6  
7  
8  

MCExpr  
  MCConstantExpr: Value  
  MCSymbolRefExpr: VariantKind, Symbol  
  MCUnaryExpr: Op, Expr  
  MCBinaryExpr: Op, LHS, RHS  
  MCTargetExpr:  
    X86MCExpr: x86 register  
  MCSpecifierExpr: expression with a relocation specifier  

`MCSymbolRefExpr::VariantKind` enums the relocation specifier, but it's a poor fit:

*   Other expressions, like `MCConstantExpr` (e.g., PPC `4@l`) and `MCBinaryExpr` (e.g., PPC `(a+1)@l`), also need it.
*   Semantics blur when folding expressions with `@`, which is unavoidable when `@` can occur at any position within the full expression.
*   The generic `MCSymbolRefExpr` lacks target-specific hooks, cluttering the interface with any target-specific logic.

Consider what happens with addition or subtraction:

1  
2  
3  

MCBinaryExpr  
  LHS(MCSymbolRefExpr): VariantKind, SymA  
  RHS(MCSymbolRefExpr): SymB  

Here, the specifier attaches only to the LHS, leaving the full result uncovered. This awkward design demands workarounds.

*   Parsing `a+4@got` exposes clumsiness. After `AsmParser::parseExpression` processes `a+4`, it detects `@got` and retrofits it onto `MCSymbolRefExpr(a)`, which feels hacked together.
*   PowerPC's `@l` `@ha` optimization needs `PPCAsmParser::extractSpecifier` and `PPCAsmParser::applySpecifier` to convert a `MCSymbolRefExpr` to a `MCSpecifierExpr`.

Worse, leaky abstractions that `MCSymbolRefExpr` is accessed widely in backend code introduces another problem: while `MCBinaryExpr` with a constant RHS mimics `MCSymbolRefExpr` semantically, code often handles only the latter.

### `MCFixup` should store `MCValue` instead of `MCExpr`

The const `MCExpr *MCFixup::getValue()` method feels inconvenient and less elegant compared to GNU Assembler's unified fixup/relocatable expression for these reasons:

*   Relocation specifier can be encoded by every sub-expression in the `MCExpr` tree, rather than the fixup itself (or the instruction, as in GNU Assembler). Supporting all of `a+4@got, a@got+4, (a+4)@got` requires extensive hacks in LLVM MCParser.
*   `evaluateAsRelocatable` converts an MCExpr to an MCValue without updating the MCExpr itself. This leads to redundant evaluations, as `MCAssembler::evaluateFixup` is called multiple times, such as in `MCAssembler::fixupNeedsRelaxation` and `MCAssembler::layout`.

Storing a MCValue directly in MCFixup, or adding a relocation specifier member, could eliminate the need for many target-specific `MCTargetFixup` classes that manage relocation specifiers. However, target-specific evaluation hooks would still be needed for specifiers like PowerPC `@l` or RISC-V `%lo()`.

Computing label differences will be simplified as we can utilize `SymA` and `SymB`.

Our long-term goal is to encode the relocation specifier within `MCFixup`. ([https://github.com/llvm/llvm-project/issues/135592](https://github.com/llvm/llvm-project/issues/135592))

`MCSymbolRefExpr::VariantKind` as the legacy way to encode relocations should be completely removed (probably in a distant future as many cleanups are required).

### AsmParser: `expr@specifier`

In LLVM's assembly parser library (LLVMMCParser), the parsing of `expr@specifier` was supported for all targets until I updated it to be [an opt-in feature](https://github.com/llvm/llvm-project/commit/a0671758eb6e52a758bd1b096a9b421eec60204c) in March 2025.

AsmParser's `@specifier` parsing is suboptimal, necessitating lexer workarounds.

The `@` symbol can appear after a symbol or an expression (via `parseExpression`) and may occur multiple times within a single operand, making it challenging to validate and reject invalid cases.

In the GNU Assembler, COFF targets permit `@` within identifier names, and MinGW supports constructs like `.long ext24@secrel32`. It appears that a recognized suffix is treated as a specifier, while an unrecognized suffix results in a symbol that includes the `@`.

The PowerPC AsmParser (`llvm/lib/Target/PowerPC/AsmParser/PPCAsmParser.cpp`) parses an operand and then calls `PPCAsmParser::extractSpecifier` to extract the optional `@` specifier. When the `@` specifier is detected and removed, it generates a `PPCMCExpr`. This functionality is currently implemented for `@l` and @ha\`, and it would be beneficial to extend this to include all specifiers.

### AsmPrinter

In `llvm/lib/CodeGen/AsmPrinter/AsmPrinter.cpp`, `AsmPrinter::lowerConstant` outlines how LLVM handles the emission of a global variable initializer. When processing `ConstantExpr` elements, this function may generate data directives in the assembly code that involve differences between symbols.

One significant use case for this intricate code is `clang++ -fexperimental-relative-c++-abi-vtables`. This feature produces a PC-relative relocation that points to either the PLT (Procedure Linkage Table) entry of a function or the function symbol directly.
