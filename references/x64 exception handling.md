
x64 exception handling
======================

Feedback

Summarize this article for me

In this article
---------------

1.  [Unwind data for exception handling, debugger support](#unwind-data-for-exception-handling-debugger-support)
2.  [Unwind procedure](#unwind-procedure)
3.  [Language-specific handler](#language-specific-handler)
4.  [Unwind helpers for MASM](#unwind-helpers-for-masm)
5.  [Unwind data definitions in C](#unwind-data-definitions-in-c)
6.  [See also](#see-also)

Show 2 more

An overview of structured exception handling and C++ exception handling coding conventions and behavior on the x64. For general information on exception handling, see [Exception Handling in Microsoft C++](https://learn.microsoft.com/en-us/cpp/cpp/exception-handling-in-visual-cpp?view=msvc-170).

[](#unwind-data-for-exception-handling-debugger-support)

Unwind data for exception handling, debugger support
----------------------------------------------------

Several data structures are required for exception handling and debugging support.

[](#struct-runtime_function)

### struct RUNTIME\_FUNCTION

Table-based exception handling requires a table entry for all functions that allocate stack space or call another function (for example, nonleaf functions). Function table entries have the format:

Expand table

Size

Value

ULONG

Function start address

ULONG

Function end address

ULONG

Unwind info address

The RUNTIME\_FUNCTION structure must be DWORD aligned in memory. All addresses are image relative, that is, they're 32-bit offsets from the starting address of the image that contains the function table entry. These entries are sorted, and put in the .pdata section of a PE32+ image. For dynamically generated functions \[JIT compilers\], the runtime to support these functions must either use RtlInstallFunctionTableCallback or RtlAddFunctionTable to provide this information to the operating system. Failure to do so will result in unreliable exception handling and debugging of processes.

[](#struct-unwind_info)

### struct UNWIND\_INFO

The unwind data info structure is used to record the effects a function has on the stack pointer, and where the nonvolatile registers are saved on the stack:

Expand table

Size

Value

UBYTE: 3

Version

UBYTE: 5

Flags

UBYTE

Size of prolog

UBYTE

Count of unwind codes

UBYTE: 4

Frame Register

UBYTE: 4

Frame Register offset (scaled)

USHORT \* n

Unwind codes array

variable

Can either be of form (1) or (2) below

(1) Exception Handler

Expand table

Size

Value

ULONG

Address of exception handler

variable

Language-specific handler data (optional)

(2) Chained Unwind Info

Expand table

Size

Value

ULONG

Function start address

ULONG

Function end address

ULONG

Unwind info address

The UNWIND\_INFO structure must be DWORD aligned in memory. Here's what each field means:

*   **Version**
    
    Version number of the unwind data, currently 1.
    
*   **Flags**
    
    Three flags are currently defined:
    
    Expand table
    
    Flag
    
    Description
    
    `UNW_FLAG_EHANDLER`
    
    The function has an exception handler that should be called when looking for functions that need to examine exceptions.
    
    `UNW_FLAG_UHANDLER`
    
    The function has a termination handler that should be called when unwinding an exception.
    
    `UNW_FLAG_CHAININFO`
    
    This unwind info structure is not the primary one for the procedure. Instead, the chained unwind info entry is the contents of a previous RUNTIME\_FUNCTION entry. For information, see [Chained unwind info structures](#chained-unwind-info-structures). If this flag is set, then the UNW\_FLAG\_EHANDLER and UNW\_FLAG\_UHANDLER flags must be cleared. Also, the frame register and fixed-stack allocation fields must have the same values as in the primary unwind info.
    
*   **Size of prolog**
    
    Length of the function prolog in bytes.
    
*   **Count of unwind codes**
    
    The number of slots in the unwind codes array. Some unwind codes, for example, UWOP\_SAVE\_NONVOL, require more than one slot in the array.
    
*   **Frame register**
    
    If nonzero, then the function uses a frame pointer (FP), and this field is the number of the nonvolatile register used as the frame pointer, using the same encoding for the operation info field of UNWIND\_CODE nodes.
    
*   **Frame register offset (scaled)**
    
    If the frame register field is nonzero, this field is the scaled offset from RSP that is applied to the FP register when it's established. The actual FP register is set to RSP + 16 \* this number, allowing offsets from 0 to 240. This offset permits pointing the FP register into the middle of the local stack allocation for dynamic stack frames, allowing better code density through shorter instructions. (That is, more instructions can use the 8-bit signed offset form.)
    
*   **Unwind codes array**
    
    An array of items that explains the effect of the prolog on the nonvolatile registers and RSP. See the section on UNWIND\_CODE for the meanings of individual items. For alignment purposes, this array always has an even number of entries, and the final entry is potentially unused. In that case, the array is one longer than indicated by the count of unwind codes field.
    
*   **Address of exception handler**
    
    An image-relative pointer to either the function's language-specific exception or termination handler, if flag UNW\_FLAG\_CHAININFO is clear and one of the flags UNW\_FLAG\_EHANDLER or UNW\_FLAG\_UHANDLER is set.
    
*   **Language-specific handler data**
    
    The function's language-specific exception handler data. The format of this data is unspecified and completely determined by the specific exception handler in use.
    
*   **Chained Unwind Info**
    
    If flag UNW\_FLAG\_CHAININFO is set, then the UNWIND\_INFO structure ends with three UWORDs. These UWORDs represent the RUNTIME\_FUNCTION information for the function of the chained unwind.
    

[](#struct-unwind_code)

### struct UNWIND\_CODE

The unwind code array is used to record the sequence of operations in the prolog that affect the nonvolatile registers and RSP. Each code item has this format:

Expand table

Size

Value

UBYTE

Offset in prolog

UBYTE: 4

Unwind operation code

UBYTE: 4

Operation info

The array is sorted by descending order of offset in the prolog.

[](#offset-in-prolog)

#### Offset in prolog

Offset (from the beginning of the prolog) of the end of the instruction that performs this operation, plus 1 (that is, the offset of the start of the next instruction).

[](#unwind-operation-code)

#### Unwind operation code

Note: Certain operation codes require an unsigned offset to a value in the local stack frame. This offset is from the start, that is, the lowest address of the fixed stack allocation. If the Frame Register field in the UNWIND\_INFO is zero, this offset is from RSP. If the Frame Register field is nonzero, this offset is from where RSP was located when the FP register was established. It equals the FP register minus the FP register offset (16 \* the scaled frame register offset in the UNWIND\_INFO). If an FP register is used, then any unwind code taking an offset must only be used after the FP register is established in the prolog.

For all opcodes except `UWOP_SAVE_XMM128` and `UWOP_SAVE_XMM128_FAR`, the offset is always a multiple of 8, because all stack values of interest are stored on 8-byte boundaries (the stack itself is always 16-byte aligned). For operation codes that take a short offset (less than 512K), the final USHORT in the nodes for this code holds the offset divided by 8. For operation codes that take a long offset (512K <= offset < 4GB), the final two USHORT nodes for this code hold the offset (in little-endian format).

For the opcodes `UWOP_SAVE_XMM128` and `UWOP_SAVE_XMM128_FAR`, the offset is always a multiple of 16, since all 128-bit XMM operations must occur on 16-byte aligned memory. Therefore, a scale factor of 16 is used for `UWOP_SAVE_XMM128`, permitting offsets of less than 1M.

The unwind operation code is one of these values:

*   `UWOP_PUSH_NONVOL` (0) 1 node
    
    Push a nonvolatile integer register, decrementing RSP by 8. The operation info is the number of the register. Because of the constraints on epilogs, `UWOP_PUSH_NONVOL` unwind codes must appear first in the prolog and correspondingly, last in the unwind code array. This relative ordering applies to all other unwind codes except `UWOP_PUSH_MACHFRAME`.
    
*   `UWOP_ALLOC_LARGE` (1) 2 or 3 nodes
    
    Allocate a large-sized area on the stack. There are two forms. If the operation info equals 0, then the size of the allocation divided by 8 is recorded in the next slot, allowing an allocation up to 512K - 8. If the operation info equals 1, then the unscaled size of the allocation is recorded in the next two slots in little-endian format, allowing allocations up to 4GB - 8.
    
*   `UWOP_ALLOC_SMALL` (2) 1 node
    
    Allocate a small-sized area on the stack. The size of the allocation is the operation info field \* 8 + 8, allowing allocations from 8 to 128 bytes.
    
    The unwind code for a stack allocation should always use the shortest possible encoding:
    
    Expand table
    
    **Allocation Size**
    
    **Unwind Code**
    
    8 to 128 bytes
    
    `UWOP_ALLOC_SMALL`
    
    136 to 512K-8 bytes
    
    `UWOP_ALLOC_LARGE`, operation info = 0
    
    512K to 4G-8 bytes
    
    `UWOP_ALLOC_LARGE`, operation info = 1
    
*   `UWOP_SET_FPREG` (3) 1 node
    
    Establish the frame pointer register by setting the register to some offset of the current RSP. The offset is equal to the Frame Register offset (scaled) field in the UNWIND\_INFO \* 16, allowing offsets from 0 to 240. The use of an offset permits establishing a frame pointer that points to the middle of the fixed stack allocation, helping code density by allowing more accesses to use short instruction forms. The operation info field is reserved and shouldn't be used.
    
*   `UWOP_SAVE_NONVOL` (4) 2 nodes
    
    Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is primarily used for _shrink-wrapping_, where a nonvolatile register is saved to the stack in a position that was previously allocated. The operation info is the number of the register. The scaled-by-8 stack offset is recorded in the next unwind operation code slot, as described in the note above.
    
*   `UWOP_SAVE_NONVOL_FAR` (5) 3 nodes
    
    Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH. This code is primarily used for _shrink-wrapping_, where a nonvolatile register is saved to the stack in a position that was previously allocated. The operation info is the number of the register. The unscaled stack offset is recorded in the next two unwind operation code slots, as described in the note above.
    
*   `UWOP_SAVE_XMM128` (8) 2 nodes
    
    Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of the register. The scaled-by-16 stack offset is recorded in the next slot.
    
*   `UWOP_SAVE_XMM128_FAR` (9) 3 nodes
    
    Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info is the number of the register. The unscaled stack offset is recorded in the next two slots.
    
*   `UWOP_PUSH_MACHFRAME` (10) 1 node
    
    Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception. There are two forms. If the operation info equals 0, one of these frames has been pushed on the stack:
    
    Expand table
    
    Location
    
    Value
    
    RSP+32
    
    SS
    
    RSP+24
    
    Old RSP
    
    RSP+16
    
    EFLAGS
    
    RSP+8
    
    CS
    
    RSP
    
    RIP
    
    If the operation info equals 1, then one of these frames has been pushed:
    
    Expand table
    
    Location
    
    Value
    
    RSP+40
    
    SS
    
    RSP+32
    
    Old RSP
    
    RSP+24
    
    EFLAGS
    
    RSP+16
    
    CS
    
    RSP+8
    
    RIP
    
    RSP
    
    Error code
    
    This unwind code always appears in a dummy prolog, which is never actually executed, but instead appears before the real entry point of an interrupt routine, and exists only to provide a place to simulate the push of a machine frame. `UWOP_PUSH_MACHFRAME` records that simulation, which indicates the machine has conceptually done this operation:
    
    1.  Pop RIP return address from top of stack into _Temp_
        
    2.  Push SS
        
    3.  Push old RSP
        
    4.  Push EFLAGS
        
    5.  Push CS
        
    6.  Push _Temp_
        
    7.  Push Error Code (if op info equals 1)
        
    
    The simulated `UWOP_PUSH_MACHFRAME` operation decrements RSP by 40 (op info equals 0) or 48 (op info equals 1).
    

[](#operation-info)

#### Operation info

The meaning of the operation info bits depends upon the operation code. To encode a general-purpose (integer) register, this mapping is used:

Expand table

Bit

Register

0

RAX

1

RCX

2

RDX

3

RBX

4

RSP

5

RBP

6

RSI

7

RDI

8 to 15

R8 to R15

[](#chained-unwind-info-structures)

### Chained unwind info structures

If the UNW\_FLAG\_CHAININFO flag is set, then an unwind info structure is a secondary one, and the shared exception-handler/chained-info address field contains the primary unwind information. This sample code retrieves the primary unwind information, assuming that `unwindInfo` is the structure that has the UNW\_FLAG\_CHAININFO flag set.

C++ Copy

    PRUNTIME_FUNCTION primaryUwindInfo = (PRUNTIME_FUNCTION)&(unwindInfo->UnwindCode[( unwindInfo->CountOfCodes + 1 ) & ~1]);
    

Chained info is useful in two situations. First, it can be used for noncontiguous code segments. By using chained info, you can reduce the size of the required unwind information, because you do not have to duplicate the unwind codes array from the primary unwind info.

You can also use chained info to group volatile register saves. The compiler may delay saving some volatile registers until it is outside of the function entry prolog. You can record them by having primary unwind info for the portion of the function before the grouped code, and then setting up chained info with a non-zero size of prolog, where the unwind codes in the chained info reflect saves of the nonvolatile registers. In that case, the unwind codes are all instances of UWOP\_SAVE\_NONVOL. A grouping that saves nonvolatile registers by using a PUSH or modifies the RSP register by using an additional fixed stack allocation is not supported.

An UNWIND\_INFO item that has UNW\_FLAG\_CHAININFO set can contain a RUNTIME\_FUNCTION entry whose UNWIND\_INFO item also has UNW\_FLAG\_CHAININFO set, sometimes called _multiple shrink-wrapping_. Eventually, the chained unwind info pointers arrive at an UNWIND\_INFO item that has UNW\_FLAG\_CHAININFO cleared. This item is the primary UNWIND\_INFO item, which points to the actual procedure entry point.

[](#unwind-procedure)

Unwind procedure
----------------

The unwind code array is sorted into descending order. When an exception occurs, the complete context is stored by the operating system in a context record. The exception dispatch logic is then invoked, which repeatedly executes these steps to find an exception handler:

1.  Use the current RIP stored in the context record to search for a RUNTIME\_FUNCTION table entry that describes the current function (or function portion, for chained UNWIND\_INFO entries).
    
2.  If no function table entry is found, then it's in a leaf function, and RSP directly addresses the return pointer. The return pointer at \[RSP\] is stored in the updated context, the simulated RSP is incremented by 8, and step 1 is repeated.
    
3.  If a function table entry is found, RIP can lie within three regions: a) in an epilog, b) in the prolog, or c) in code that may be covered by an exception handler.
    
    *   Case a) If the RIP is within an epilog, then control is leaving the function, there can be no exception handler associated with this exception for this function, and the effects of the epilog must be continued to compute the context of the caller function. To determine if the RIP is within an epilog, the code stream from RIP onward is examined. If that code stream can be matched to the trailing portion of a legitimate epilog, then it's in an epilog, and the remaining portion of the epilog is simulated, with the context record updated as each instruction is processed. After this processing, step 1 is repeated.
        
    *   Case b) If the RIP lies within the prologue, then control hasn't entered the function, there can be no exception handler associated with this exception for this function, and the effects of the prolog must be undone to compute the context of the caller function. The RIP is within the prolog if the distance from the function start to the RIP is less than or equal to the prolog size encoded in the unwind info. The effects of the prolog are unwound by scanning forward through the unwind codes array for the first entry with an offset less than or equal to the offset of the RIP from the function start, then undoing the effect of all remaining items in the unwind code array. Step 1 is then repeated.
        
    *   Case c) If the RIP isn't within a prolog or epilog, and the function has an exception handler (UNW\_FLAG\_EHANDLER is set), then the language-specific handler is called. The handler scans its data and calls filter functions as appropriate. The language-specific handler can return that the exception was handled or that the search is to be continued. It can also initiate an unwind directly.
        
4.  If the language-specific handler returns a handled status, then execution is continued using the original context record.
    
5.  If there's no language-specific handler or the handler returns a "continue search" status, then the context record must be unwound to the state of the caller. It's done by processing all of the unwind code array elements, undoing the effect of each. Step 1 is then repeated.
    

When chained unwind info is involved, these basic steps are still followed. The only difference is that, while walking the unwind code array to unwind a prolog's effects, once the end of the array is reached, it's then linked to the parent unwind info and the entire unwind code array found there is walked. This linking continues until arriving at an unwind info without the UNW\_CHAINED\_INFO flag, and then it finishes walking its unwind code array.

The smallest set of unwind data is 8 bytes. This would represent a function that only allocated 128 bytes of stack or less, and possibly saved one nonvolatile register. It's also the size of a chained unwind info structure for a zero-length prolog with no unwind codes.

[](#language-specific-handler)

Language-specific handler
-------------------------

The relative address of the language-specific handler is present in the UNWIND\_INFO whenever flags UNW\_FLAG\_EHANDLER or UNW\_FLAG\_UHANDLER are set. As described in the previous section, the language-specific handler is called as part of the search for an exception handler or as part of an unwind. It has this prototype:

C++ Copy

    typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
        IN PEXCEPTION_RECORD ExceptionRecord,
        IN ULONG64 EstablisherFrame,
        IN OUT PCONTEXT ContextRecord,
        IN OUT PDISPATCHER_CONTEXT DispatcherContext
    );
    

**ExceptionRecord** supplies a pointer to an exception record, which has the standard Win64 definition.

**EstablisherFrame** is the address of the base of the fixed stack allocation for this function.

**ContextRecord** points to the exception context at the time the exception was raised (in the exception handler case) or the current "unwind" context (in the termination handler case).

**DispatcherContext** points to the dispatcher context for this function. It has this definition:

C++ Copy

    typedef struct _DISPATCHER_CONTEXT {
        ULONG64 ControlPc;
        ULONG64 ImageBase;
        PRUNTIME_FUNCTION FunctionEntry;
        ULONG64 EstablisherFrame;
        ULONG64 TargetIp;
        PCONTEXT ContextRecord;
        PEXCEPTION_ROUTINE LanguageHandler;
        PVOID HandlerData;
    } DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;
    

**ControlPc** is the value of RIP within this function. This value is either an exception address or the address at which control left the establishing function. The RIP is used to determine if control is within some guarded construct inside this function, for example, a **`__try`** block for **`__try`**/**`__except`** or **`__try`**/**`__finally`**.

**ImageBase** is the image base (load address) of the module containing this function, to be added to the 32-bit offsets used in the function entry and unwind info to record relative addresses.

**FunctionEntry** supplies a pointer to the RUNTIME\_FUNCTION function entry holding the function and unwind info image-base relative addresses for this function.

**EstablisherFrame** is the address of the base of the fixed stack allocation for this function.

**TargetIp** Supplies an optional instruction address that specifies the continuation address of the unwind. This address is ignored if **EstablisherFrame** isn't specified.

**ContextRecord** points to the exception context, for use by the system exception dispatch/unwind code.

**LanguageHandler** points to the language-specific language handler routine being called.

**HandlerData** points to the language-specific handler data for this function.

[](#unwind-helpers-for-masm)

Unwind helpers for MASM
-----------------------

In order to write proper assembly routines, there's a set of pseudo-operations that can be used in parallel with the actual assembly instructions to create the appropriate .pdata and .xdata. And, there's a set of macros that provide simplified use of the pseudo-operations for their most common uses.

[](#raw-pseudo-operations)

### Raw pseudo-operations

Expand table

Pseudo operation

Description

PROC FRAME \[:_ehandler_\]

Causes MASM to generate a function table entry in .pdata and unwind information in .xdata for a function's structured exception handling unwind behavior. If _ehandler_ is present, this proc is entered in the .xdata as the language-specific handler.  
  
When the FRAME attribute is used, it must be followed by an .ENDPROLOG directive. If the function is a leaf function (as defined in [Function types](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170#function-types)) the FRAME attribute is unnecessary, as are the remainder of these pseudo-operations.

.PUSHREG _register_

Generates a UWOP\_PUSH\_NONVOL unwind code entry for the specified register number using the current offset in the prologue.  
  
Only use it with nonvolatile integer registers. For pushes of volatile registers, use an .ALLOCSTACK 8, instead

.SETFRAME _register_, _offset_

Fills in the frame register field and offset in the unwind information using the specified register and offset. The offset must be a multiple of 16 and less than or equal to 240. This directive also generates a UWOP\_SET\_FPREG unwind code entry for the specified register using the current prologue offset.

.ALLOCSTACK _size_

Generates a UWOP\_ALLOC\_SMALL or a UWOP\_ALLOC\_LARGE with the specified size for the current offset in the prologue.  
  
The _size_ operand must be a multiple of 8.

.SAVEREG _register_, _offset_

Generates either a UWOP\_SAVE\_NONVOL or a UWOP\_SAVE\_NONVOL\_FAR unwind code entry for the specified register and offset using the current prologue offset. MASM chooses the most efficient encoding.  
  
_offset_ must be positive, and a multiple of 8. _offset_ is relative to the base of the procedure's frame, which is generally in RSP, or, if using a frame pointer, the unscaled frame pointer.

.SAVEXMM128 _register_, _offset_

Generates either a UWOP\_SAVE\_XMM128 or a UWOP\_SAVE\_XMM128\_FAR unwind code entry for the specified XMM register and offset using the current prologue offset. MASM chooses the most efficient encoding.  
  
_offset_ must be positive, and a multiple of 16. _offset_ is relative to the base of the procedure's frame, which is generally in RSP, or, if using a frame pointer, the unscaled frame pointer.

.PUSHFRAME \[_code_\]

Generates a UWOP\_PUSH\_MACHFRAME unwind code entry. If the optional _code_ is specified, the unwind code entry is given a modifier of 1. Otherwise the modifier is 0.

.ENDPROLOG

Signals the end of the prologue declarations. Must occur in the first 255 bytes of the function.

Here's a sample function prolog with proper usage of most of the opcodes:

MASM Copy

    sample PROC FRAME
        db      048h; emit a REX prefix, to enable hot-patching
        push rbp
        .pushreg rbp
        sub rsp, 040h
        .allocstack 040h
        lea rbp, [rsp+020h]
        .setframe rbp, 020h
        movdqa [rbp], xmm7
        .savexmm128 xmm7, 020h ;the offset is from the base of the frame
                               ;not the scaled offset of the frame
        mov [rbp+018h], rsi
        .savereg rsi, 038h
        mov [rsp+010h], rdi
        .savereg rdi, 010h ; you can still use RSP as the base of the frame
                           ; or any other register you choose
        .endprolog
    
    ; you can modify the stack pointer outside of the prologue (similar to alloca)
    ; because we have a frame pointer.
    ; if we didn't have a frame pointer, this would be illegal
    ; if we didn't make this modification,
    ; there would be no need for a frame pointer
    
        sub rsp, 060h
    
    ; we can unwind from the next AV because of the frame pointer
    
        mov rax, 0
        mov rax, [rax] ; AV!
    
    ; restore the registers that weren't saved with a push
    ; this isn't part of the official epilog, as described in section 2.5
    
        movdqa xmm7, [rbp]
        mov rsi, [rbp+018h]
        mov rdi, [rbp-010h]
    
    ; Here's the official epilog
    
        lea rsp, [rbp+020h] ; deallocate both fixed and dynamic portions of the frame
        pop rbp
        ret
    sample ENDP
    

For more information about the epilog example, see [Epilog code](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170#epilog-code) in [x64 prolog and epilog](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170).

[](#masm-macros)

### MASM macros

In order to simplify the use of the [Raw pseudo-operations](#raw-pseudo-operations), there's a set of macros, defined in ksamd64.inc, which can be used to create typical procedure prologues and epilogues.

Expand table

Macro

Description

alloc\_stack(n)

Allocates a stack frame of n bytes (using `sub rsp, n`), and emits the appropriate unwind information (.allocstack n)

save\_reg _reg_, _loc_

Saves a nonvolatile register _reg_ on the stack at RSP offset _loc_, and emits the appropriate unwind information. (.savereg reg, loc)

push\_reg _reg_

Pushes a nonvolatile register _reg_ on the stack, and emits the appropriate unwind information. (.pushreg reg)

rex\_push\_reg _reg_

Saves a nonvolatile register on the stack using a 2-byte push, and emits the appropriate unwind information (.pushreg reg). Use this macro if the push is the first instruction in the function, to ensure that the function is hot-patchable.

save\_xmm128 _reg_, _loc_

Saves a nonvolatile XMM register _reg_ on the stack at RSP offset _loc_, and emits the appropriate unwind information (.savexmm128 reg, loc)

set\_frame _reg_, _offset_

Sets the frame register _reg_ to be the RSP + _offset_ (using a `mov`, or an `lea`), and emits the appropriate unwind information (.set\_frame reg, offset)

push\_eflags

Pushes the eflags with a `pushfq` instruction, and emits the appropriate unwind information (.alloc\_stack 8)

Here's a sample function prolog with proper usage of the macros:

MASM Copy

    sampleFrame struct
        Fill     dq ?; fill to 8 mod 16
        SavedRdi dq ?; Saved Register RDI
        SavedRsi dq ?; Saved Register RSI
    sampleFrame ends
    
    sample2 PROC FRAME
        alloc_stack(sizeof sampleFrame)
        save_reg rdi, sampleFrame.SavedRdi
        save_reg rsi, sampleFrame.SavedRsi
        .end_prolog
    
    ; function body
    
        mov rsi, sampleFrame.SavedRsi[rsp]
        mov rdi, sampleFrame.SavedRdi[rsp]
    
    ; Here's the official epilog
    
        add rsp, (sizeof sampleFrame)
        ret
    sample2 ENDP
    

[](#unwind-data-definitions-in-c)

Unwind data definitions in C
----------------------------

Here's a C description of the unwind data:

C Copy

    typedef enum _UNWIND_OP_CODES {
        UWOP_PUSH_NONVOL = 0, /* info == register number */
        UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
        UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
        UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
        UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
        UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
        UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
        UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
        UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
    } UNWIND_CODE_OPS;
    
    typedef unsigned char UBYTE;
    
    typedef union _UNWIND_CODE {
        struct {
            UBYTE CodeOffset;
            UBYTE UnwindOp : 4;
            UBYTE OpInfo   : 4;
        };
        USHORT FrameOffset;
    } UNWIND_CODE, *PUNWIND_CODE;
    
    #define UNW_FLAG_EHANDLER  0x01
    #define UNW_FLAG_UHANDLER  0x02
    #define UNW_FLAG_CHAININFO 0x04
    
    typedef struct _UNWIND_INFO {
        UBYTE Version       : 3;
        UBYTE Flags         : 5;
        UBYTE SizeOfProlog;
        UBYTE CountOfCodes;
        UBYTE FrameRegister : 4;
        UBYTE FrameOffset   : 4;
        UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
    } UNWIND_INFO, *PUNWIND_INFO;
    
    typedef struct _RUNTIME_FUNCTION {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG UnwindData;
    } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
    
    #define GetUnwindCodeEntry(info, index) \
        ((info)->UnwindCode[index])
    
    #define GetLanguageSpecificDataPtr(info) \
        ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))
    
    #define GetExceptionHandler(base, info) \
        ((PEXCEPTION_HANDLER)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))
    
    #define GetChainedFunctionEntry(base, info) \
        ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))
    
    #define GetExceptionDataPtr(info) \
        ((PVOID)((PULONG)GetLanguageSpecificData(info) + 1))
    
