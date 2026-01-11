
**Exceptional Behavior - x64 Structured Exception Handling**  
The NT Insider, Vol 13, Issue 3, May - June 2006 | Published: 23-May-06| Modified: 23-May-06  

If you've been working in kernel-mode on Windows for any significant amount of time, you've almost certainly encountered Structured Exception Handling (SEH). Basically, SEH is the standard kernel-mode exception handling mechanism that's built into Windows. Because support within the O/S with no way to access it doesn't make much sense, Microsoft compilers provide access to the O/S's exception support via the **\_\_try** and **\_\_except** keywords.

To make SEH work, cooperating support must be provided by the compiler, hardware, and OS. Precisely _how_ SEH is implemented on a particular platform can vary based on architecture. Information on how SEH is implemented on the x86 is readily available. In fact, it's likely that you've stumbled upon a variation of this construct at least once while stepping through assembly code in the debugger:

 push    0x17708  
 push    0x173f4  
 mov     eax,fs:\[00000000\]  
 push    eax  
 mov     fs:\[00000000\],esp

Once you see a sequence like this, it's a clear tip-off that the function uses SEH. It's also possible to use this information to locate all of the possible exception handlers within the routine.

In debugging driver code on the x64, I noticed that I _never_ saw those telltale sequences, I couldn't help wondering what was going on.  How _does_ Windows implement exception handling on the x64?

**Huh?**  
If you're already confused, then this article might not be for you. To get up to speed on how x86 exception handling is implemented, I recommend reading ["A Crash Course on the Depths of Win32 Structured Exception Handling"](http://www.microsoft.com/msj/0197/exception/exception.aspx) by Matt Pietrek, which appeared in the January 1997 issue of the _Microsoft Systems Journal_. While understanding how x86 exception handling is implemented isn't absolutely necessary to understand this article, it provides a good starting point to understand the differences between x86 exception handling and the x64 implementation.

**x64 - A Chance to Trim the Fat**  
Because on the x86 each function that uses SEH has this aforementioned construct as part of its prolog, the x86 is said to use _frame based exception handling_. There are a couple of problems with this approach:

1.  Because the exception information is stored on the stack, it is susceptible to buffer overflow attacks.
    
2.  Overhead. Exceptions are, well, exceptional, which means the exception will not occur in the common case. Regardless, every time a function is entered that uses SEH, these extra instructions are executed.
    

Because the x64 was a chance to do away with a lot of the cruft that had been hanging around for decades, SEH got an overhaul that addressed both issues mentioned above. On the x64, SEH has become _table-based_, which means when the source code is compiled, a table is created that fully describes all the exception handling code within the module. This table is then stored as part of the PE header. If an exception occurs, the exception table is parsed by Windows to find the appropriate exception handler to execute. Because exception handling information is tucked safely away in the PE header, it is no longer susceptible to buffer overflow attacks. In addition, because the exception table is generated as part of the compilation process, no runtime overhead (in the form of **push** and **pop** instructions) is incurred during normal processing.

Of course, table-based exception handling schemes have a couple of negative aspects of their own. For example, table-based schemes tend to take more space in memory than stack-based schemes. Also, while overhead in the normal execution path is reduced, the overhead it takes to process an exception is significantly higher than in frame-based approaches. Like everything in life, there are trade-offs to consider when evaluating whether the table-based or a frame-based approach to exception handling is "best."

**Seeing It for Yourself**  
So, how is table-based exception handling implemented on the x64? It just so happens that all of the data structures and functions involved in SEH on the x64 are documented as part of the SDK. Not uncharacteristically, the documentation tends to be a bit terse, and at times it only provides structure definitions. This article explores this information in a more practical manner.

**Exception Directory and RUNTIME\_FUNCTIONs**  
Within a PE image there are various _directories_ that contain information about the image. For example, if the image has any exports, there will be an export directory that describes the exports. In the case of an x64 image, there happens to be an _exception_ directory that contains a variable number of **RUNTIME\_FUNCTION** structures, listed below:

  
 typedef struct \_RUNTIME\_FUNCTION {  
     ULONG BeginAddress;  
     ULONG EndAddress;  
     ULONG UnwindData;  
 } RUNTIME\_FUNCTION, \*PRUNTIME\_FUNCTION;

Note the use of **ULONG**s for addresses even though we're talking about a 64-bit architecture. This is because the values contained in the structure are offsets from the base of the image and not addresses or pointers. Now let's describe each field in turn.

**_BeginAddress_** - This value represents an offset into the image where some bit of code of interest to SEH begins. This is an incredibly vague description that will (hopefully) become clearer as we move along.

**_EndAddress_** - This value represents an offset into the image where some bit of code of interest to SEH ends. This is an incredibly vague description that will (hopefully) become clearer as we move along.

**_UnwindData_** - This value is an offset from the base of the image to an UNWIND\_INFO structure that describes _why_ the bit of code encompassed in the _BeginAddress_ and _EndAddress_ is of interest. The UNWIND\_INFO structure is defined in _Figure 1_.

#define UNW\_FLAG\_NHANDLER 0x0  
#define UNW\_FLAG\_EHANDLER 0x1  
#define UNW\_FLAG\_UHANDLER 0x2  
#define UNW\_FLAG\_CHAININFO 0x4

typedef struct \_UNWIND\_INFO {  
    UBYTE Version         : 3;  
    UBYTE Flags           : 5;  
    UBYTE SizeOfProlog;  
    UBYTE CountOfCodes;  
    UBYTE FrameRegister  : 4;  
    UBYTE FrameOffset    : 4;  
    UNWIND\_CODE UnwindCode\[1\];  
    union {  
        //  
        // If (Flags & UNW\_FLAG\_EHANDLER)  
        //  
        OPTIONAL ULONG ExceptionHandler;  
        //  
        // Else if (Flags & UNW\_FLAG\_CHAININFO)  
        //  
        OPTIONAL ULONG FunctionEntry;  
    };  
    //  
    // If (Flags & UNW\_FLAG\_EHANDLER)  
    //  
    OPTIONAL ULONG ExceptionData\[\];  
} UNWIND\_INFO, \*PUNWIND\_INFO;

  
**Figure 1 - UNWIND\_INFO Structure**

For the sake of brevity (and actually achieving something with this article) I'm going to limit the scope of our discussion to **UNWIND\_INFO** structures that describe exception handlers, which are those that have the **UNW\_FLAG\_EHANDLER** bit set. So called "unwind handlers" and "chained handlers" are going to have to wait for a later issue.

So, where was I...Oh, that's right...If the _UnwindData_ has the **UNW\_FLAG\_EHANDLER** bit set, then the _BeginAddress_ and _EndAddress_ fields of the **RUNTIME\_FUNCTION** describe the location of a function in the image that uses SEH. The _UnwindData_ structure then is going to describe all the places where the **\_\_try** keyword appears in the function, their associated exception handlers (a.k.a. exception _filters_), and the location of the code contained in the **\_\_except** block. Be sure to note the distinction between the exception handler and the exception block itself - the handler determines if the **\_\_except** block is executed or not.

The two members of the **UNWIND\_INFO** structure that relate directly to exception handling are _ExceptionHandler_ and _ExceptionData_. So, next we'll look at these two in a bit more detail. Incidentally, the _CountOfCodes_ and _UnwindCode_ array are also important and interesting, but, again, that's fodder for another article.

**Yes! More Data Structures  
**When the **UNW\_FLAG\_EHANDLER** bit is set, the _ExceptionHandler_ field of the **UNWIND\_INFO** structure is assumed to be valid. This field is filled in by the compiler and says, "Hey, you, O/S! If an exception ever occurs and the instruction pointer is >= _BeginAddress_ and < _EndAddress, call this handler!"_ This generic exception handler, currently implemented as **\_C\_specific\_handler**, is then responsible for figuring out exactly what to do with this exception. It does this by parsing the _ExceptionData_.

On the x64, the _ExceptionData_ is actually an offset to a pointer to a **SCOPE\_TABLE** structure (defined in ntx64.h in build 5308 of the Windows Driver Kit):

 typedef struct \_SCOPE\_TABLE {  
     ULONG Count;  
     struct  
     {  
         ULONG BeginAddress;  
         ULONG EndAddress;  
         ULONG HandlerAddress;  
         ULONG JumpTarget;  
     } ScopeRecord\[1\];  
 } SCOPE\_TABLE, \*PSCOPE\_TABLE;

As you can see, this is a variable length structure containing a count followed by _Count_ "scope records". While the **RUNTIME\_FUNCTION** describes the entire range of a function that contains SEH, the **SCOPE\_TABLE** describes each of the individual **\_\_try**/**\_\_except** blocks within the function. Let's check out each of the fields of the scope record in turn:

**_BeginAddress_** - This value indicates the offset of the first instruction within a **\_\_try** block located in the function.

_**EndAddress**_ - This value indicates the offset to the instruction after the last instruction within the **\_\_try** block (conceptually the **\_\_except** statement).

**_HandlerAddress_** - This value indicates the offset to the function located within the parentheses of the **\_\_except()** statement. In the documentation you'll find this routine called the "exception handler" or "exception filter".

If the code in question specifies the predefined handler **EXCEPTION\_EXECUTE\_HANDLER**, this value may simply be "1" (i.e. the value of **EXCEPTION\_EXECUTE\_HANDLER**).

**_JumpTarget_** \- This value indicates the offset to the first instruction in the **\_\_except** block associated with the **\_\_try** block.  

**The Result**  
Putting all of the foregoing info together, _Figure 2_ shows the data structure that we're going to be dealing with for the remainder of the article.

![](images/default/articles/469/Picture10.gif)

**Figure 2 - RUNTIME\_FUNCTION with UNW\_FLAG\_EHANDLER FUNCTION Set**

**Example**  
Checking out an example of how this all fits together should help clear up what the structures that we've seen so far represent. Consider this function:

VOID  
FrobThePointer(  
 PUCHAR UserAddress  
 ) {  
 \_\_try {  
        \*UserAddress = 0;  
               \*UserAddress = 1;  
 } \_\_except (EXCEPTION\_EXECUTE\_HANDLER) {  
        DbgPrint("Bad Address\\n");  
 }  
}

Using instruction address zero as the base, the resulting assembly looks something like what you see in _Figure 3_.

<00> mov     \[rsp+0x8\],rcx  
<05> sub     rsp,0x28  
<09> mov     rax,\[rsp+0x30\]        // Move UserAddress into RAX  
<0e> mov     byte ptr \[rax\],0x0    // \*UserAddress = 0;  
<11> mov     rax,\[rsp+0x30\]        // Move UserAddress into RAX  
<16> mov     byte ptr \[rax\],0x1    // \*UserAddress = 1;  
<19> jmp     FrobThePointer+0x28   // Success!  
<1b> lea     rcx,"Bad Address\\n"   // Begin of code in except block...  
                                             //  prepare to DbgPrint  
<22> call    DbgPrint  
<27> nop  
<28> add     rsp,0x28  
<2c> ret

**Figure 3 - Assembly of FrobThePointer**

During the compilation process, the **RUNTIME\_FUNCTION** (See _Figure 4_) would be put into the exception directory of the driver's PE header. Note that the numbers here are again based on the previous, zero based example for clarity.

**![](images/default/articles/469/Picture11.gif)**

**Figure 4 - RUNTIME\_FUNCTION for FrobThePointer**

As you can see, this structure fully describes the SEH used within this function. By looking at the **SCOPE\_TABLE** we know that:

1.  There is one **\_\_try**/**\_\_except** block in this function.
    
2.  The **\_\_try** block begins at address 0x9 and ends at 0x1b.
    
3.  The developer provided the default exception filter of **EXCEPTION\_EXECUTE\_HANDLER**, meaning always call the **\_\_except** block.
    
4.  The **\_\_except** block can be found at address 0x1b.
    

If an exception occurs while dereferencing one of the pointers within the **\_\_try** block, the function **\_C\_specific\_handler** will be called and will begin parsing the _ExceptionData_. Once **\_C\_specific\_handler** finds a scope record that covers the faulting instruction, it knows exactly where the exception handler and code for the **\_\_except** block reside.

**More About \_C\_specific\_handler  
**Now let's take all of the info we've collected to put together the pseudo code for **\_C\_specific\_handler** in _Figure 5_. Earlier I mentioned that the _ExceptionHandler_ in the **RUNTIME\_FUNCTION** is the compiler telling the O/S what to call if an exception is raised while executing the function. Once the exception is raised by the processor, the standard exception handling mechanism in Windows will find the **RUNTIME\_FUNCTION** for the offending instruction pointer and call the _ExceptionHandler_. This will always result in a call to **\_C\_specific\_handler** for kernel-mode code running on current versions of Windows. **\_C\_specific\_handler** will then begin walking all of the **SCOPE\_TABLE** entries searching for a match on the faulting instruction, and will hopefully find an **\_\_except** statement that covers the offending code.

\_C\_specific\_handler {

       scopeTable = UwindData->ExceptionData;  
       For (index = 0; index < scopeTable->Count; index++)  
scopeRecord = scopeTable->ScopeRecord\[i\];  
               If (FaultingInstruction >= scopeRecord->BeginAddress &&  
                   FaultingInstruction < scopeRecord->EndAddress) {  
     
                      If (scopeRecord->HandlerAddress != 1) {  
                             callExceptHandler = (\*scopeRecord->HandlerAddress)();  
                      } else {  
                             callExceptHandler = TRUE;  
                      }  
   
                      If (callExceptHandler) {  
                             (\*scopeRecord->JumpTarget)();  
                      }  
               }  
       }  
} 

**Figure 5 - Pseudo-code for \_C\_specific\_handler**

**Wanna Know More?**  
If you're dying to know more, all this information is readily available through your favorite debugger. Simply pass the function of interest to the **.fnent** command and all that's left is parsing the **UNWIND\_INFO** structure. Also, don't forget this is fully documented in the SDK, along with various functions and structure definitions to make your spelunking that much more enjoyable.

[Tweet](http://twitter.com/share)

**Related Articles**  
[Inlining into SEH Filters Can Result in Invalid Code on AMD64](article.cfm^article=301.htm)  
[ExAllocatePoolWithQuota Raises Exceptions](article.cfm^article=305.htm)  
[Only Signed Drivers To Run on Vista X64](article.cfm^article=435.htm)  
[Take Two - x64 Driver Signing](article.cfm^article=465.htm)  
[Just Sign Everything - What to Sign and How to Sign It for Vista](article.cfm^article=466.htm)  
[x64 Driver Signing as of Vista RC1 (and later)](article.cfm^article=476.htm)  
