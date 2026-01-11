Ryūjin - Writing a Bin2Bin Obfuscator from Scratch for Windows PE x64 and Fully Deobfuscating It
================================================================================================

14/11/2025

117 minutes

23220 words

#reverse

#engineering

#windows

#x64

#bin2bin

#protector

#virtualization

#obfuscation

Author: João Vitor (@Keowu) - Security Researcher

Introduction
------------

With this article we will fully understand how commercial protection tools known as Bin2Bin work, from their internal structure to concepts about how a PE file is laid out. We will also see how to obtain an opcode sequence produced by any compiler (in this article, MSVC), disassemble it, split it into individual procedures and build properly structured basic blocks. From there, we will learn to generate fully modified code, implement a mutation algorithm and even add support for creating custom passes.

In addition, we will cover and implement common techniques used in this kind of technology, such as simple or advanced code virtualization (combining a code VM running inside a virtual machine with Microsoft's hypervisor APIs), anti-debug, IAT protection and crypter functions. We will also cover fundamental memory concepts, for example how relocations work, allowing code to be moved from one place to another while maintaining compatibility.

All of this aims to build, from scratch, the essential foundation for full mastery of Bin2Bin obfuscation and virtualization tools. This article will serve as a guide for anyone who wants to understand how projects similar to Ryūjin work under the hood, so you start seeing obfuscators in a different light. That knowledge will be highly useful, not only to write your own obfuscation tool but also to deobfuscate them more simply and effectively.

![#0](/posts/images/2025-11-14/intro.png)

Table of Contents
-----------------

1.  [Introduction](#introduction)
2.  [Our Usual Prelude](#our-usual-prelude)
3.  [Understanding Bin2Bin](#understanding-bin2bin)
    *   [Bin2Bin 101](#bin2bin-101)
    *   [PE Format, Disassemblers and Assemblers](#pe-format-disassemblers-and-assemblers)
        *   [PE Format](#pe-format)
    *   [Disassemblers, Assemblers, Basic Blocks & Obfuscation](#disassemblers-assemblers-basic-blocks--obfuscation-passes)
4.  [Ryūjin - Deep into the Bin2Bin Dracco](#ryujin---deep-into-the-bin2bin-dracco)
    *   [Architecting Ryūjin](#architecting-ryujin)
    *   [Ryūjin Core](#ryujin-core)
        *   [RyujinObfuscatorConfig](#ryujinobfuscatorconfig)
        *   [RunRyujinCore Export](#runryujincore-export)
        *   [Ryujin Class](#ryujin-class)
        *   [Ryujin Constructor](#ryujin-constructor)
        *   [Ryujin Run](#ryujin-run)
        *   [RyujinBasicBlockerBuilder](#ryujinbasicblockerbuilder)
        *   [RyujinBasicBlockerBuilder Constructor](#ryujinbasicblockerbuilder-constructor)
        *   [RyujinBasicBlockerBuilder createBasicBlocks](#ryujinbasicblockerbuilder-createbasicblocks)
        *   [RyujinObfuscationCore](#ryujinobfuscationcore)
        *   [RyujinObfuscationCore Constructor](#ryujinobfuscationcore-constructor)
            *   [extractUnusedRegisters](#extractunusedregisters)
        *   [RyujinObfuscationCore Run](#ryujinobfuscationcore-run)
            *   [addPaddingSpaces](#addpaddingspaces)
            *   [RyujinRunOncePass](#ryujinrunoncepass)
            *   [RyujinObfuscationCore -> RyujinRunOncePass -> insertAntiDump](#ryujinobfuscationcore---ryujinrunoncepass---insertantidump)
            *   [RyujinObfuscationCore -> RyujinRunOncePass -> insertMemoryProtection](#ryujinobfuscationcore---ryujinrunoncepass---insertmemoryprotection)
            *   [RyujinObfuscationCore -> Normal Pass -> insertAntiDebug](#ryujinobfuscationcore---normal-pass---insertantidebug)
            *   [RyujinObfuscationCore -> Normal Pass -> insertVirtualization](#ryujinobfuscationcore---normal-pass---insertvirtualization)
            *   [RyujinObfuscationCore -> Normal Pass -> obfuscateIat](#ryujinobfuscationcore---normal-pass---obfuscateiat)
            *   [RyujinObfuscationCore -> Normal Pass -> insertJunkCode](#ryujinobfuscationcore---normal-pass---insertjunkcode)
            *   [RyujinObfuscationCore -> Normal Pass -> Custom Passes](#ryujinobfuscationcore---normal-pass---custom-passes)
            *   [RyujinObfuscationCore -> updateBasicBlocksContext](#ryujinobfuscationcore---updatebasicblockscontext)
            *   [RyujinObfuscationCore -> insertBreakDecompilers](#ryujinobfuscationcore---insertbreakdecompilers)
            *   [RyujinObfuscationCore -> removeOldOpcodeRedirect](#ryujinobfuscationcore---removeoldopcoderedirect)
            *   [RyujinObfuscationCore -> InsertMiniVmEnterProcedureAddress](#ryujinobfuscationcore---insertminivmenterprocedureaddress)
            *   [RyujinObfuscationCore -> applyRelocationFixupsToInstructions](#ryujinobfuscationcore---applyrelocationfixupstoinstructions)
    *   [Ryujin Bin2Bin Final Overview](#ryujin-bin2bin-final-overview)
5.  [Deobfuscating Ryūjin](#deobfuscating-ryujin)
    *   [Techniques and approaches adopted](#techniques-and-approaches-adopted)
    *   [Writing a Test Binary](#writing-a-test-binary)
    *   [Analyzing code encryption](#analyzing-code-encryption)
    *   [Identifying Obfuscation/Protection Patterns](#identifying-obfuscationprotection-patterns)
    *   [Removing mutation / Junk Code](#removing-mutation--junk-code)
    *   [Devirtualizing and Analyzing RyujinMiniVm (and its variants)](#devirtualizing-and-analyzing-ryujinminivm-and-its-variants)
    *   [Extracting and Analyzing the RyujinMiniVm bytecode interpreter](#extracting-and-analyzing-the-ryujinminivm-bytecode-interpreter)
    *   [Analyzing Ryujin's virtualization implementation via Microsoft Hyper-V APIs to run RyujinMiniVM](#analyzing-ryujins-virtualization-implementation-via-microsoft-hyper-v-apis-to-run-ryujinminivm)
    *   [Analyzing auxiliary protection techniques](#analyzing-auxiliary-protection-techniques)
        *   [Analyzing Anti-Debug and Troll Reversers](#analyzing-anti-debug-and-troll-reversers)
        *   [Analyzing Anti-Dumper](#analyzing-anti-dumper)
        *   [Analyzing Memory Protection](#analyzing-memory-protection)
    *   [Writing a Universal Deobfuscation Plugin](#writing-a-universal-deobfuscation-plugin)

*   [Practice](#practice)
*   [The End](#the-end)
*   [Bonus: Writing an _MBA Obfuscation Pass_ for Ryujin](#bonus-writing-an-mba-obfuscation-pass-for-ryujin)
*   [References](#references)

Our Usual Prelude
-----------------

Dear reader, it’s been quite some time since my last article. I recognize the delay and apologize for it. I’d love to maintain a more consistent pace from now on, but I feel that’s almost impossible these days (I’ve been very busy taking care of business, people, research/studies, languages, and more). Finally, this article. one that demanded a great deal of work, research, study, coding, writing, and review. is ready to be published. Along with it, I’d like to express my gratitude to everyone: to those who read my articles, follow each one closely, send me private questions, reach out with topic suggestions or review requests (yes, that happens quite often. well-known figures whose articles I’ve read come to me asking for input on my own writing). That truly motivates me. It’s rewarding to see that something which started as a hobby has grown to the point where experienced people in the community now help me improve continuously. Thank you so much, sincerely.

I also dedicate this article, in particular, to the work of others whose research is cited in the references of this text. In all my writings, I always emphasize, and strongly defend, my point of view that **absolutely no one builds knowledge alone**. Even though in today’s world dishonesty and falsehood often prevail, I hope my articles reflect the opposite and help redirect some attention toward the true spirit of community and gratitude.

I also thank my reviewers and direct collaborators on this article, people who invested their time and knowledge to help improve this work and ensure its quality:

*   Buzzer-re([https://github.com/buzzer-re](https://github.com/buzzer-re))
*   rem0obb([https://github.com/rem0obb](https://github.com/rem0obb))
*   amapires([https://github.com/amapires](https://github.com/amapires))

Finally, I usually include a song in my articles, and this one won’t be any different. A suggestion to listen to while reading is [SawanoHiroyuki\[nZk\]:Laco「FAKEit」](https://www.youtube.com/watch?v=a_iU8YeH944).

**Attention:** before we continue, it’s advisable that you, dear reader, have some background in reverse engineering and a certain level of understanding about file formats. Ideally, that should be the PE (Portable Executable) format, which is what we’ll be working with throughout this article. Lacking some of this background doesn’t disqualify you from reading, but at certain points it may require you to look up additional material online.

I hope this article meets your expectations and that you enjoy the read!

Understanding Bin2Bin
---------------------

In this first section, before we begin exploring and diving deeper into the concepts behind writing a Bin2Bin obfuscator, it’s necessary to level the ground so all readers can follow the concepts of reverse engineering, operating system internals and file formats.

### Bin2Bin 101

First of all, let’s reflect: do you really know what a Bin2Bin is? Different authors treat this term in different ways. It is not necessarily tied only to obfuscating an already compiled binary. The correct concept behind a Bin2Bin is the processing of a binary with or without its symbols. in other words, being able to manipulate code that has already been compiled by a compiler such as MSVC and produce some alteration or processing of it (not directly related to obfuscation), creating a different (or slightly modified) binary in such a way that it still runs normally.

Complex? Not exactly. Many associate this term directly with obfuscators. that’s not wrong, but the term Bin2Bin refers only to the processing itself. If you look at some commercial obfuscators like VMProtect, Themida, Obsidium, Enigma and CodeGuard (Back Engineering Labs, by far my favorite), you’ll see they use the term "Bin2Bin obfuscators". Obfuscation is just one process. Bin2Bin indicates that these products are able to take a binary file, process it and produce a new, functional file with the modifications provided by their mechanisms, in this case obfuscation or virtualization.

With this concept well defined, we can now understand how this is done through a flow diagram: ![#1](/posts/images/2025-11-14/img1.png) With this diagram we can visualize, in a simplified way, how the process happens. First we have a compiler, whichever it may be **(MSVC, GCC or even the Delphi Compiler)**, which is responsible for producing our executable file, whether it’s a **PE, ELF, Mach-O or similar**. That file is then processed by some "specialist" tool, in this case the bin2bin tool, capable of loading the file of its specialized type and performing some processing, directly or indirectly related to obfuscation. After that, a new specialized file is generated, able to be executed without breaking compatibility with the original input file.

You might wonder, or be curious, how that processing is done. however, that is a topic for the next sections. For now, to complement our understanding of the subject, know that there are other ways to obfuscate or modify the scope of a given output binary. This is done through the compilation and linking approach, using some infrastructure compiler such as LLVM, where you can manipulate an intermediate language and control its generation to produce a binary in any format, without needing anything specialized beyond architecture independence. For that, a pass must be created, and it will be responsible for performing a preprogrammed processing. But that is not the subject of this article. just know that bin2bin is not the only way to process a binary.

After this introduction to bin2bin, I assume you’re interested in continuing your journey to understand them. So, let’s move on together to the next section of this article.

![#2](/posts/images/2025-11-14/img2.gif)

### PE Format, Disassemblers and Assemblers

Let's continue building the foundation to understand the concept of a Bin2Bin. This time we'll explore and understand how, starting from a PE file, we are able to disassemble its code and later assemble it back. You may be wondering: "What does all this have to do with a Bin2Bin, and how will understanding PE, disassemblers and assemblers help me write and understand one?" Everything here is the groundwork that lets us dive deeply, without confusion, into how Ryūjin works and to understand each implementation and concept. Don’t worry: by the end of this section you will fully understand the relationship between these topics.

#### PE Format

Starting with the PE file format, let’s do a deep dive into the main concepts that let us grasp fundamental details needed to write and operate a Bin2Bin. The goal here is not to present a complete, fully documented specification of the format. Throughout this documentation and this section I will use the `CFF Explorer` tool.

We’ll begin understanding the PE file in a different way. I will abstract various fields from the `IMAGE_DOS_HEADER` and `IMAGE_NT_HEADERS`, which will be detailed more thoroughly when we actually structure and present how Ryūjin works. We’ll start instead with the sections of a PE file ([**IMAGE\_SECTION\_HEADER**](https://learn.microsoft.com/pt-br/windows/win32/api/winnt/ns-winnt-image_section_header)) that encapsulate some critical information used during our processing of disassembled code. A PE has many sections; the most common ones that contain executable code are `.text` and `.code`, the latter used by some specific compilers such as Embarcadero. Let’s look at an example of a PE already processed by Ryūjin, a special, unconventional case to exercise the basic concepts:

![#3](/posts/images/2025-11-14/img3.png)

In this binary we have the following sections: `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc` and `.Ryujin`.

Do you know how each of them works? Ignore `.text` and `.Ryujin` for now. If we look at `.rdata`, can you tell exactly how it works? The short answer is not just "it stores read-only constant data." Okay, that’s true. But how does it do that? That behavior is implemented and controlled by the `IMAGE_SECTION_HEADER.Characteristics` field. In this case, if we inspect `.rdata`, it has the following characteristics: `Is readable` and `Contains initialized data`. So basically, the point I want to make is not that you are wrong, but that behind every label there is a caveat. including in the naming. This is critical knowledge that goes beyond the basic coverage found in online PE documentation. With that small clarification out of the way, let’s take three main sections: `.text`, `.reloc` and `.Ryujin`, which are the most important for our Bin2Bin.

To the point: why is `.reloc` important? Because it contains the relocation table that holds all relocation information for references in our sections, regardless of ASLR. This comment applies specifically to x86. In our Bin2Bin, since we will work with x64 architecture, most references are RIP-relative, which greatly simplifies the implementation. In other words, if we move a `call` or a `lea reg, imm`, we only need to recalculate the difference between the instruction’s current address and its original address in the new section. Don’t worry about understanding every detail right now. We will have a dedicated section for these concepts later in this article.

Looking at `.text` and `.Ryujin`, you can see their characteristics differ. `.text` follows the standard `0x60000020` (`Is executable`, `Is readable` and `Contains Code`), not allowing writes to the code section. `.Ryujin` has the same flags plus the write permission flag: `0xE0000020` (`Is executable`, `Is readable`, `Is writeable` and `Contains Code`). The reason for this, in the context of obfuscation, is that code protected by Ryūjin needs to self-modify. for example to decompress or decrypt itself. These characteristics are important so the obfuscator does not need to use system APIs later to change page permissions; many malware families apply the same idea. Commercial obfuscators like `VMProtect` and `Themida`, and packers such as `UPX`, also use these section-based concepts.

Other concepts important to writing a good Bin2Bin include fields such as `IMAGE_NT_HEADERS->OptionalHeader.AddressOfEntryPoint`, `IMAGE_NT_HEADERS->FileHeader.NumberOfSections`, among others, which we will cover in more detail later in this article.

**Finally, in this section we will briefly explain how a Bin2Bin finds procedures.** How does a Bin2Bin identify where a procedure starts and ends and how many procedures exist in the input binary? There are three main approaches. One is a heuristic that analyzes basic blocks to identify procedures. a much more complex method that requires a solid static analysis algorithm and is commonly implemented by commercial obfuscators like **Code Guard (Back Engineering Labs)**, **Themida** and **VMProtect**. In simpler Bin2Bin implementations, such as Ryūjin, we use `.map` or `.pdb` files. As of this article’s publication, Ryūjin supports only `.pdb` files. Later in this article we will also explain how the `.pdb` parser is implemented, using the WinAPI helpers from [`DbgHelp`](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/).

I hope this section has leveled the foundational understanding of PE files required for us to move on to the next topic, where we will cover the disassembler and assembler technologies commonly used by Bin2Bin solutions.

![#4](/posts/images/2025-11-14/img4.gif)

#### Disassemblers, Assemblers, Basic Blocks & Obfuscation Passes

In this topic we’ll cover the basic concepts used by Bin2Bin technologies: what basic blocks are, how a disassembler works, how an instruction assembler works, and why we must follow a standardized approach when implementing our Bin2Bin.

First off, do you know what **Basic Blocks** are? How they’re built and organized?

**Basic blocks**, in the context of obfuscators, are sequences of instructions terminated by an outgoing control flow, for example a control structure, a return instruction, or an unconditional jump, something that breaks the instruction sequence of a given routine and leads to a different sequence or routine. They are crucial because they allow a high-level approach to a sequence of instructions, giving a macro view of its behavior and control flow. Most Bin2Bin obfuscators operate from them, since they allow modifying the application’s scope at a macro level. In `Ryūjin` we will implement an algorithm capable of dissecting (disassembling) the instructions of a user-selected routine, creating basic blocks and linking their sequences with a specific class so we can manipulate them easily during our `Obfuscation Passes`. To reinforce the concepts, look at an example of a `Basic Block` represented from an IDA `Flow Graph`:

![#5](/posts/images/2025-11-14/img5.png)

In the image above you can better visualize the practical concept of a basic block; notice the flow break at the `call` and `jz` instructions. This organization lets us abstract and work more efficiently with candidate instructions at obfuscation time. Understanding will become even clearer as we progress through this article and analyze the implementation in our own Bin2Bin.

Now let’s discuss disassemblers and assemblers, specifically frameworks commonly used in Bin2Bin tools. The `Ryūjin` project uses the following in its implementation:

**Zydis** as the [disassembler backend](https://zydis.re/), chosen for its versatility and efficiency when analyzing routine instructions, building basic blocks, analyzing patterns and obfuscation candidates, extracting used registers, and much more. Zydis is friendly and extremely powerful; choosing it ensures that, during this article, we can focus solely on implementing the logic of our `Obfuscation Passes`.

**AsmJit** as the [assembler backend](https://asmjit.com/)), by far the most practical way to insert new instructions into our basic blocks; we will use AsmJit extensively while coding our `Obfuscation Passes`.

Don’t worry about fully understanding right now how these frameworks will be used. You can consult the basic examples in the Zydis and AsmJit documentation to familiarize yourself with their structure. Throughout this article we will cover their complete usage while writing our Bin2Bin.

Finally, the last subject of this leveling chapter: what are **obfuscation passes**. Passes are simply the name given to a "standard" procedure function implemented by our Bin2Bin, which will be executed during the `Run` routine when it receives the context of the routine to be manipulated and its respective **basic blocks**. Think of them as a standard procedure, for example:

    void myPass(ProcContext& proc);
    

Where the `ProcContext` class loads the complete context of the routine we will work on and manipulate to produce some modification in instructions and structures, whether inserting new instructions or manipulations with solvers and the like. Each Bin2Bin obfuscator implements this feature differently, but in `Ryūjin`, besides offering some obfuscation techniques, this procedure also allows the obfuscator’s user to implement their own passes based on a callback template. We will explore this in detail and everything will make even more sense as we move forward.

That brings us to the end of the leveling and introduction chapter on the Bin2Bin concept. From here on we will move forward to structure our own obfuscator, followed by a step-by-step implementation walkthrough of `Ryūjin`. ![#6](/posts/images/2025-11-14/img6.gif)

Ryūjin - Deep into the Bin2Bin Dracco
-------------------------------------

In this chapter we will study the structure and architecture of `Ryūjin`, so that we can get an overview of its capabilities and operation. Then we will break down every small detail of how it works, covering:

*   Loading and processing PE files.
*   Instruction extraction.
*   PDB parser.
*   Basic block processing.
*   Support for obfuscation configuration.
*   Extraction of unused registers (from the procedure context).
*   Adding padding spaces for instruction insertion.
*   Implementation of a mutation/junk code algorithm.
*   Implementation of an IAT protection algorithm.
*   A VM for virtualizing mathematical operations.
*   Math-code VM interpreter using Microsoft Hypervisor APIs on an emulated processor to hide execution.
*   A crypter for the obfuscated code (implementing our own encryption algorithm).
*   Anti-dump techniques.
*   Anti-disassembler/decompiler techniques.
*   Memory protection.
*   Exploiting a Windows feature (to frustrate reverse engineers analyzing our binary).
*   Insertion and alignment of instruction relocations and understanding how this is done step by step.
*   Implementation of support for custom passes.
*   Insertion of a new section and generation of a fully functional PE file.
*   And much more.

**Note:** for an even deeper understanding, I recommend following the article together with the project source code, **available at [Ryūjin GitHub](https://github.com/keowu/Ryujin/tree/main)**.

Many topics! And you, dear reader, are you as excited as I am to dive deep into this subject?

![#7](/posts/images/2025-11-14/img7.gif)

### Architecting Ryūjin

In this section we will analyze Ryūjin’s architecture so we can fully understand how it works. We will use diagrams to explain concepts more didactically, preventing doubts in the following sections where we will go deep into implementation and algorithms.

Every good project starts from a diagram, and Ryūjin was no different. In this first diagram, we have the basic workflow and its usage structure. Check it out:

![#8](/posts/images/2025-11-14/img8.png)

This diagram exemplifies the whole flow of a Bin2Bin described in the [introductory topics](#bin2bin-101), adapting the structure to Ryūjin’s usability and components. In the first panel we have the compiler, which produces two files: the PE binary and its PDB file. With these inputs two initial usage paths are opened, chosen by the user: a **Ryūjin GUI** and **Ryūjin CLI**, both serving as pre-input to the **Ryūjin Core**, where all the Bin2Bin magic will happen and which will be detailed in the next diagram. After the **Core Module** processing, the protected output binary is provided to the user.

In the **Ryūjin Core** structure diagram we can understand in greater detail how the Bin2Bin is structured and processed:

![#9](/posts/images/2025-11-14/img9.png)

This is, without question, a large flow diagram; don’t worry, I will explain every detail from now on.

At first glance, the **Ryūjin Core** flow starts from the **Ryūjin GUI** or **Ryūjin CLI**, which configure the `RyujinObfuscatorConfig` class, responsible for managing all configuration states of the Bin2Bin. Next, this configuration is received by the export `RunRyujinCore`, which will instantiate the `Ryujin` class, calling its constructor to map the input PE file into memory as well as to parse the input PDB file. Then the `Ryujin.Run` method is called, which will be the entry point for processing. It begins by extracting and organizing the procedures that are candidates for obfuscation, supplied in the input configuration structure. For each procedure, **Basic Blocks** are created with the `RyujinBasicBlockerBuilder` class. The instance of that class is then passed to the `RyujinObfuscationCore`, specifically to its `RyujinObfuscationCore.Run` method.

From `RyujinObfuscationCore.Run`, the magic begins: the created Basic Blocks are processed and manipulated. The first step is to run `addPaddingSpaces` to add space to the Basic Blocks correctly for subsequent processing. Right after that, passes marked as `RyujinRunOncePass` are executed with the intention of running only once per obfuscation session, among them, **AntiDump** and **insertMemoryProtection**. Next come the non-critical passes: initially, **AntiDebug** techniques are inserted, followed by the **Ryujin MiniVM**, **IAT Obfuscation**, and **Junk Code/Mutation**, finishing with calls to the **custom pass callbacks** registered by the user. For each executed pass, a call to **updateBasicBlocksContext** is made to redraw the Basic Blocks according to the instruction currently analyzed.

When `RyujinObfuscationCore.Run` finishes its execution, the final obfuscation stages begin, which occur in `Ryujin.Run` and focus on finishing procedures. These steps include: insertion of a new section in the mapped PE, the **insertion of the MiniVM Entry**, fixing for each candidate procedure the **RIP-relative offsets/relocations** with respect to the new section, based on the already obfuscated Basic Blocks, adding the **TeaDelKew decrypt stub**, **encrypting the obfuscated code with TeaDelKew**, fixing and final adjustments to the **PE header, saving the processed file to disk**, and, finally, the **complete CleanUp of the obfuscation section**.

With this description we are able to understand `Ryūjin’s` Core and how it works. A diagram like this is not mandatory for every Bin2Bin, but it allows us to know and understand all the implementations that we will study in depth in the next sections.

![#10](/posts/images/2025-11-14/img10.png)

### Ryūjin Core

In this section we will finally explore in detail each part of the `Ryūjin Core` implementation, which is where, in fact, all the business logic and the entire **Bin2Bin** algorithm live. It is a dynamic library that can be included and used however the consumer wishes. Other components, such as the `CLI` and `GUI`, are just wrappers to simplify usage. The **Core** will be our main focus in this article section, so you can understand every small detail of the project and get inspired to build your own.

#### RyujinObfuscatorConfig

This will be the first class we study inside the `Ryūjin Core` framework. It is extremely important, since it carries the entire and sole input to the Bin2Bin obfuscation engine. Its declaration is present in a header called `RyujinObfuscatorConfig.hh`, which is included by any application that wants to control the dynamic module.

From this class we have access to several configuration fields, which are:

Field

Descrição

isRandomSection

With this option enabled, the section where the obfuscated code will be stored has a completely random name, similar to Themida and VmProtect.

isVirtualized

With this option, the RyujinMiniVM is added for all mathematical operators of the obfuscated procedures, converting them to bytecode and interpreting them (slow, but useful to obfuscate calculations).

isIatObfuscation

Obfuscates all procedure calls in the IAT, causing them to be encrypted and decrypted at runtime.

isJunkCode

Adds junk code and mutates the original opcodes of the specified procedures, making them extremely complex and random to analyze and preventing even decompilation, while preserving the original behavior.

isIgnoreOriginalCodeRemove

Allows the original procedure code not to be removed after obfuscation, very useful to compare results.

isEncryptObfuscatedCode

Fully encrypts the code in the obfuscated section using a proprietary algorithm, then decrypts it during PE binary initialization.

isAntiDebug

Adds anti-debug techniques in user and kernel mode, terminating the application silently.

isTrollRerversers

Exactly the same as `isAntiDebug`, with the only difference being that it exploits a Windows technique to crash the entire operating system, forcing the analyst to lose all progress.

isAntiDump

Prevents the protected PE binary from being dumped by tools like ScyllaDump.

isMemoryProtection

Protects the obfuscated procedures against modification on disk and in memory; if modification is detected, the application exits silently.

m\_isHVPass

Executes some parts of Ryujin protection stubs using emulation on a virtual processor with Microsoft's hypervisor APIs, mainly used together with RyujinMiniVM to isolate and make analysis harder.

strProceduresToObfuscate

List containing the name of all procedures (symbols) to be obfuscated by RyujinCore.

callbacks

List of callbacks that can be registered by the user to implement their own obfuscation passes.

In addition to carrying all configuration fields, we have the method `RyujinObfuscatorConfig.RunRyujin`. The class also manages loading the module and calling the export `RunRyujinCore`, handling errors and more

This class is easy to implement and allows simple, effective usage. See a simple usage example implemented in the `Ryujin CLI`:

![#11](/posts/images/2025-11-14/img11.png)

In the example above we configured all the techniques requested by the user via CLI, parsed the names of the provided procedures and, of course, set a custom callback implemented by our user to execute custom passes.

Custom passes follow a standardized signature, also defined in the `RyujinObfuscatorConfig` class:

    void (*)(RyujinProcedure*);
    

Here is an example of a custom pass procedure implemented in the `Ryujin CLI`:

![#12](/posts/images/2025-11-14/img12.png)

To register callbacks, the method `RyujinObfuscatorConfig.RegisterCallback` is used, receiving the address of the properly implemented callback, which will be called from inside the **Ryujin Core** flow.

See the complete overview of this class and remember its structure: it is very important for us to continue progressing and implementing the **Ryujin Core**:

![#13](/posts/images/2025-11-14/img13.png)

#### RunRyujinCore Export

After understanding how [RyujinObfuscatorConfig](#ryujinobfuscatorconfig) works, it’s time to see how the **Ryujin Core** starts operating. As mentioned, it is the initial entry point, responsible for receiving and validating the information present in the reference provided by the configuration class `RyujinObfuscatorConfig`, preparing the internal control class `RyuJinConfigInternal`, and also instantiating the main execution class `Ryujin`, calling its `Run` method, where our **bin2bin** magic will take place.

![#14](/posts/images/2025-11-14/img14.png)

#### Ryujin Class

As mentioned, `Ryujin` is the main control and management class of our Bin2Bin. It handles numerous important functions, such as managing the input PE file, parsing the PDB file, managing the `RyujinProcedure` classes that encapsulate the procedures to be processed by the bin2bin, as well as controlling calls to passes, creating basic blocks, building the output PE file, and much more. We will address these points carefully in separate sections for better understanding.

##### Ryujin Constructor

In the `Ryujin` class constructor, the implementation is based on mapping the input PE file into memory for later processing by the `Run` method, as well as extracting the procedures from the PDB file corresponding to that input PE.

The implementation of these algorithms focuses on two namespaces. The first is for the PE file parser, `RyujinUtils`, in its method `MapPortableExecutableFileIntoMemory`, whose name clearly describes its function. We use the WinAPI `CreateFileMappingA` to map the file with the `SEC_IMAGE` flag, so that relocations are resolved, which simplifies future work when manipulating this PE file (the importance of this flag will become clearer later in this article). Here’s a practical implementation:

![#15](/posts/images/2025-11-14/img15.png)

In addition to mapping the input PE file, we also work with the corresponding PDB file. As mentioned earlier, the PDB file helps us have full control over the location of each procedure (in case you’re unaware: the PDB file contains numerous symbols and very useful debugging information) and, for a Bin2Bin tool like ours, parsing it is essential so we don’t have to implement more complex analysis algorithms to determine the start and end of procedures. This parsing step saves us time and processing. Another useful option with the same purpose is the `.map` file. It is not generated by default by compilers like **MSVC** unless explicitly enabled in the settings; for now, I won’t focus on supporting it in **Ryūjin**. In Ryujin, we have a namespace fully dedicated to this purpose called `RyujinPdbParsing`, which includes the method `ExtractProceduresFromPdb`; its implementation is relatively simple and uses the WinAPIs from `Dbghelp.h`.

Many **Bin2Bin** obfuscators implement this feature manually, which is interesting, but in my view, makes less sense on Windows, since Microsoft itself provides efficient and functional tools for this task. The implementation of this step is straightforward: we use the WinAPI `SymEnumSymbols`, which allows us to register a callback; from this callback, we filter by the `SymTagFunction` tag in our argument structure `PSYMBOL_INFO`. Check it out:

![#16](/posts/images/2025-11-14/img16.png)

In **Ryūjin**, we store the procedures and their information, such as name, address, and size, in a model class called `RyujinProcedure`. This class fully encapsulates the lifecycle of procedures from the input PE. However, this only considers them as candidates for obfuscation, since the user can configure which procedures they want. Candidates not selected are discarded, and only the necessary procedures are considered. We will explore and discuss the `RyujinProcedure` model class in detail as we progress in our study.

Here’s an overview of the `Ryujin` class constructor implementation:

![#17](/posts/images/2025-11-14/img17.png)

##### Ryujin Run

Now, in this topic we will dedicate our study to the `Run` method of the `Ryujin` class. It is one of the most important classes, in my opinion, since it controls almost the entire life-cycle / processing of the obfuscation session of our Bin2Bin.

The `Ryujin.Run` step focuses on the following phases:

*   Validations (PE, RyujinConfig, PDB, procedures and more).
*   Creation of `Basic Blocks` for the procedures selected by the user to be obfuscated.
*   Execution of the `RyujinObfuscationCore` class and its passes in the `RyujinObfuscationCore.Run` procedure.
*   Creation of the `.Ryujin` section.
*   Insertion of stub for `Ryujin Mini-VM Normal` and `Mini-VM Microsoft - Hypervisor`.
*   Fixing relocations for the obfuscated procedures.
*   Redirecting old procedures to the new obfuscated section and removal of opcodes.
*   Encryption of the code in the obfuscated section and addition of the decrypt stub at the entrypoint.
*   Rebuilding the output PE file.
*   Execution of the clean-up.

We will abstract some of these details, focusing on what really matters for the construction and logic of a Bin2Bin.

**Procedure Obfuscation Core flow**

First, before we understand how the `Basic Blocks` are obtained, it is necessary to reinforce what candidate procedures and processed procedures are in the context of Ryujin.

In the [previous topic](#ryujin-constructor) we discussed that, during the PDB parsing stage, we have the model class `RyujinProcedure`, where the classes that are candidates for obfuscation are stored and managed. In this stage they will be very important: unused classes will be discarded and only the classes provided by the user during the `RyujinObfuscatorConfig` configuration will be considered for all stages from now on. Furthermore, each of the procedures that will actually be considered will have a reference to the model class stored in the local vector `processed_procs` to ease work during this processing stage.

With this basis we can continue, where we will finally discuss how the `Basic Blocks` are created before the `RyujinObfuscationCore` class begins its processing. If you are interested only in the processing, consider reading the [Obfuscation Core](#ryujinobfuscationcore) topic. Everything starts after deciding that the candidate procedure is, in fact, the one selected by the user. Then we extract its respective opcodes based on `RyujinProcedure.address` so that we can access only its opcodes:

![#18](/posts/images/2025-11-14/img18.png)

Right after this step, we pass the respective opcodes to our `RyujinBasicBlockerBuilder` class which, as the name implies, will be responsible for creating our `Basic Blocks`. This class has two main parts that must be configured: its **constructor** and its **createBasicBlocks** method.

![#19](/posts/images/2025-11-14/img19.png)

The call to the **createBasicBlocks** method returns a `std::vector<RyujinBasicBlock>`, which is then stored in the procedure model class `RyujinProcedure.basic_blocks`, so that they can be passed to our `RyujinObfuscationCore` class.

![#20](/posts/images/2025-11-14/img20.png)

A detailed explanation of how it works is available in the dedicated [Obfuscation Core](#ryujinobfuscationcore) topic and an explanation of how the [Basic Blocks](#ryujinbasicblockerbuilder) are generated is also available in a dedicated topic. For now, just know that it will operate on our `basic blocks` and will store the result of the processed procedure model class in our control vector `processed_procs`.

The flow described above demonstrates how the processing and execution of passes are separated from the other core flows of our Bin2Bin. Now let’s understand the post-processing stages of the obfuscator (which may or may not depend on the configuration made by the user in `RyujinObfuscatorConfig`). Some of these stages are crucial for a Bin2Bin and will be fully explained in separate, properly referenced topics.

**Section management**

After the obfuscation flow of procedures by `RyujinObfuscationCore`, the logic to insert a new section into the input PE begins, where the obfuscated code will reside. This section follows a default name: `.Ryujin`. However, it is fully configurable by the user via `RyujinObfuscatorConfig`. Thus, based on the idea used by commercial obfuscators to randomize the section name with a random algorithm (in the namespace `RyujinUtils.randomizeSectionName`), the user can change the name:

![#21](/posts/images/2025-11-14/img21.png)

The configuration for randomized section names depends on the `RyujinObfuscatorConfig.m_isRandomSection` flag being set to **true**. As for insertion of the section itself into the output PE file, that task is fully managed by the `RyujinPESections` class in its `AddNewSection` method. Its operation is simple; to understand it one should read the [PE Format](#formato-pe) topic. We assume the reader knows the basic PE parsing procedure. We will focus only on the logic to insert a new section:

![#22](/posts/images/2025-11-14/img22.png)

The insertion logic is straightforward: we check if there is enough space in the input PE file so that we can insert a new section. In the `RyujinPESections` class itself we have a field `m_newSection` which is nothing more than an `IMAGE_SECTION_HEADER` structure, which will be pre-configured at this stage, aligning it, calculating virtual addressing and initializing basic fields with default values, and then being inserted into the final file built in memory through the `ProcessOpcodesNewSection` method.

**Ryujin MiniVM Stub management**

During processing of the `Ryujin.Run` method, at a certain point we manage the insertion of our mathematical VM interpreter `RyujinMiniVM`. Although we will have a dedicated topic about this subject in the future, the Ryujin MiniVM is nothing more than a handler that will receive as an argument a bytecode in the `RDX` register with all 8 bytes in size and a register context in `RCX`. Its "bytecodes" are interpreted with the goal of executing only mathematical operations. It creates a wrapper for each mathematical operation in order to make analysis of cryptographic algorithms harder.

There are two usage variations of the MiniVM Stub: the first is normal, which simply includes the stub directly and applies junk/mutation passes to it; the second uses another technique that leverages Microsoft hypervisor APIs to create a guest that will be responsible for executing the MiniVM stub with mutation/obfuscation in an isolated and secure way, providing extra protection and significantly increasing analysis difficulty.

The first variation, MiniVM Normal, just adds the bytecode-interpreting stub with the appropriate handlers directly, without an isolated/intermediate layer such as the "HVPass" feature (Microsoft Hypervisor):

![#23](/posts/images/2025-11-14/img23.png)

The stub is already pre-processed. That means its opcodes have already been compiled and only their bytes were extracted as a kind of shellcode, which is then inserted at the beginning of the obfuscated code section. Of course it will also undergo mutation later; the implementation code of the MiniVM is also available as comments, allowing modifications. There are techniques to generate/extract opcodes from a procedure of the program itself to automate this step, but I considered the current approach far more performant and effective.

The second variation uses a technique similar to the Normal one, but with the major difference that we have a layer to perform the setup of a GUEST through the Microsoft [Hyper-V virtualization APIs](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture). Check it out:

![#23_1](/posts/images/2025-11-14/img23_1.png)

**Note:** Certain parts of the implementation were omitted due to size; you, dear reader, can view it in full: [Directly in the implementation of Ryujin.Run.](https://github.com/keowu/Ryujin/blob/main/RyujinCore/Ryujin/Ryujin.cc#L233).

Similar to the RyujinMiniVM Normal stub, here we also have the opcodes to be inserted, already compiled, as well as all the original code comments that originated those same opcodes. The implementation does not depend on imports, meaning it resolves all APIs and modules dynamically at runtime; it allocates memory for the guest, creates a virtual processor, configures GDT, memory layer and base registers so that it is possible to execute and wait for a HLT exception, where we capture the result of the RyujinMiniVM interpretation to finally return it and let execution continue. This implementation will be addressed later when we study [the Ryūjin VM deobfuscation process](#desofuscando-o-ryujin).

After one of the two Ryujin MiniVM logics is inserted, it is time to configure and insert the opcodes into the vector that stores all opcodes resulting from the `RyujinObfuscationCore`.

![#23_2](/posts/images/2025-11-14/img23_2.png)

As mentioned, besides inserting the opcodes into our vector that stores the obfuscated opcodes, before this is actually done, the opcodes are mutated and receive junkcode. This is done by configuring a new `RyujinProcedure` and creating a new instance of `RyujinObfuscationCore` with a `RyujinObfuscationConfig` defining only the junkcode feature and processing so that we obtain only the obfuscated opcodes to then add to our vector that stores all opcodes. Usually these MiniVM Stub opcodes will, by rule, be the first procedure in the added section to store the `.Ryujin` obfuscated opcodes. In addition, we also calculate the **size and virtual offset to control where we should insert the result of the other procedures and their respective processed opcodes.** In the next topic we will fully explore how RIP-relative offset control works for our obfuscated procedures.

**Fixing RIP-relative relocations, Old Procedure Entry Redirection and Opcode Generation**

We finally arrived at a very specific and fun topic. Up to this point in our article we haven’t yet dug into more complex obfuscation concepts, like passes and the like; those will be covered in their own sections so we can go into depth. At this stage of processing, inside the `Ryujin.Run` method, we perform relocation fixes, redirect the old procedure to the new (obfuscated) one, and generate opcodes.

At first glance a big question must arise: how are relocations fixed? The references, the calls, the immediates. absolutely everything. They should all be broken and completely misaligned; there’s no way we can simply append the processed opcodes into a new section, redirect the old procedure to it and just run. Indeed, you are absolutely correct.

To solve this big problem, the `RyujinObfuscationCore` class itself provides the `applyRelocationFixupsToInstructions` method, which fully addresses this issue. Because we are writing an obfuscator for x64, it’s much simpler than x86: all instructions and references are RIP-relative, which makes it relatively easy and effective to implement an algorithm that uses the old reference to recalculate the new one for the obfuscated section. All of this will be explained in a detailed and didactic way in the [Obfuscation Core](#ryujinobfuscationcore) section.

Besides calculating relocations, another important step is, without a doubt, redirecting the old procedure so the new obfuscated procedure runs and, of course, completely cleaning the old opcodes so they don’t expose logic prior to obfuscation. This is done by inserting a simple unconditional jump `jmp .Ryujin.Ofuscado`, and the old opcodes are simply replaced with **NOPs (0x90 - No Operation)**. The routine responsible for this task is `removeOldOpcodeRedirect`, also in the `RyujinObfuscationCore` class.

On top of that, we also process the insertion of relocations and redirecting the obfuscated code for cases where the `Ryujin MiniVM` is used; that step is handled by the `InsertMiniVmEnterProcedureAddress` method, again in `RyujinObfuscationCore`.

After all these procedures, the opcodes of the procedures are finally fully corrected with the right relocations, allowing them to be executed from the obfuscated section without any problems. They are then added to our vector that stores all obfuscated opcodes to be either encrypted or simply appended into the new PE section managed by the `RyujinPESections` class, so we end up with a functional, obfuscated PE output file. All these topics will be covered in much more detail in the [Obfuscation Core](#ryujinobfuscationcore) section.

**Ryujin TeaDelKew code Crypt and Custom Entrypoint**

As mentioned earlier, one of Ryujin’s features is the ability to encrypt the obfuscated code on disk and decrypt it at runtime, specifically at the EntryPoint of the obfuscated application.

This step also lives inside the `Ryujin.Run` method, where we encrypt the contents of our opcodes already processed by the Bin2Bin. I implemented an algorithm of my own that modifies XTEA to expand it, make it different from the original, and even more confusing to analyze. That algorithm is known as [TeaDelKew](https://github.com/keowu/gamespy/blob/main/code_base/Kurumi/TeaDelKewTests/TeaDelKewAlgo.hh#L2). The algorithm incorporates some modifications, such as the `kew_box`, which adds 12 constants used for permutations during the encryption cycles. The algorithm uses 2048 iterations for each main part of XTEA. In addition to the Feistel transformation, TeaDelKew combines XOR and iterations with negative values. The mathematical formula that represents TeaDelKew is as follows.

During the initial permutation with the `kew_box` from 0 to 2047:

![#24](/posts/images/2025-11-14/img24.png)

Following the initial permutation, the modified `Feistel transformation` algorithm is applied from 0 to 2047:

![#25](/posts/images/2025-11-14/img25.png)

For decryption we do the reverse of the algorithm; at first we apply the inverse of our modified `Feistel transformation` from 0 to 2047:

![#26](/posts/images/2025-11-14/img26.png)

Finally, we apply the inverse permutation of the `kew_box` from 0 to 2047:

![#27](/posts/images/2025-11-14/img27.png)

Not all Bin2Bins follow the same pattern; some implement their own encryption techniques, others don’t. I chose to use this modified algorithm with the intent of encrypting using an algorithm that is already secure while breaking the pattern of conventional XTEA.

As mentioned, there is not much mystery about how encryption is done: we apply it to the opcodes of the obfuscated procedures already stored in our specific vector for this purpose, with the only difference that, at the end of that obfuscated code, we append our stub that will replace the original `EntryPoint` with a stub that will decrypt the obfuscated section and redirect execution to the application’s `original EntryPoint`. Check the implementation.

![#28](/posts/images/2025-11-14/img28.png)

The implementation flow is very simple: first we encrypt the obfuscated opcodes in the vector, then we modify our shellcode stub to reference the Original EntryPoint; we calculate the decryption size for the new EntryPoint stub; we add the shellcode stub to our encrypted vector — it is the only part left unencrypted; and finally we calculate the EntryPoint inside the obfuscated section and change the EntryPoint in the PE header to point to the new EntryPoint of our stub. With these steps we ensure execution proceeds without issues.

**Adding opcodes to the new section and Creating the output PE file**

This will be the last topic we address about `Ryujin.Run`. In this stage we focus on two important routines of the `RyujinPESections` class, the `ProcessOpcodesNewSection` and `FinishNewSection` methods, which handle the complex work of inserting the opcodes into the new section we created and writing the file to disk.

In `ProcessOpcodesNewSection` we simply insert the opcodes from our vector at the end of the file, into the reserved, aligned and calculated space for our new section. Check it out.

![#29](/posts/images/2025-11-14/img29.png)

No secrets here: we resize the input PE file, increment the number of sections, align the image size and copy the content to the end of the file.

And finally, in `FinishNewSection`:

![#30](/posts/images/2025-11-14/img30.png)

We just write our PE file to disk, fully reconstructed in memory, based on the **Path** and **Name** configured by the user in `RyujinObfuscatorConfig`.

So, we reached the end of this topic. But we are far from the end of this article. Next we will understand how the Basic Blocks algorithms were implemented in the `RyujinBasicBlockerBuilder` class and, after that, how the actual **Bin2Bin** magic happens in the `RyujinObfuscationCore` class.

![#31](/posts/images/2025-11-14/img31.jpg)

#### RyujinBasicBlockerBuilder

In this section we'll cover how the parsing algorithm for the **basic blocks** of `Ryūjin` procedures was implemented. As we studied in the previous section [Ryujin Run](#ryujin-run), one of the requirements to run our passes over instances of `RyujinProcedure`, and thus actually manipulate the procedures' original code through the class [RyujinObfuscationCore](#ryujinobfuscationcore), is to have the corresponding **basic blocks** stored in the `basic_blocks` field of `RyujinProcedure`. That is done by the class we discuss here.

##### RyujinBasicBlockerBuilder Constructor

As mentioned in the introductory section [Disassemblers, Assemblers, Basic Blocks & Obfuscation Passes](#disassemblers-assemblers-basic-blocks--obfuscation-passes), we use Zydis as the disassembly framework for `Ryūjin` because of its convenience. Zydis is essential for building our **Basic Blocks**. During the call to the **RyujinBasicBlockerBuilder** constructor, a couple of Zydis-specific arguments are expected: `ZydisMachineMode` and `ZydisStackWidth`. With x64 support configured, the constructor receives the following constants: `ZYDIS_MACHINE_MODE_LONG_64` and `ZydisStackWidth_::ZYDIS_STACK_WIDTH_64`, which set the machine mode and stack width when initializing Zydis via the `ZydisDecoderInit` call. The constructor call is straightforward, used only to configure Zydis and to keep the code easily portable in the future if necessary. Check the implementation:

![#32](/posts/images/2025-11-14/img32.png)

##### RyujinBasicBlockerBuilder createBasicBlocks

When writing the `Ryūjin` **Basic Blocks** parsing algorithm I focused on a few key points: **simplicity**, **practicality**, and **ease of use**. I wanted something fast and accurate that would generate the **Basic Blocks** and store them in a vector so I could access them, with each block linked exclusively to the context of the procedure provided. Thus, the only data I programmed as required were: the procedure's opcodes extracted from the input binary, its size in bytes, and the address where it is located, so I can calculate each block's references and addressing.

Additionally, I chose to store the Basic Blocks in a model class representing them, `RyujinBasicBlock`, and to modularize the disassembled instructions into another model class inside the base model class, which I named `RyujinInstruction`. Check their declarations:

    struct RyujinInstruction {
    
        ZydisDisassembledInstruction instruction; // Class to manipulate Zydis's own instructions
        uintptr_t addressofinstruction; // Virtual address of the respective instruction
    
    };
    
    class RyujinBasicBlock {
    
    public:
    	std::vector<RyujinInstruction> instructions; // List containing every instruction in the current basic block
    	std::vector<std::vector<ZyanU8>> opcodes; // List containing the raw opcodes of every instruction in the current basic block
    	uintptr_t start_address; // Start address of the current basic block
    	uintptr_t end_address; // End address of the current basic block
    
    };
    

The representation I created for my **Basic Blocks** and their instructions looks simple, but that was exactly the goal. Study this structure carefully and remember the explanation in the comment next to each field: they control virtually the entire obfuscation lifecycle of our procedures from the input binary and will be important when we study our passes in more depth in [RyujinObfuscationCore](#ryujinobfuscationcore).

After that explanation of the **Basic Blocks** organization and structure, it's time to understand how the Basic Block separation algorithm works. Spoiler, it’s not as complex as you, dear reader, might imagine. If you remember the basic concept we studied about creating **Basic Blocks** in [Disassemblers, Assemblers, Basic Blocks & Obfuscation Passes](#disassemblers-assemblers-basic-blocks--obfuscation-passes), you'll recall that the basis for separating and creating them are branches and unconditional branches, things that break the procedure's execution flow, until we find the final instruction that closes that context. With that in mind it becomes much easier to analyze the implementation. Check it out:

![#33](/posts/images/2025-11-14/img33.png)

The implementation of the `createBasicBlocks` method receives a pointer to the opcodes to be processed, their size, and the start address. With that configured we disassemble using **Zydis**, calling `ZydisDisassembleIntel`. That call returns a `ZydisDisassembledInstruction`, which is promptly added to a `RyujinInstruction` class instance, along with its virtual start and end addresses. We do this for each instruction, storing the resulting `RyujinInstruction` model in the vector that holds the **Basic Block** instructions inside the `RyujinBasicBlock` class. This repeats until the disassembly flow reaches the end of the basic block; who determines whether the current Basic Block context has finished is the `isControlFlow` method. Its implementation checks for a break in the **Basic Block** context via a conditional or unconditional execution break. Check the implementation:

![#34](/posts/images/2025-11-14/img34.png)

The logic to decide that the current block has ended is extremely simple: we check all Zydis execution-break categories and, when one of those breaks is found, we stop disassembling instructions. We store the current **Basic Block** and continue the analysis in a new **Basic Block** context. This cycle repeats until we have processed all opcodes related to the provided procedure. In the end, we simply return our vector containing each of the **Basic Blocks** so we can process them and apply our own pass algorithms. There are many possible approaches for this kind of parsing, for example linking each block via a linked list, storing state and the type of break that generated the new **Basic Block**, among others, but for `Ryūjin` the basic and simple approach was more than enough to achieve the goal.

Finally, now that we understand how the **Basic Blocks** are generated and the complete workings of the `RyujinBasicBlock` and `RyujinInstruction` model classes, it's time for the fun part: let's study the passes and the logic for manipulating procedures through their Basic Blocks to accomplish our Bin2Bin obfuscation goal.

![#35](/posts/images/2025-11-14/img35.gif)

#### RyujinObfuscationCore

In this section we will cover the obfuscation core of how `Ryūjin` works in detail, covering everything related to the passes and obfuscation algorithms based on the procedure **basic blocks**, such as:

*   Extraction of unused registers
*   Padding of spaces in basic blocks
*   Obfuscation of IAT calls
*   Junk code and mutation
*   Virtualization
*   AntiDump
*   AntiDebug (regular and a trick to frustrate reverse engineers)
*   Memory protection
*   Breaking disassemblers and decompilers, and custom passes

We will also cover two very important algorithms responsible for **relocation fixups and for handling execution redirection of procedures, removal of unobfuscated code and redirection to the virtualization VMEntry**. Check the names of the procedures we will study:

*   applyRelocationFixupsToInstructions
*   removeOldOpcodeRedirect
*   InsertMiniVmEnterProcedureAddress

We will begin our study from two main parts of the `RyujinObfuscationCore` class: the **Constructor** and the **Run Method**. The idea is to follow the real flow and organization, exploring subtopics for each and detailing them as much as possible. Other topics will be treated separately after presenting these two main parts, such as the logic for **relocation fixups, procedure redirect, and insertion of the MiniVM Entry**.

Also, before we continue, it is important to point out that the `RyujinObfuscationCore` class is instantiated for each procedure that is a candidate for obfuscation and its respective basic blocks, not for the entire context of all procedures. Thus, they are updated individually without manipulating another procedure's space. This is done for many reasons, my main choice being practicality and compatibility. See an example of usage to get an idea of how it works:

    for (auto& proc : m_ryujinProcedures) {
    .
    .
    .
    RyujinObfuscationCore obc(config, proc, reinterpret_cast<uintptr_t>(m_mappedPE.get()));
    obc.Run(RyujinRunOncePass);
    .
    .
    .
    }
    

With this introduction about the `RyujinObfuscationCore` class and its importance, composition and relevant topics, we have the necessary foundation and can finally start understanding it.

##### RyujinObfuscationCore Constructor

The constructor of the `RyujinObfuscationCore` class is simple and straightforward. Its main function is to set up the primary operation fields for the **Run** method and all passes during its lifecycle.  
The first argument received is the `RyujinObfuscatorConfig` class, which stores the obfuscation settings configured by the user when initializing the Ryujin Core. The second argument is an instance of the `RyujinProcedure` class, which represents the entire lifecycle of the procedure, its basic blocks and much more; in other words, the procedure candidate for obfuscation. The last argument is a pointer to the input PE file mapped in memory, which will be used by the standard x64 RIP relocation calculation routine. All of these arguments are assigned to the class private variables for internal use.

Next, the constructor calls the first pass method, responsible for analyzing registers unused by the procedure in question by analyzing its basic blocks: `extractUnusedRegisters`. Check the constructor implementation:

![#36](/posts/images/2025-11-14/img36.png)

###### extractUnusedRegisters

The implementation of the register extraction algorithm in `RyujinObfuscationCore` is quite simple. It consists of analyzing each instruction in the procedure's **basic blocks**, storing every register used in a **set-like structure**. After analyzing all instructions of each **basic block** of the procedure, we filter against a list of all x64 registers to determine which ones are not present. These are the registers not used by the procedure and that we can freely use during our passes. For the procedure to be obfuscated, `RyujinObfuscationCore` expects that the procedure has at least **two unused registers** available to run our passes. Check the implementation:

![#37](/posts/images/2025-11-14/img37.png)

Based on the implementation above, we can better clarify how extraction of unused GPRs and XMMs is done during execution of candidate procedures for obfuscation. As mentioned, two vectors are used: the first, `candidateGprRegs`, stores general-purpose registers; the second, `candidateXmmRegs`, stores multimedia registers. The extraction logic is clearly based on Zydis and on our basic block model classes, `RyujinBasicBlock`, obtaining each instruction stored in each basic block belonging to the candidate procedure. We filter each `ZydisInstruction` based on its operand type (`ZYDIS_OPERAND_TYPE_REGISTER` or `ZYDIS_OPERAND_TYPE_MEMORY`). With this filter we can extract the `ZydisRegister` enum value available in each instruction and add it to the candidate registers vector (based, of course, on whether its class is `ZYDIS_REGCLASS_XMM`, `ZYDIS_REGCLASS_GPR` or `ZYDIS_REGCLASS_SEGMENT`). When all possible instructions of each basic block of the candidate procedure are processed, we apply the unique-unused-register extraction logic. This is done using another vector, `m_unusedRegisters`, which only stores entries of the `ZydisRegister` enum based on our full list of available `candidateGprRegs` in the ISA. the same applies to the `candidateXmmRegs` list. Based on the count for each `ZydisRegister` entry, we add the entry to `m_unusedRegisters` and then return it. It is necessary that, at the end of the register extraction processing, we have at least two unused registers to execute the Ryujin Core passes. Additionally, up to the time of writing this article, Ryujin passes support but do not use the extracted multimedia registers.

##### RyujinObfuscationCore Run

As mentioned earlier, this is the second main public method of the `RyujinObfuscationCore` class, where the execution of obfuscation passes and the manipulation of the procedure candidate’s **Basic Blocks** take place. The logic follows a predefined flow, running each pass individually over the **Basic Blocks** and their instructions and, after execution, updating them again with a call to `updateBasicBlocksContext`.

During execution, the passes are organized into two different categories: `RyujinRunOncePass` and `Normal Pass`. As the name implies, the Once Pass runs only once and exclusively for the first procedure candidate for obfuscation. This type is ideal for passes that cannot be run multiple times, such as certain memory protection techniques or anti-dump protections. On the other hand, the **Normal Passes** are the common passes. for example Junk Code/Mutation, IAT protection, Virtualization, and similar. which can be executed more than once without issues or interference between procedure candidates for obfuscation.

All passes are executed according to the settings defined by the user during `Ryujin Core` initialization via the `RyujinObfuscatorConfig` class. Reviewing the implementations shows that passes only run if the appropriate configurations were previously set.

Let’s examine a section of the `Run` method implementation. Here’s an overview of the implementation:

![#38](/posts/images/2025-11-14/img38.png)

The first method we will study is `addPaddingSpaces`. Next, we’ll go through the methods in the **Run Once** and **Normal Passes** categories, organized accordingly, finishing with an explanation of the **custom passes**.

###### addPaddingSpaces

In this procedure we address a topic of extreme importance for a bin2bin obfuscator. If you were wondering how to insert new instructions into our **Basic Blocks** without breaking their alignment and sequence, this algorithm/technique is how we do it.

The idea of a padding algorithm is precisely to add instructions that cause no state change relative to the current instructions, so that we can use those extra spaces within passes to insert obfuscation, align instructions, fix relocations, and for other purposes.

There are several approaches to inserting padding. The one I chose is simply to add `0x90 (NOP)` instructions between each instruction. The amount is directly related to the number of operations I expect to perform on the **Basic Block** in question. This amount is controlled by the constant `RyujinObfuscationCore::MAX_PADDING_SPACE_INSTR`, which is set to 14. That means between each instruction we will have fourteen `0x90 (NOP)` operations, providing plenty of room for manipulations. With the configuration complete, by the end of pass processing, absolutely all spaces added by this algorithm are used or replaced. Below is a graphic example that shows how this algorithm works:

![#39](/posts/images/2025-11-14/img39.png)

After processing, each instruction ends up containing the sequence with the alignment instructions and corresponding spaces. At first glance, if you don’t have prior obfuscation experience, this technique may seem odd, but as we progress it will make sense. Now, let’s look at the implementation of our algorithm:

![#40](/posts/images/2025-11-14/img40.png)

This opcode-generation procedure uses the AsmJit Framework, as discussed in the [Disassemblers, Assemblers, Basic Blocks & Obfuscation Passes](#disassemblers-assemblers-basic-blocks--obfuscation-passes) section. Through AsmJit, we can generate the `0x90 (NOP)` opcode more efficiently into the original opcodes of the **Basic Block** code, processing each of them, prepending the desired padding pattern, and overwriting the opcodes stored in the **Basic Block** so they are reflected in the obfuscated code later, when we call `updateBasicBlocksContext`.

###### RyujinRunOncePass

After understanding the Padding and Spaces algorithms discussed earlier, it’s time to talk about the passes in the **Run Once** category. We will cover each of them in as much detail as possible so you can fully grasp how each works and, of course, why each one exists.

###### RyujinObfuscationCore -> RyujinRunOncePass -> insertAntiDump

The first pass executed in the Run Once category is the **AntiDump insertion** pass. Before explaining how it is inserted into our **Basic Blocks**, we need to understand how the technique itself works (specifically, how we prevent our PE from being dumped).

There are several approaches to the **AntiDump** technique. the most common are: **erasing the PE header**, **spoofing the number of sections**, **spoofing sections and their virtual addresses**. Each contributes to the same objective, which is to break dumping tools like `ScyllaDump`, `OlyDumpEx`, and `LordPE`, since these tools rely on the header to calculate offsets and reconstruct the PE file on disk for reinserting the rebuilt IAT sections. Here is a commonly used example:

![#41](/posts/images/2025-11-14/img41.png)

For the `insertAntiDump` algorithm, I chose to completely corrupt the section headers by inserting the stub responsible for this function in the very first procedure candidate provided by the user. The insertion logic into the **Basic Blocks** is very simple, see below:

![#42](/posts/images/2025-11-14/img42.png)

In the logic we iterate over all basic blocks and their instructions. We search for the basic block ID based on the instruction so we can obtain exactly the opcodes in our opcode list stored in the model class `RyujinBasicBlock` in its vector field `opcodes`. We search to find the exact address where the opcode sequence for the instruction begins so we can modify it, adding our call to the stub with the **AntiDump** logic. The detection shellcode-stub has the following logic for deleting the header:

    __declspec(noinline) __declspec(safebuffers) void AntiDumpShell() {
    	.
    	.
    	.
    	.
    	// Update section header to be R/W
        if (NtProtect(reinterpret_cast<HANDLE>(-1), &baseAddr, &headerSize, PAGE_READWRITE, &oldProtect) == 0) {
    
    		// ZERO ALL SECTION HEADERS
            for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
    
                auto* ptr = reinterpret_cast<uint8_t*>(&sectionHeaders[i]);
    
                for (auto j = 0; j < sizeof(IMAGE_SECTION_HEADER); ++j)
                    *ptr++ = 0;
    
            }
    
    		// Update section header to be R/O
            NtProtect(reinterpret_cast<HANDLE>(-1), &baseAddr, &headerSize, oldProtect, &oldProtect);
    
        }
    
    }
    

The logic erases and modifies all **IMAGE\_SECTION\_HEADER's**. It’s not a very common technique. usually people just spoof the number or erase the header. and it’s highly effective, because when a dumping tool tries to parse it, it won’t find the information necessary for reconstruction, forcing anyone attempting a dump to reconstruct manually. The generation of the stub is extremely simple: I compile this routine and extract its bytes to add and execute them.

So that this injected stub in our **Basic Blocks** can execute without breaking the flow of the original instructions, we use the following instructions to ensure the original code context is not lost:

    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    // OUR INJECTED STUB OPCODES
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    

These instructions ensure everything executes as expected, saving the entire **EFLAGS** context and all registers, and fully restoring them after finishing execution. It’s worth noting this pattern will be mutated in subsequent passes to ensure it’s not possible to create a signature that allows an easy bypass. Another technique also used is `insertBreakDecompilers`, which we will cover later in this section. When everything has been generated, we use AsmJit to produce the appropriate opcodes, insert them into our **Basic Blocks**, and update them with a call to `updateBasicBlocksContext`, which we will discuss next.

###### RyujinObfuscationCore -> RyujinRunOncePass -> insertMemoryProtection

In this **pass** we have an algorithm similar to the first technique we saw in `insertAntiDump` to store register context without breaking the original execution logic; therefore, I’ll focus only on explaining how the stub works to detect runtime memory modifications.

The most common techniques used by commercial Bin2Bin solutions like **VMProtect** and **Themida** rely on `CRC32` to hash the protected executable code, storing that value and comparing it at runtime. That way, if a single byte is changed the check fails and the protected binary has been tampered with, either at runtime or on disk (both cases).

In `insertMemoryProtection` only the opcodes stored in the `.Ryujin` section are protected, where the obfuscator code resides after Bin2Bin processing. The stub is very simple and, similar to what we saw before, we use the **PEB** to obtain the module ImageBase, parse the binary’s sections, find the obfuscator section, compute the full `CRC32` of its opcodes and compare it with the stored value. Let’s see how this works:

![#43](/posts/images/2025-11-14/img43.png)

When any change occurs in the obfuscator result section `.Ryujin`, the CRC32 check will fail and the whole binary will stop working. The CRC32 of all executable code in the section is stored in the `PointerToLinenumbers` field and is calculated at the moment the section is about to be saved to disk. Check the implementation of this checking stub added by this pass:

    #pragma optimize("", off)
    __declspec(noinline) __declspec(safebuffers) void RyujinMemoryCrc32Protection() {
    	.
    	.
    	.
    
    	//Image Base + Ryujin Section Address
    	const uint8_t* data = base + ryujin->VirtualAddress;
    
    	//calculate CRC32
    	uint32_t crc = 0xFFFFFFFF;
    	for (size_t i = 0; i < ryujin->NumberOfLinenumbers; ++i) {
    
    		crc ^= data[i];
    
    		for (int j = 0; j < 8; ++j) {
    			if (crc & 1)
    				crc = (crc >> 1) ^ 0xB0B0C400;
    			else
    				crc >>= 1;
    		}
    
    	}
    
    	auto crcvalue = crc ^ 0xFFFFFFFF;
    
    	// Check if the CRC32 match with stored one
    	if (ryujin->PointerToLinenumbers != crcvalue)
    		NtTerminate(reinterpret_cast<HANDLE>(-1), crcvalue);
    }
    

Similar to the previous pass, here we also compile and generate the shellcode stub that will be inserted during this pass execution into the instructions of our **Basic Blocks**. Detection is very simple: we dynamically calculate the **CRC32** over the section contents and compare it with the stored value. if it fails, i.e., if it was manipulated externally or at runtime, we simply **terminate the protected application**.

###### RyujinObfuscationCore -> Normal Pass -> insertAntiDebug

Now we introduce the normal passes, that is, those that can be added more than once to procedures chosen for obfuscation. We’ll start with the `insertAntiDebug` pass and fully explore how it works.

In the `insertAntiDebug` pass there are two operation modes for protection. The **first** simply terminates the application when debugging is detected in the protected application. The **second**, nicknamed **Troll Reversers**, makes the user’s operating system crash and triggers a **BSOD** for whoever is analyzing the protected binary.

The stub insertion technique for detection follows the same pattern we explained for the `insertAntiDump` pass, storing **contexts of all registers and flags** and using `AsmJit` to generate the context-saving opcodes for the detection stub. So I’ll focus only on explaining how the AntiDebug technique works; also, only this pass and one other use this context-saving technique, the others work differently.

The AntiDebug technique can detect both kernel and usermode debuggers and implements some well-known methods. Because of the risk of causing frustration, I chose to provide limited support for this technique, since the user can implement their own custom pass and expand it as desired. The kernel debug detection technique uses `NtSystemDebugControl` (which is also functional for userland) and `QuerySystemInformation` for this purpose. For userland, besides `NtSystemDebugControl`, I also use `PEB->BeingDebugged`, even though it’s somewhat of a joke. Let’s look at how it works visually:

![#44](/posts/images/2025-11-14/img44.png)

At this point you might be wondering how we can trigger a **BSOD from userland**. It’s very simple: we use undocumented APIs. Specifically, `NtRaiseHardError`, used by `CSRSS.exe` and present in `ntdll.dll`. Microsoft does not filter who calls this syscall. therefore we can easily pass an error code, the most common is `STATUS_FLOAT_MULTIPLE_FAULTS`, and force the entire system to crash immediately. **This technique is not new and has been present since Windows XP.** And yes, to this day nobody has fixed the issue; a few malwares have used this to frustrate analysts, maybe more will in the future. Let’s look at the implementation of this technique and the entire **AntiDebug** stub with the **TrollReversers** feature:

    __declspec(noinline) __declspec(safebuffers) void detectWithTroll() {
    	.
    	.
    	.
    	auto status = NtSystemDebugControl(SysDbgCheckLowMemory, 0, 0, 0, 0, 0);
    
    	if (status != STATUS_DEBUGGER_INACTIVE && status != STATUS_NOT_IMPLEMENTED) goto detected;
    
    	SYSTEM_KERNEL_DEBUGGER_INFORMATION KdDebuggerInfo;
    	status = NtQuerySystemInformation(SystemKernelDebuggerInformation, &KdDebuggerInfo, sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION), NULL);
    
    	if (NT_SUCCESS(status)) if (KdDebuggerInfo.KernelDebuggerEnabled || !KdDebuggerInfo.KernelDebuggerNotPresent) goto detected;
    
    	if (peb->BeingDebugged) goto detected; // Is this a meme Keowu ? yes!
    
    	goto no_detected;
    
    detected:
    	// For no "TrollReversers", consider just NtTerminateProcess.
    	if (NT_SUCCESS(NtAdjustPrivilege(19, TRUE, FALSE, &enabled)))
    		NtRaiseHardError(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, nullptr, 6, &resp);
    
    no_detected:
    	
    	return;
    .
    .
    .
    }
    

As with all other stages, the code above is compiled and a **shellcode stub** is generated for insertion together with the execution context-saving logic for registers and flags via `AsmJit`, in order to modify our **opcodes** and **basic blocks** of the candidate procedure.

###### RyujinObfuscationCore -> Normal Pass -> insertVirtualization

Now let’s discuss the virtualization pass, `insertVirtualization`. It no longer follows the shellcode-stub logic we saw previously, since the algorithm here is intelligent and complex enough to generate everything dynamically. It analyzes arithmetic operation opcodes, generates bytecode for them and arranges it correctly so it can be interpreted by the `RyujinMiniVm`.

The `RyujinMiniVm` is a simple stub that receives a `UINT64 (8 bytes)`, splits and interprets it, performing the operation equivalent to the original opcode’s mathematical operator. Confusing? Let’s understand, briefly, the concept of a virtual machine.

An **interpreter virtual machine**, in the context of code protection, refers to a **non-conventional architecture**. What is a **non-conventional architecture**? Simple: an architecture with no public documentation. Exactly that. create your own exclusive architecture. Where each opcode is interpreted by a dedicated **handler** and executed so as to produce the same result. Other bin2bin solutions, like **VMProtect** and **Themida**, follow this same principle, with the difference that they randomize their architecture (instructions and opcodes, in that case).

In `RyujinMiniVm` I implemented the idea of a very reduced version based on this single-instruction protection concept. That way, if we have, for example, an encryption routine, we can fully "virtualize" its execution using numerous calls to the **MiniVm**. My goal was to make a simpler VM, **supporting a limited instruction** set to hinder analysis without creating excessive interpretation overhead, serving as a starting point for those who want to expand its behavior and capabilities.

As mentioned earlier, the VM uses only one register to load its bytecodes, i.e., 8 bytes (UINT64), the maximum size a register holds on x64. Intel instructions are translated to `RyujinMiniVm` bytecode as follows:

![#45](/posts/images/2025-11-14/img45.png)

The diagram above illustrates well how the translation process from **Intel x64** to **RyujinMiniVM** bytecode works.

In the normal flow, after compilation, we have a simple procedure that uses some mathematical operator. In this case, a sum function: based on the value received, it adds 10 (decimal) and returns. Modestly simple behavior, easily reversed. Now let’s apply the translation using the `translateToMiniVmBytecode` algorithm: first we analyze and find all math operators used by the candidate procedure, supported ones are `add, sub, imul` and `div`. These instructions are converted to the internal representation, in this case `add = 01`. Next we convert the operands: `rax = 0x33` and `0x0A` as the operand value remain the same. The final translation step is to concatenate the bytecodes into a single hexadecimal value to be assigned to the `RDX` register (in the RyujinVmStub `RCX` carries the previous return/context address), resulting in **0x33010A**. This final value will still be encrypted with a random key and mutated in its final form to ensure randomness and hinder analysis. Check the implementation of the algorithm:

![#46](/posts/images/2025-11-14/img46.png)

The algorithm in question is **very large**, so only the main part was added as a screenshot. It implements and executes the details described above. And, if you want, you can **[see the implementation of the insertVirtualization method in the Ryūjin repository itself](https://github.com/keowu/Ryujin/blob/d8c37b2d4c1bc785e2a1b92a67f6ded9591a00cd/RyujinCore/Ryujin/RyujinCore/RyujinObfuscationCore.cc#L412).**

Finally, we understand exactly how the translation from Intel to RyujinMiniVm bytecode works, implementing a simple virtual machine concept to protect simple mathematical code. Now let’s look at the stub that interprets this bytecode at runtime inside the protected binaries:

    __declspec(noinline) __declspec(safebuffers)uintptr_t miniVmExecute(uintptr_t rcx, uintptr_t rdx) {
    
    	unsigned char reg = (rdx >> 16) & 0xFF; // Get reg index(just a extra info, not used in fact(we already handle it on MiniVmExit code, but useful for someone trying to expand it's works)).
    	unsigned char op = (rdx >> 8) & 0xFF; // Get op byte.
    	uint64_t value = rdx & 0xFF; // Get value for execution.
    
    	uintptr_t result = rcx; // Previous Context
    
    	//Which op to "handler" ?
    	switch (op) {
    
    		case 1:
    			result += value;
    			break;
    
    		case 2:
    			result -= value;
    			break;
    
    		case 3:
    			result *= value;
    			break;
    
    		case 4:
    			result /= value;
    			break;
    
    		default:
    			result = 0;
    			break;
    
    		}
    
    		return result;
    	}
    

The stub is very simple and has no external dependencies; it is self-contained. It usually resides near the start of the `.Ryujin` section. It receives only two arguments: the first, in `RCX`, contains the register context before entering the **RyujinMiniVM**, so its operations don’t get lost during execution. the second, in `RDX`, carries the bytecodes decrypted dynamically during the call to the **RyujinMiniVM**, where they will be split to execute the mathematical operation corresponding to their **handler** (making analysis harder and requiring prior understanding of its behavior). **A more secure variation, using Microsoft’s Hyper-V layer (HVPass)**, is available to add even more protection to the bytecodes and to the MiniVM stub logic, but the concepts above are exactly the same, it’s just an extra isolation layer.

###### RyujinObfuscationCore -> Normal Pass -> obfuscateIat

Another obfuscation pass very common in protectors like VmProtect, Themida and others is the protection of the import table and its calls. This feature is implemented in countless ways. VmProtect, for example, uses an IAT with jump addresses, replacing the original call with a call to its own section that retrieves the address of its protected import table, obviously heavily mutated, and, at the end, uses the ret instruction to jump to the real import table address.

In `Ryūjin` I tried to implement a similar solution, **in some parts using VmProtect’s approach**, but of course with its own peculiarities. The operation of this obfuscation pass is relatively simple. IAT protection is based on finding **instructions inside our basic blocks** that make calls to the **import table (call IAT)**. Based on RIP-relative relocation, calculate the real destination address and store the RVA between the module base and the destination where the IAT entry will be. From there, we rebuild the entire call to be **non-RIP-relative relocation**, that is, so that it works only with a simple addition with the protected binary’s module base, and we can access the address to retrieve the entry that the loader filled in the import table. thus finishing with a `call rax` to its proper address.

At first this explanation may seem very confusing, but it is not really the case. Let’s dive deeper into the technique, but first, understand the operation through a diagram:

![#47](/posts/images/2025-11-14/img47.png)

The procedure better illustrates everything discussed above. Now let’s understand it in more detail, starting with the following reflective question: how is an address for an IAT call resolved?

Simple: we are on x64, it is RIP-relative. We can easily calculate its entry address in the `.idata` section from where the address used for the call will be retrieved. Suppose the call we want is at address **0x1400011BE**:

![#48](/posts/images/2025-11-14/img48.png)

If we take the address following our `call` **0x1400011C4**, and add the call displacement:

![#49](/posts/images/2025-11-14/img49.png)

Like this: `0x1400011C4 + 0x1E3C = 0x140003000`, that is, the exact address where our import table procedure will reside:

![#50](/posts/images/2025-11-14/img50.png)

What we do in `Ryūjin’s` IAT obfuscation algorithm is simply subtract the module ImageBase of the protected binary and obtain the **RVA**, since that interests us to calculate the address at runtime later. Let’s see in detail how the stub that decrypts works:

    rdgsbase rax
    add     rax, 57h
    xor     rax, 37h
    mov     rax, [rax]
    add     rax, 27h
    xor     rax, 37h
    mov     rax, [rax]
    add     rax, 4C37h
    xor     rax, 7C37h
    mov     rax, [rax]
    call    rax
    

The operation is quite simple. The technique uses `rdgsbase rax` to store the GS segment base in RAX. We will add `0x57` and XOR with `0x37`, which will result in `0x60`, precisely our **PEB**, where we will access (`mov rax, [rax]`) and retrieve its value. Next we will add to `rax` the value `0x27` to the **PEB** address and xor with `0x37`, which will result in `0x10`, exactly the **ImageBase** field of the PEB. then we will access (`mov rax, [rax]`) and retrieve the **ImageBase** in `rax` again. We will add `0x4C37` and XOR with `0x7C37`, resulting in `0x3000`, exactly the RVA of the **.idata** entry. Suppose we have the ImageBase at **0x140000000** added with **0x3000**, it results in **0x140003000**, the exact address where the loader placed the desired procedure’s address. To retrieve it, we access address **0x140003000** (`mov rax, [rax]`) and obtain that address; finally we call it via `call rax`. It’s worth remembering that this is the technique without any other pass, such as mutation/junk code, which would completely change the logic and make it much harder to discover the access constants and other useful information for analysis.

Now that everything has been explained and leveled, let’s look at the implementation of this pass’s algorithm; you will be able to fully understand it:

![#51](/posts/images/2025-11-14/img51.png)

**Author’s additional note:** when we use a filter by `ZYDIS_CATEGORY_CALL` and `ZYDIS_OPERAND_TYPE_MEMORY`, we ensure we will only pick calls to standard IAT memory locations with the opcode prefixes `0xFF15`.

Dear reader, the implementation is quite extensive; consider **[viewing the obfuscateIat method implementation in the Ryūjin repository](https://github.com/keowu/Ryujin/blob/d8c37b2d4c1bc785e2a1b92a67f6ded9591a00cd/RyujinCore/Ryujin/RyujinCore/RyujinObfuscationCore.cc#L127)**

###### RyujinObfuscationCore -> Normal Pass -> insertJunkCode

In this topic we will cover the last programmed obfuscation pass, before, of course, addressing the custom passes that `Ryūjin` users can implement on their own. This last obfuscation pass focuses on inserting **Junk Code/Mutation** and implements an algorithm capable of analyzing an instruction and dynamically generating **numerous mathematical and flag-manipulation instructions**, without losing or changing the candidate procedure’s core logic. Some of these techniques were based on the same technique used by **VmProtect’s Mutation feature** ([previously documented here](https://keowu.re/posts/Analyzing-Mutation-Coded-VM-Protect-and-Alcatraz-English/#analyzing-techniques-and-mutation-of-vm-protect)), with additional techniques discovered while writing the algorithm.

The operation of the **Junk Code/Mutation** algorithm requires at least **two registers** not used by the candidate procedure, which are collected by the **[extractUnusedRegisters](#extractunusedregisters)** algorithm. These registers are essential so we can insert instructions without breaking the original code logic. Furthermore, for each instruction in our **Basic Block** the algorithm also inserts **paddings** to align opcodes correctly, similarly to **[addpaddingspaces](#addpaddingspaces)**. The original opcodes of the candidate procedure are then stored, and an **AsmJit** instance begins its work to generate instructions dynamically based on the configurations:

*   (1 to 69) instructions per iteration in the basic block.
*   (1 to 100) candidate values for immediate operations.
*   (1 to 69) randomized values for bitwise operations.
*   Stack saving (RBP, RSP) to ensure correct alignments.

These ranges are chosen randomly each iteration, and in addition the number of randomizations per **Basic Block** is also random, aiming to make it harder to remove the obfuscation instructions based on clear patterns by those analyzing the **protected code** (even during reverse engineering attempts to track register usage):

![#52](/posts/images/2025-11-14/img52.png)

Currently the instructions inserted dynamically and randomly are pre-programmed, and they change according to the values generated randomly during the iteration. These are the mutation instructions currently used by our algorithm:

    sub
    imul
    xor
    or
    not
    neg
    shl
    shr
    sar
    rol
    ror
    inc
    dec
    test
    cmp
    lea
    nop
    bt
    bts
    btc
    movzx
    movsx
    movsxd
    cmovs
    cmovp
    sal
    rcl
    rcr
    stc
    clc
    cmc
    cdqe
    cbw
    sbb
    bsf
    

Consider that they do not follow a fixed logic and, furthermore, are random each time **basic blocks** are processed, along with their **operands, values, operations** and **results**, with the aim of confusing individuals interested in reversing. Now let’s understand the operation of this obfuscation pass and its result through a diagram:

![#53](/posts/images/2025-11-14/img53.png)

The diagram exemplifies the exact processing performed by this obfuscation pass. We have an unobfuscated code, in this case a simple candidate procedure that adds 10 to the value received as an argument. As a first step we extract the opcodes stored in its **Basic Block** so we can work on inserting new opcodes between each opcode relative to each individual instruction. Secondly, between each instruction (and its respective opcodes) we add padding with **NOP instructions (0x90)** to ensure proper spaces and alignments. Thirdly we analyze and verify whether we have the necessary requirements to continue, which in this case are two unused registers, and we ensure we do not manipulate any stack-related registers (RSP and RBP). Fourth, we start AsmJit and configure it based on the specifications commented earlier for the required randomization. Fifth, we begin the **manipulations and insertions of the junk/mutation instructions** between each stored instruction. Finally, we generate a **new output buffer with AsmJit** and replace the stored opcodes in our **Basic Block** so they are updated after exiting the pass. In this way, the candidate procedure is totally modified.

Now let’s look at the algorithm implementation:

![#54](/posts/images/2025-11-14/img54.png)

Dear reader, the implementation is quite large. consider **[viewing the insertJunkCode method implementation in the Ryūjin repository](https://github.com/keowu/Ryujin/blob/51668165b7b09e5297b19f89a4828027df49835e/RyujinCore/Ryujin/RyujinCore/RyujinObfuscationCore.cc#L334)**.

###### RyujinObfuscationCore -> Normal Pass -> Custom Passes

In this topic we will explore how `Custom Passes` work to allow third parties to implement their own obfuscation passes and extend `Ryūjin`'s functionality.

Currently, to let users implement their own passes, we use callback techniques. That is: the user registers a method using a standard signature, implements all desired logic, and then provides the address of that routine to be registered during configuration initialization via the `RyujinObfuscatorConfig` class. This is the signature for implementation:

     void (RyujinProcedure* proc);
    

When implemented, the callback will receive a reference to the class that manages the lifecycle of the candidate procedure `RyujinProcedure`, where the user can access the most important fields. That class requires no extra dependencies to use, so it can be easily included, adopting a convenience similar to the modularization of `RyujinCore`.

Any change made by a callback to its **Basic Blocks** is applied as soon as execution finishes. Similar to other scheduled passes, a call is made to [updateBasicBlocksContext](#ryujinobfuscationcore---updatebasicblockscontext).

Now let's implement a simple pass via a **callback** that prints information about the **Basic Block** and its **instructions**:

    void RyujinCustomPassDemo(RyujinProcedure* proc) {
    
        std::printf("----------------------------------------------\n");
        std::printf("RyujinCustomPassDemo get called for %s\n", proc->name.c_str());
        std::printf("%s has %lld bytes, resides on 0x%llx, with %llx basic blocks.\n", proc->name.c_str(), proc->size, proc->address, proc->basic_blocks.size());
    
        std::printf("Instructions:\n");
    
        for (auto& block : proc->basic_blocks)
            for (auto& inst : block.instructions)
                std::printf("%s\n", inst.instruction.text);
    
        std::printf("----------------------------------------------\n");
    
    }
    

In this example we implement a callback that, when executed, will print the **name of the procedure candidate for obfuscation**, its **virtual address**, its **size (in bytes)**, and the **number of Basic Blocks** it contains. To register this callback for use, we use the obfuscation configuration class `RyujinObfuscatorConfig` in the `RegisterCallback` method.

    config.RegisterCallback(RyujinCustomPassDemo);
    

With that, we'll be able to run our custom pass as soon as an obfuscation session is initialized by `RyujinCore`. Check the result:

![#55](/posts/images/2025-11-14/img55.png)

The implementation in the `RyujinObfuscationCore` class for executing custom passes is very simple. Check it out:

![#56](/posts/images/2025-11-14/img56.png) It checks if any callbacks are registered. If so, we iterate over all callbacks in the list, verify the address is present and, finally, invoke the registered callback, passing a reference to the candidate procedure in question (class `RyujinProcedure`). If any modification was made, it is updated after the custom pass executes with a call to `updateBasicBlocksContext`, thus ending its execution. If other callbacks are also registered, the process repeats for each of them until fully completed.

###### RyujinObfuscationCore -> updateBasicBlocksContext

When any change occurs in the **Basic Blocks** or in their **stored original opcodes**, this method is used to update the entire context and reflect the modifications made in the model class `RyujinBasicBlock`. This algorithm is very important and is used whenever a pass of any category is executed (Run Once or Normal). Check its implementation:

![#57](/posts/images/2025-11-14/img57.png)

The logic is simple: we have a dedicated class to generate them, as discussed in the [RyujinBasicBlockerBuilder](#ryujinbasicblockerbuilder) topic. What is done here is to overwrite the already stored **Basic Blocks** with the new ones, updated in the private field of the `RyujinObfuscationCore` class.

###### RyujinObfuscationCore -> insertBreakDecompilers

The `insertBreakDecompilers` algorithm is not considered an obfuscation pass; it is only a helper for a trick that can be added from any running instance of **AsmJit** during the execution of certain obfuscation passes.

The trick in this algorithm is derived from an obfuscation technique known and demonstrated by the creator of **Binary Ninja**, Jordan Wiens, during a talk at **Off-By-One 2025** titled `Breaking Decompilers`. In that talk, **Jordan** demonstrates several techniques that can be used to break tools such as **IDA, Ghidra and Binary Ninja**, techniques that are hard for those tools' analysis engines to determine automatically during symbolic analysis.

While implementing `insertBreakDecompilers` I expanded the techniques presented in the talk to achieve the same goal and to make them random on each execution of the obfuscation pass that uses this technique. See the implementation of this technique:

![#58](/posts/images/2025-11-14/img58.png)

The techniques above abuse a very simple trick: `0xEB 0xFF` translates to a `jmp +1`. However, due to alignment, the disassembler gets confused and considers it a return, because when `jmp +1` is executed the real opcode is `0xFF 0xC3`, which translates to `inc ebx`. See:

![#61](/posts/images/2025-11-14/img61.png)

When the disassembler analyzes it, it will consider that we have a `ret` and stop analyzing the procedure. But that is not true, because the code that actually executes is:

![#62](/posts/images/2025-11-14/img62.png)

A very simple technique. However, without prior knowledge of how it works, it makes analysis by inattentive third parties much harder.

###### RyujinObfuscationCore -> removeOldOpcodeRedirect

This method is responsible for redirecting the original candidate procedures to execute in the obfuscator section `.Ryujin`, where their respective obfuscated versions will reside.

The algorithm will receive the input binary already processed with the appropriate section inserted. From there, the redirection simply happens by adding a `jmp 0x1234` instruction and, of course, removing the original opcodes and replacing them with **0x90 (NOP)**. Depending on the configuration, if the user chooses not to remove the original code, the replacement step will not occur (thus keeping the original opcodes before obfuscation, a feature useful for debugging passes). See the implementation:

![#59](/posts/images/2025-11-14/img59.png)

###### RyujinObfuscationCore -> InsertMiniVmEnterProcedureAddress

This procedure is a helper to modify the code generated by the pass [RyujinObfuscationCore -> Normal Pass -> insertVirtualization](#ryujinobfuscationcore---normal-pass---insertvirtualization) to insert the address of the MiniVMEntry stub in the `.Ryujin` section. This is done by searching for the signature `48 05 88 00 00 00`, which translates to `mov rax, 0x88`. Thus, the algorithm logic only replaces the immediate value **0x88** with the **virtual RVA of the procedure that will interpret the MiniVM bytecode**. This approach was chosen because we can only compute the exact RVA where the MiniVM will reside after executing all passes and configuring the obfuscator's new section in the protected binary (which is only done after everything has been properly obfuscated). That way we have no addressing limitations. See the implementation:

![#60](/posts/images/2025-11-14/img60.png)

###### RyujinObfuscationCore -> applyRelocationFixupsToInstructions

This procedure is one of the most important. The algorithm inside it will be responsible for fixing all **RIP-relative relocations (x64 only)** for all obfuscated procedures that were moved to another PE binary section controlled by the obfuscator itself (`.Ryujin`).

At first you, dear reader, may be confused as to why we have an algorithm that, after executing all passes, works on each procedure individually and fixes their opcodes and relocations. See an example of what happens if this work is not done:

At first you, dear reader, may be puzzled by the existence of an algorithm that, after all passes have run, works on each procedure individually to fix its opcodes and relocations. See an example where this work is not performed:

![#63](/posts/images/2025-11-14/img63.png)

Notice how the reference used in the call instruction becomes completely broken after we process and move it to the `.Ryujin` section and do not fix its relocations. This is a big problem, because when that code is actually executed we will immediately get an **exception for an invalid destination address**. Now let us look at the same snippet, fully corrected by the fixup algorithm discussed in this section:

![#64](/posts/images/2025-11-14/img64.png)

Observe in the image how the reference corrected by our algorithm is already readily identified by **IDA** during its processing, this particular call is a call to the execution wrapper of a simple **printf**.

In the algorithm implemented in `applyRelocationFixupsToInstructions` we have three central logics for relocation fixes: **RIP offset calculations**, **RIP offset calculation for IAT**, and **Branch Sync** (the latter refers to updating conditional branch offsets between Basic Blocks of obfuscated procedures, so we adjust the link between Basic Blocks correctly to follow the same logic as the original code). We will cover each individually before examining the complete algorithm, but first, above all, let us understand how this algorithm works through a diagram:

![#65](/posts/images/2025-11-14/img65.png) The diagram above clearly outlines how the algorithm works. Note that for each instruction type in our diagram there is an associated number; the goal is to show which calculation logic is used for each of them. In the end, we have the expected result: all relocations functioning.

Now let us explore how each of these algorithms works, this is necessary so that all concepts are well explained when the complete algorithm is shown in the article.

**Call to a memory(IAT) - RIP Relative Relocation**

For a didactic approach to how we recalculate an offset from a different point than the original, I will use a real example. Consider the following **IAT Call** instruction in the new section with the obfuscated opcodes in `.Ryujin`:

![#66](/posts/images/2025-11-14/img66.png)

Now see this same **IAT Call** in its original section, `.text`. To visualize this comparison result, I used Ryujin's `--keep-original` flag to keep the original opcodes after obfuscation, as discussed earlier.

![#67](/posts/images/2025-11-14/img67.png)

Let us understand what each byte sequence means and its importance during the fixup:

![#68](/posts/images/2025-11-14/img68.png)

The opcodes `0xFF15` always correspond to a call by relative offset; on Windows, this is a direct call to an entry in the import table in the `.idata` section. The next four consecutive bytes `0x351E0000` are the relative offset used to resolve the address of the IAT entry; considering ASLR, this offset is RIP-relative, as mentioned. To calculate the offset correctly, we use the new address in the obfuscated section (`0x1400092BE`), add `6 bytes` corresponding to its opcodes, obtaining `0x1400092C4`, and subtract the import address in the `.idata` section (in this case `0x140003000`). The logic to find the address in the `.idata` section is done based on the old relocation. See the mathematical formula for this correction:

![#68_1](/posts/images/2025-11-14/img68_1.png) Applying the formula, we get the offset result: **0xFFFF9D3C**. You, dear reader, may wonder whether the fact that the offset value is negative affects the displacement calculation; the answer is no. This is normal, since we are after the `.idata` section, unlike `.text`, which is before. To make the reference properly functional, just replace the four bytes of the **relative RIP offset in the obfuscated section:** `0xFF153C9DFFFF`. See the result:

![#69](/posts/images/2025-11-14/img69.png)

**Golden recommendation to the reader**: try applying the values in the formula and run your own tests by moving code from one section to another using a debugger!

**Branch Sync - Conditional/unconditional - RIP Relative Relocation**

Now let’s cover how the **Branch Sync** logics were implemented in Ryujin. Note that **Branch Sync** is simply the name we gave to Ryujin’s exclusive technique; this is the approach used by our Bin2Bin solution and each project may have its own internal variations.

Before we see how the correction is applied, let’s look at the problem that appears when we do not synchronize basic blocks using **Branch Sync** after we obfuscate opcodes and place them into the obfuscator section `.Ryujin`:

![#70](/posts/images/2025-11-14/img70.png)

Notice how our **branch `jz`** instruction is completely misaligned and targeting the wrong region of the **basic block**. This happens because the **fall-through offset was lost due to the new instructions our passes inserted.** Now look at the same region after we fix that offset so it points to the correct **basic block** and region:

![#71](/posts/images/2025-11-14/img71.png)

Above you can see the effect of our fix: the **basic block** is properly aligned again, just as it was originally before the change.

The correction algorithm itself runs on the obfuscated instructions. For that we compute the branch’s effective address, which is also RIP-relative. We apply this calculation: the instruction address (in this case `0x1400092E2`) plus the size of its opcodes (here `2 bytes`) plus `0x3B` which is the jump offset, resulting in `0x14000931F` (the same address we saw in IDA after the fix). The formula below represents that operation:

![#72](/posts/images/2025-11-14/img72.png)

All resolution calculations are done from a copy of the original, non-obfuscated basic blocks; the goal is to synchronize the **basic blocks**. We then use the `BRANCH_TARGET` result to find the correct **basic block ID** and obtain the target basic block for both the original and the obfuscated jump. Check the algorithm responsible for that task:

![#73](/posts/images/2025-11-14/img73.png)

After locating the corresponding destination basic blocks and synchronizing them, we run another routine named `RyujinObfuscationCore -> fix_branch_near_far_short`. It will adjust opcodes depending on the discrepancy of offsets in the obfuscated **basic blocks**, taking into account the branch instruction size and its addressing limits (addressing range is, indeed, a major constraint). The algorithm computes the offset and rewrites the opcodes to cover the difference while respecting the x86-64 ISA limitations. We consider, for example, the differences between `near`, `far` and `short`, so the branch behaves like the original code even though the code was completely rewritten and addressing issues would appear if we did nothing. See the implementation:

![#74](/posts/images/2025-11-14/img74.png)

The algorithm is fairly straightforward: it checks whether the current branch instruction we want to fix can support the size of the new offset that will be written. As noted before showing the algorithm, every branch instruction has its own quirks and limits. Given that, we check, for example: if we have a `short` branch instruction, it requires the offset to fit a signed 8-bit range (`-0x80..0x7F`). If the computed offset does not fit, we try a `far/near` variant that supports a signed 32-bit range (`-0x80000000..0x7FFFFFFF`). That range will almost certainly cover the displacement required for our obfuscated code. If you pay attention, you’ll also notice that in each branch logic we only change the opcode to choose between `short` or `far/near`, and that the RIP-relative relocation calculation is essentially the same, the only difference being the instruction byte-size (`2 bytes` for short and `6 bytes` for far/near). As mentioned earlier, to compute the displacement itself we use the obfuscated basic block’s branch instruction address — this is our `jmp_address` argument. The second argument is the destination address, obtained via the sync-by-block\_id technique described before — this is the `target_address`. With those values and after we decide whether to use `short` or `far/near`, we apply the following formula:

![#75](/posts/images/2025-11-14/img75.png)

With the new offset computed, we can replace the original basic block opcodes with the corrected version, adjusted for addressing limits, so that the obfuscated code reaches the same destination as the original.

![#76](/posts/images/2025-11-14/img76.png)

**RIP Displacement Generic - op \[\], reg - op reg, \[\] - RIP Relative Relocation**

Finally, we reach the third and last RIP-relative relocation correction logic in Ryujin. The goal here is to understand how generic instructions like **call, mov, lea, add** and others are fixed. There is nothing exotic here. The correction logic follows basically what we already saw, with subtle differences, the main one being instruction size. This logic is more generic: we extract the instruction’s relative offset and apply the same calculation we discussed earlier, accounting for those subtle differences. For example, consider the following:

![#77](/posts/images/2025-11-14/img77.png)

Ryujin’s generic algorithm can correct these relocations while taking each instruction’s peculiarities into account. Thus, for each example above:

**Example:**

`E8 -> CALL | 08 FF FF FF -> Relative Offset`

Applying the same algorithm we already know:

![#77A](/posts/images/2025-11-14/img77_a.png)

When we fix it, we simply change the instruction to our new relative offset (**E82E7FFFFF**):

![#78](/posts/images/2025-11-14/img78.png)

As a bonus to reinforce this important topic, I challenge you to practice by solving **examples 2 and 3** using the data I provide:

**Example 2:**

*   **Instruction address:** 0x140009118
*   **Original call target address:** 0x140003330
*   **Instruction size:** 7

**Exemplo 3:**

*   **Instruction address:** 0x1400090F0
*   **Original call target address:** 0x1400030D0
*   **Instruction size:** 7

**Note: Solve the examples and send me a DM on Discord or on X with your results!**

**Note:** The full source code of the RIP-relative correction algorithm `applyRelocationFixupsToInstructions` is long and available in the Ryujin project repository on [GitHub - file RyujinObfuscationCore.cc (applyRelocationFixupsToInstructions)](https://github.com/keowu/Ryujin/blob/main/RyujinCore/Ryujin/RyujinCore/RyujinObfuscationCore.cc#L2648).

#### Ryujin Bin2Bin Final Overview

From everything we've covered so far, you, dear reader, now have the foundation needed to understand how Ryujin works end to end. You’re also fully capable of writing your own Bin2Bin: from input, PE parsing, PDB parsing, opcode analysis, disassembler, basic block creation, manipulating basic blocks with your own passes, fully fixing relocations, to generating a fully functional and obfuscated binary. Throughout this article we’ll shift our focus to a topic closely tied to the Bin2Bin: complete deobfuscation of the output binary. In other words, from now on we’ll analyze our output binary and undo its obfuscation, producing a binary that is again fully analyzable, all as a second learning opportunity.

Are you excited for the coming topics?

![#79](/posts/images/2025-11-14/img79.gif)

Deobfuscating Ryūjin
--------------------

In this section we will fully reverse the obfuscation applied to a binary protected by Ryujin. This chapter is intended not only for those **who want to study the topic to learn**, but also for **malware analysts who, for some reason, encounter malware using Ryujin.** One of my concerns with this project was, without a doubt, considering the possibility that a malicious actor could use one of my projects in targeted attacks (it has happened before). So don’t worry: by the end of this section you, whether malware analyst or devoted reader, will be able to completely remove the binary’s obfuscation and analyze it fully.

This section is split into several parts and, at the end, an IDA script will be provided to do the whole job in one go. The topics below are designed to focus on analyzing each technique added, while explaining the steps of an obfuscator analysis. If you already read the Ryujin explanation chapter, you can challenge yourself to solve it on your own first and then check this article for complementary details. The following topics:

*   Techniques and approaches adopted
*   Writing a test binary
*   Analyzing code encryption
*   Identifying obfuscation/protection patterns
*   Removing mutation/junk code
*   Devirtualizing and analyzing the RyujinMiniVm (and its variants)
*   Analyzing auxiliary protection techniques
*   Writing a complete and universal deobfuscator

All right, dear reader, here we go again (another obfuscation article on our blog). Can you picture the mood behind this meme? Let’s have some fun.

![#80](/posts/images/2025-11-14/img80.png)

#### Techniques and approaches adopted

For this article I used the new [IDA Domain](http://ida-domain.docs.hex-rays.com/) that Hex-Rays introduced in IDA 9.2 Beta. They finally made the Python SDK APIs much simpler and more Pythonic, especially compared to the old IDA Python SDK, which was a nasty thin binding over their C API. This API was already discussed in previous posts, such as [Analyzing Mutation-Coded - VM Protect and Alcatraz English](https://keowu.re/posts/Analyzing-Mutation-Coded-VM-Protect-and-Alcatraz-English)).

**Author’s purely personal note:** don’t assume the new `IDA Domain` feature appeared because Hex-Rays had the community or customers in mind; on the contrary, it was a market move prompted by the success of Vector35’s product, Binary Ninja, whose automation was light-years ahead. That taught us something useful and necessary for the security market and competition. I hope Hex-Rays isn’t upset with my comment, but let’s face it: that’s the unvarnished truth.

Besides using `IDA Domain` for Python automation, we’ll also use Visual Studio 2022, MASM Macro Assembler, WinAPI, and so on, to generate a simple binary so we can build test binaries and validate changes in a real analysis.

While following this article, try to read and practice the steps in your own IDA. That will likely make your experience and retention much better. I hope you enjoy the approach. If you have a different method, show me. I’d love to see it (send me a DM on X or Discord).

#### Writing a Test Binary

One of the first approaches we’ll take is to create a test binary that allows us to obfuscate certain parts so we can compare the differences between the original version and the one processed by Ryujin.

In this example, everyone has their own approach. Some like to obfuscate simple mathematical operations, code with few API calls, and so on, either in a single binary or in separate binaries. For example: one binary with only mathematical operations, another only with WinAPI calls, so each technique used by the obfuscator can be explored. For my part I have a slightly different personal approach: I prefer to use Macro Assembler and write my own instructions so I can easily identify my own code.

For this article I prepared an example: a console application written entirely in x64 Assembly and compiled with MASM that makes WinAPI calls. It performs I/O, disk operations and more, all written by hand so we have full control over the generated code, reflecting 1:1 between the compilation result and what we see in a disassembler.

Here is my implementation for our test binary:

![#81](/posts/images/2025-11-14/img81.png)

When we compile the code, it will have some major differences compared to a conventional C/C++ binary that includes its runtime. In our case, the entry point will be `main` itself, since we are writing it manually. When we analyze the binary in IDA, we can see it reflects 1:1 the code we wrote:

![#82](/posts/images/2025-11-14/img82.png)

Besides the code reflecting exactly what we wrote, the binary is extremely small and organized into procedures.

![#83](/posts/images/2025-11-14/img83.png)

With this binary we can easily identify our own procedures and the procedures added by Ryujin. This technique of writing our own x64 Assembly is very useful to make it easier to analyze the behavior of any obfuscator we intend to study.

Now let’s apply Ryujin to this binary we created. I will use the console version. Below is the command I used, followed by an explanation of each option I chose for our test binary:

    RyujinConsole.exe --input RyujinTestingBinary.exe --pdb RyujinTestingBinary.pdb --output RyujinTestingBinary.ryujin.exe --virtualize --junk --encrypt --iat --HVPass --procs executeFun,executeCalculationFun
    

In the command above we define an input binary with the `--input` flag, specify its corresponding PDB file with `--pdb`, and set the output file with `--output`. The following obfuscation passes were defined to run on our binary:

*   Mathematical virtualization using the HVPass feature
*   Import table call protection
*   Junk code and mutation
*   Code encryption

These passes will be executed on the two main procedures of our test binary: `executeFun` and `executeCalculationFun`.

![#84](/posts/images/2025-11-14/img84.gif)

After all these steps, our binary is now protected by Ryujin and more than ready for us to start our analysis. So, let’s go!

![#85](/posts/images/2025-11-14/img85.gif)

#### Analyzing code encryption

One of Ryujin’s capabilities is code encryption, which is a feature we applied to our test binary. It prevents analysis of the obfuscated code, which is stored in the `.Ryujin` section. The code is decrypted at runtime starting from the **binary’s EntryPoint**.

![#86](/posts/images/2025-11-14/img86.png)

The decryption routine is straightforward and nothing out of the ordinary. If we correctly set the types for the structures **IMAGE\_DOS\_HEADER**, **IMAGE\_NT\_HEADERS** and **IMAGE\_SECTION\_HEADER**, everything starts to make more sense and we can identify the **modified XTEA** routine:

![#87](/posts/images/2025-11-14/img87.png)

After applying the correct types, we can clearly see that the main logic to decrypt the obfuscated code focuses on finding the obfuscator’s own section and navigating to the start of the mapped section, then decrypting its opcodes. The stub decrypts byte by byte based on the section size and also takes into account the size of the decrypt stub itself (so it is not corrupted), using the difference of its own size as a reference: `1625` bytes. Check the algorithm logic for decryption:

![#88](/posts/images/2025-11-14/img88.png)

The implementation of the decryption algorithm is very simple and we can easily port it to Python and, consequently, automate the process by replacing the encrypted opcodes with the new ones directly in IDA, using the **ida-domain APIs**.

If we do a **basic OSINT search, common to any good malware analyst**, using GitHub itself, we can easily find the algorithm that originated this implementation:

![#88_1](/posts/images/2025-11-14/img88_1.png)

The algorithm in question is called **TeaDelKew**, which is a modification of conventional **XTEA**.

![#88_2](/posts/images/2025-11-14/img88_2.png)

With that, we have **even more context** to rewrite Ryujin’s encryption algorithm in Python, with the goal of automating the decryption of binaries protected by the same mechanism.

Before we move on to opcode decryption, let’s turn our attention to how the encrypted opcodes are organized when we look at the **.Ryujin section**:

![#89](/posts/images/2025-11-14/img89.png)

As you can see in the screenshot excerpt above of the Ryujin section, the code is completely encrypted. We will reimplement the decryption algorithm in Python and will be fully capable of decrypting the opcodes:

    MASK32 = 0xFFFFFFFF  
      
    XOR_KEYS_BASE = [  
      
        0x77122545, 0x88998877, 0x9944DEAD, 0x10CAFEB4,  
        0x45B0B0C4, 0x35DEADDE, 0x25C4C4C4, 0x85634897,  
        0x56123456, 0x11454545, 0x12323232, 0x95959595,  
      
    ]  
    XOR_KEYS_12 = np.array([np.uint32(x) for x in XOR_KEYS_BASE], dtype=np.uint32)  
      
      
    @njit(parallel=True, nogil=True)  
    def _process_pairs_numba_for_teadelkew(arr32, num_pairs, xorkeys12):  
      
        key_k1 = np.uint32(0x56343698)  
        key_k0 = np.uint32(0xA9BF9BAA)  
        sum_init = np.uint32(0x85862000)  
        delta = np.uint32(0x00B0B0C4)  
      
        for i in prange(num_pairs):  
            off = 2 * i  
            v0 = np.uint32(arr32[off])  
            v1 = np.uint32(arr32[off + 1])  
      
            s = sum_init  
      
            for _ in range(2048):  
                part = np.uint32(((v0 << np.uint32(4)) ^ (v0 >> np.uint32(5))) & np.uint32(MASK32))  
                part = np.uint32((part + v0) & np.uint32(MASK32))  
                tmp = np.uint32((~part) & np.uint32(MASK32)) ^ np.uint32((s + key_k1) & np.uint32(MASK32))  
                v1 = np.uint32((v1 - tmp) & np.uint32(MASK32))  
      
                s = np.uint32((s - delta) & np.uint32(MASK32))  
      
                part2 = np.uint32(((v1 << np.uint32(4)) ^ (v1 >> np.uint32(5))) & np.uint32(MASK32))  
                part2 = np.uint32((part2 + v1) & np.uint32(MASK32))  
                tmp2 = np.uint32((~part2) & np.uint32(MASK32)) ^ np.uint32((s + key_k0) & np.uint32(MASK32))  
                v0 = np.uint32((v0 - tmp2) & np.uint32(MASK32))  
      
            for j in range(2048):  
                key_x = xorkeys12[j % 12]  
                term = np.uint32((np.uint64(j) * np.uint64(0x44444444)) & np.uint64(MASK32))  
                nm = np.uint32((~np.uint32(j)) & np.uint32(MASK32))  
                v1 = np.uint32(v1 ^ key_x ^ term ^ nm)  
                v0 = np.uint32(v0 ^ key_x ^ term ^ nm)  
      
            arr32[off] = np.uint32((~v0) & np.uint32(MASK32))  
            arr32[off + 1] = np.uint32((~v1) & np.uint32(MASK32))  
      
      
    def execute_decrypt(buf: bytearray, stub_size: int = 0):  
        length = len(buf)  
        limit = length - stub_size  
        if limit < 8:  
            return 0  
      
        num_pairs = limit // 8  
      
        arr_full = np.frombuffer(buf, dtype=np.uint32)  
        needed_elems = num_pairs * 2  
      
        made_copy = False  
        if arr_full.size < needed_elems:  
            arr32 = np.frombuffer(bytes(buf), dtype=np.uint32).copy()  
            made_copy = True  
        else:  
            arr32 = arr_full  
      
        _process_pairs_numba_for_teadelkew(arr32, num_pairs, XOR_KEYS_12)  
      
        if made_copy:  
            buf[:arr32.nbytes] = arr32.view(np.uint8)[:arr32.nbytes]  
      
        return num_pairs  
      
      
    def main():  
      
    	# Using ida-domain for get the section opcodes decrypt it with reverse teadelkew algorithm and fixing it back on IDA again.
        with Database.open("RyujinTestingBinary.ryujin.exe.i64", save_on_close=True) as db:  
      
            ryujin_seg = db.segments.get_by_name(".Ryujin")  
            name = db.segments.get_name(ryujin_seg)  
            if name == ".Ryujin":  
      
                section_opcodes = db.bytes.get_bytes_at(ryujin_seg.start_ea, ryujin_seg.end_ea-ryujin_seg.start_ea)  
      
                data = bytearray(section_opcodes)  
      
                blocks = execute_decrypt(data, stub_size=1625)  
      
                db.bytes.set_bytes_at(ryujin_seg.start_ea, builtins.bytes(data))  
      
                db.close()  
      
                print(f"Nyan. we Processed {blocks} 8-byte blocks :D")
    

When analyzing the algorithm above, you can see that I fully reimplemented the **TeaDelKew** decryption logic. The script works as follows:

*   First, we open our `.idb` database of the Ryujin-processed binary.
*   We look for the Ryujin section in the binary and obtain the start and end addresses to collect all the bytes of the respective opcodes.
*   Based on the collected opcodes, we apply, similarly to the process performed at the PE binary’s EntryPoint, the TeaDelKew algorithm to decrypt its content.
*   After decrypting the opcodes, we replace them in their original location.
*   We save and close our `.idb` file of the obfuscated binary.

While writing the script above, dear reader, you will notice that my code became extremely optimized, and there is a good reason for that. The TeaDelKew decryption algorithm is very slow because it works block by block on 4 bytes. To speed up the processing, my approach was to use parallel processing, disable the GIL and use only NumPy bindings.

See the before and after of running our script:

![#90](/posts/images/2025-11-14/img90.gif)

Now that we have the code decrypted, let’s move to the next topic, where we will focus on studying the junk code/mutation pattern.

#### Identifying Obfuscation/Protection Patterns

Finally, we arrive at a very important topic for deobfuscating Ryujin, which is nothing more than a very common technique in deobfuscation procedures. The best way to perform this identification step is to compare the x64 assembly code we wrote manually in the clean binary with the result from the binary protected by the obfuscator.

Let's start a side-by-side comparison between the original and the obfuscated code to see if we can identify patterns in the assembly. I chose the procedure **executeFun** for our analysis:

![#91](/posts/images/2025-11-14/img91.png)

Right at the start of the instructions we can see that the first instruction `push r15` is present in both the original and the obfuscated code. We'll use IDA’s search to check whether we can find the following instruction, `push r14 (41 56)`:

![#92](/posts/images/2025-11-14/img92.png)

By looking for the opcodes corresponding to that instruction, we are able to find the following results:

![#93](/posts/images/2025-11-14/img93.png)

Let's repeat the same test with the next instruction from our original binary `sub rsp, 38h (48 83 EC 38)` so we can check whether it is also present in the Ryujin-processed binary:

![#94](/posts/images/2025-11-14/img94.png)

As we can see, our instructions are still present in the obfuscated code, but they are completely modified. That is the idea behind a mutation/junk code algorithm: to confuse the analyst. Can you, dear reader, spot a pattern among all these instructions we analyzed?

I hope so. We can see a pattern before and after each original instruction:

    popf
    pop r13
    Original Instruction
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    

Let's confirm that pattern by looking at our other procedure, **executeCalculationFun**, in a similar way to the first comparative analysis we performed:

![#95](/posts/images/2025-11-14/img95.png)

Let's search for the second instruction `mov ebx, 0Bh (BB 0B 00 00 00)` to see if the same pattern we identified repeats in the assembly of the code protected by Ryujin:

![#96](/posts/images/2025-11-14/img96.png)

It is possible to confirm that it does. There is a certain pattern in how Ryujin’s mutation/junk code is generated. Notice that the pattern is exactly the same, with a single difference: `pop r15` whereas in the first function we have `pop r13`. Thus, our pattern is based on:

    popf
    pop REG
    Original Instruction
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    

Very well, but you, reader, may have some doubts about why those instructions are there and why they can reveal the junk code pattern. This is very common. A conventional bin2bin obfuscator, and that includes **VmProtect, Themida and similar tools**\*, uses junk code instructions based on registers that are not used by the current procedure and inserts, based on those registers, instructions to create dead code, such as **bitwise operations, flag (eflags) manipulation, memory operations, mathematical operations, and much more**. So the execution context of the code needs to remain consistent in some way, and this is done using the stack itself, either by pushing the register context before performing a given operation and restoring it afterward. Normally not only registers are saved this way; the flags context is often stored with the `pushf` instruction. This is not exclusive to large commercial protectors. it happens in most bin2bins.

Now that we were able to identify a pattern in Ryujin’s junk code/mutation, in the next topic we will write a script to remove that mutation/junk code and analyze things more closely. So, dear reader, are you excited?

![#97](/posts/images/2025-11-14/img97.gif)

#### Removing mutation / Junk Code

Now let's write one more script, this time based on the pattern we found earlier. We will remove all the Junk Code / mutation using **IDA Domain's own APIs.**

The idea of this script is to enumerate all functions in our IDB, find the functions protected by Ryujin, `executeFun` and `executeCalculationFun`, and from there obtain the address of the jump Ryujin inserted to locate the entry point of the mutated code. Then we will enumerate each [insn\_t](https://cpp.docs.hex-rays.com/classinsn__t.html) structure that represents every instruction of the disassembled function in IDA, with the final goal of looking for the pattern we identified before and thus being able to tell real instructions from fake ones.

At first glance, dear reader, this may look very complex. I would even agree with you if we were using the **conventional IDAPython bindings**, that would be a very tedious task. But now, with **IDA Domain**, it becomes much easier. Finally a win, right, dear Ilfak?

To begin, we will use IDA Domain to identify the following jump pattern that Ryujin inserts into the obfuscated functions:

![#98](/posts/images/2025-11-14/img98.png)

As we understood previously in the section about writing a Bin2Bin, Ryujin adds a jump in the original function to its new section created by the obfuscator, and that is how we find the start of the obfuscated code. The following script was created to extract the start address:

    with Database.open("RyujinTestingBinary.ryujin.exe.i64", save_on_close=True) as db:  
        candidates = [ "executeFun", "executeCalculationFun" ]  
        for f in db.functions:  
            if f.name not in candidates:  
                continue  
      
            instr = db.instructions.get_at(f.start_ea)  
            obfuscated_ryujin_executefun = instr.Op1.addr  
            print(f"0x{instr.ea:x} -> {db.instructions.get_disassembly(instr)} -> 0x{obfuscated_ryujin_executefun:x}")
    

In the script above we open Ryujin's IDB and then enumerate each function using the helper `db.functions`, comparing them to the functions we are interested in. When we find one of those functions, we use the helper `db.instructions.get_at` to get the `insn_t` structure for the first instruction of the function, which corresponds to the jump inserted by Ryujin. From that we access the address associated with the `jmp`, that is, the first opcode's `Op1.addr` field, which is the jump destination. Finally, we use the helper `db.instructions.get_disassembly` to get the disassembly string of the instruction and make sure we extracted the correct address.

**Check the output of our script run:**

![#99](/posts/images/2025-11-14/img99.png)

With this first objective completed, now the fun begins: identifying real instructions among the fake ones. We can do this by enumerating every instruction of the function in the obfuscator section and checking whether the pattern `popf, pop reg, real instruction, nop, nop` is present, printing each instruction that matches that pattern so we can verify whether there are any decent results. See the script output followed by its explanation:

    with Database.open("RyujinTestingBinary.ryujin.exe.i64", save_on_close=True) as db:  
        candidates = [ "executeFun", "executeCalculationFun" ]  
        for f in db.functions:  
            if f.name not in candidates:  
                continue  
      
            instr = db.instructions.get_at(f.start_ea)  
            obfuscated_ryujin_executefun = instr.Op1.addr  
            print(f"0x{instr.ea:x} -> {db.instructions.get_disassembly(instr)} -> 0x{obfuscated_ryujin_executefun:x}")
      
            real_instruction_address = []  
            cur_ea = obfuscated_ryujin_executefun  
            instr = db.instructions.get_at(cur_ea)  
      
            while instr is not None:  
                # Looking for a pattern: popf, pop instruction, real instruction, nop  
                if db.instructions.get_mnemonic(instr) == "popf":  
                    ea1 = cur_ea + instr.size  
                    instr2 = db.instructions.get_at(ea1)  
                    if instr2 and db.instructions.get_mnemonic(instr2) == "pop":  
                        ea2 = ea1 + instr2.size  
                        instr3 = db.instructions.get_at(ea2)  
                        if instr3:  
                            ea3 = ea2 + instr3.size  
                            instr4 = db.instructions.get_at(ea3)  
                            if instr4 and db.instructions.get_mnemonic(instr4) == "nop" and db.instructions.get_mnemonic(instr3) != "nop":  
                                print(f"Real instruction at 0x{instr3.ea:x} -> {db.instructions.get_disassembly(instr3)}")  
                                real_instruction_address.append(instr3.ea)  
      
                cur_ea += instr.size  
                instr = db.instructions.get_at(cur_ea)  
      
            print(f"Collected {len(real_instruction_address)} real instruction addresses")
    

In the script above, for each of the functions obfuscated by Ryujin, and right after we obtain the start address in the obfuscator section, we iterate over all instructions in that function. For each `insn_t` we extract its mnemonic with the helper `db.instructions.get_mnemonic`, comparing whether the instructions following the current one also match the pattern we identified. When the pattern is found, we print the instruction and add the instruction's address to a list that will store the real instructions.

**Check the output of our script run:**

![#100](/posts/images/2025-11-14/img100.png)

Okay. To better analyze the results of our script, we redirect stdout to a file and inspect what we found:

![#101](/posts/images/2025-11-14/img101.png)

The script works very well and is fully capable of identifying the real instructions, which is excellent. Although we still have some junk instructions interspersed with the real ones, do not worry: we will leave the remainder to IDA's own symbolic analysis, which is able to remove the vast majority automatically.

![#102](/posts/images/2025-11-14/img102.jpg)

At this point we already have a list of addresses for all the real instructions of the code protected by Ryujin. Let's write a script that eliminates instructions not present in that list, so that the function keeps only the real instructions. Check the logical implementation of this script:

    with Database.open("RyujinTestingBinary.ryujin.exe.i64", save_on_close=True) as db:  
        candidates = [ "executeFun", "executeCalculationFun" ]  
        for f in db.functions:  
            if f.name not in candidates:  
                continue  
      
            instr = db.instructions.get_at(f.start_ea)  
            obfuscated_ryujin_executefun = instr.Op1.addr  
            print(f"0x{instr.ea:x} -> {db.instructions.get_disassembly(instr)} -> 0x{obfuscated_ryujin_executefun:x}")  
      
            real_instruction_address = []  
            cur_ea = obfuscated_ryujin_executefun  
            instr = db.instructions.get_at(cur_ea)  
      
            while instr is not None:  
                # Looking for a pattern: popf, pop instruction, real instruction, nop  
                if db.instructions.get_mnemonic(instr) == "popf":  
                    ea1 = cur_ea + instr.size  
                    instr2 = db.instructions.get_at(ea1)  
                    if instr2 and db.instructions.get_mnemonic(instr2) == "pop":  
                        ea2 = ea1 + instr2.size  
                        instr3 = db.instructions.get_at(ea2)  
                        if instr3:  
                            ea3 = ea2 + instr3.size  
                            instr4 = db.instructions.get_at(ea3)  
                            if instr4 and db.instructions.get_mnemonic(instr4) == "nop" and db.instructions.get_mnemonic(instr3) != "nop":  
                                print(f"Real instruction at 0x{instr3.ea:x} -> {db.instructions.get_disassembly(instr3)}")  
                                real_instruction_address.append(instr3.ea)  
      
                cur_ea += instr.size  
                instr = db.instructions.get_at(cur_ea)  
      
            print(f"Collected {len(real_instruction_address)} real instruction addresses")  
      
            # Gettting procedure function and first instruction  
            cur_ea = obfuscated_ryujin_executefun  
            instr = db.instructions.get_at(cur_ea)  
      
            # Ignore the first instruction of every obfuscated code  
            real_instruction_address.append(instr.ea)  
      
            # make a set to be more fast and precise  
            real_set = set(real_instruction_address)  
      
            last_sum_size = 0  
            while instr is not None:  
                if instr.ea in real_set:  
                    # real instruction, we just skip it!  
                    print(f"Real instruction detected. ignoring... -> 0x{instr.ea:x} {db.instructions.get_disassembly(instr)} ({instr.size} bytes)")  
                else:  
                    # junk/mutation removing all nops instructions by new ones  
                    for i in range(instr.size):  
                        db.bytes.patch_byte_at(instr.ea + i, 0x90)  
                    # print(f"Removed junk/mutation: 0x{instr.ea:x} - {db.instructions.get_disassembly(instr)}")  
      
                cur_ea += instr.size  
                last_sum_size = instr.size  
                instr = db.instructions.get_at(cur_ea)  
      
            # Putting a ret on the end of the deobfuscated function  
            db.bytes.patch_byte_at(cur_ea - last_sum_size, 0xC3)  
      
            print("Finished")  
      
        db.close()
    

Let us understand the new implementation of our script. Right after collecting all addresses of the real instructions, I convert the list to a set for better performance in comparisons and then start again to enumerate each `insn_t` of the function. For each instruction I check whether its address is present in our set of real instructions; if it is, I keep the instruction. Otherwise, I replace each opcode belonging to that instruction with a `NOP(0x90)`, effectively removing it and leaving only what really matters. At the end, I make sure we have a return instruction `ret(0xC3)` and I **save our changes back to the input IDB**.

**Check the output of our script run:**

![#103](/posts/images/2025-11-14/img103.png)

Now let us inspect the results obtained by the script by opening the IDB in IDA. But first, we will make a small configuration to ensure the decompiler can handle our function. By default IDA has a 64k instruction limit for the decompiler, fine for casual decompilation but bad for our case, where Ryujin added far more than 64k instructions that are now just `NOPs(0x90)`. We will adjust this to avoid the [Too Big Function](https://hex-rays.com/blog/igors-tip-of-the-week-166-dealing-with-too-big-function). The change is simple: edit the file `IDA Professional 9.2\cfg\hexrays.cfg`, find the line `MAX_FUNCSIZE`, modify it and save. We will then be ready to continue:

![#104](/posts/images/2025-11-14/img104.png)

Now, after that configuration, we open the **IDB in IDA** and look at the results we achieved.

![#105](/posts/images/2025-11-14/img105.png)

As I mentioned, IDA itself removed the vast majority of false positives. A few still remain, but they are minor for the analysis. We can improve further with a script to filter those instructions or by removing them manually. I chose to do it manually because there are very few, follow the steps:

![#106](/posts/images/2025-11-14/img106.png)

Just replace the opcodes of the invalid instructions with `NOPs(0x90)` again. See the result we reached after removing the invalid instructions.

![#107](/posts/images/2025-11-14/img107.png)

We can further improve the pseudocode by eliminating duplicate variables using **the "=" sign on the keyboard**. I will do that for `v3 = FileA_0`, since it is redundant. See how it looks now:

![#108](/posts/images/2025-11-14/img108.png)

**Much better, right? Now let's see all this in action: the full script run up to opening IDA so we get an overall view of how the script works.**

![#109](/posts/images/2025-11-14/img109.gif)

In short, we solved **Ryujin's Junk Code / mutation** by analyzing the pattern of how the instructions are generated and now we have code we can analyze easily. Let us move forward in our analysis; in the next sections we will reverse additional protection features of Ryujin, **starting with RyujinMiniVM**. Are you excited, dear reader?

![#110](/posts/images/2025-11-14/img110.gif)

#### Devirtualizing and Analyzing RyujinMiniVm (and its variants)

As covered in the Bin2Bin development topics, Ryujin includes support for an extremely simple code virtualization (hence the name MiniVm), intended only for basic arithmetic operators such as **addition, subtraction, multiplication and division**. That proves very useful when you look at code that performs many mathematical operations, since it makes life much harder for whoever analyzes the code.

Picking up from the previous topic, we'll use the same script to remove the **Junk Code/Mutation inserted by Ryujin** in the `executeCalculationFun` routine, which was chosen to receive the RyujinMiniVm protection. There are two RyujinMiniVm variants: the first simply translates the bytecodes and injects the MiniVm stub directly; the second executes the MiniVm and its bytecodes in a completely isolated layer via Hyper-V. In this demo we will address and analyze the second case.

Let's locate where we can find the RyujinMiniVm-protected routine inside a binary protected by it.

![#111](/posts/images/2025-11-14/img111.png)

We will apply the same algorithm as before to remove the procedure's Junk Code/Mutation so we can analyze its real functionality. For that we will use the same script we wrote in [Removing mutation/Junk Code](#removendo-mutacaojunk-code).

After running it we obtain a decent result for our full analysis, check it out:

![#112](/posts/images/2025-11-14/img112.png)

Now let's analyze every detail of this routine. We'll start with how it loads the shellcode of the interpreter for the received bytecodes. We'll analyze the stub that interprets the bytecodes and reimplement it in Python to patch the original call. After that we'll move on to understand how it performs the full guest setup and how it retrieves the result emulated by Hyper-V, returning it to the obfuscated code without breaking compatibility or performance.

##### Extracting and Analyzing the RyujinMiniVm bytecode interpreter

To extract the shellcode stub of the RyujinMiniVm interpreter, it is easy to find its use and assignment entirely via stack usage, as in the example below:

![#113](/posts/images/2025-11-14/img113.png)

We can confirm this is indeed the RyujinMiniVm shellcode we care about simply by checking cross-references.

![#114](/posts/images/2025-11-14/img114.png)

Notice the use of the instruction `0xC3 (ret)` right at the end of the "stack-based array" assignments. Using the stack is an efficient way to make the stub fit in shellcode and produces PIC (Position Independent Code), which means yes, we can extract it and place it in any binary and execute it, **even emulate it with the Unicorn Engine, Bochs, Qiling or Triton.**

However, in this article we will not use emulation; we will only analyze its operation and port it to Python to resolve the bytecodes in place after virtualization. With that in mind, we extract only the bytes that belong to the **RyujinMiniVm** stub shellcode into a binary file so we can open it in IDA. For that I wrote a script using ida-domain and Python to extract each byte from the stack moves and save the content to a file.

    with Database.open("RyujinTestingBinary.ryujin.exe.i64") as db:  
        bytes = bytearray()  
        instr = db.instructions.get_at(0x000000014000EC44)  
        while True:  
            if db.instructions.get_mnemonic(instr) != "nop" and "rsp" in db.instructions.get_operand(instr, 0).__str__():  
                bytes.append(instr.Op2.value) # https://cpp.docs.hex-rays.com/classop__t.html 
                if instr.Op2.value == 0xC3: break  
            instr = db.instructions.get_at(instr.ea + instr.size)  
        open("ryujinminivm.bin", "wb").write(bytes)
    

Simply executing the script above already gives us the output binary file `ryujinminivm.bin`:

![#115](/posts/images/2025-11-14/img115.png)

Now we can drop it into IDA and select that the file contains **x64 Assembly opcodes** to disassemble, and we get the following result:

![#116](/posts/images/2025-11-14/img116.png)

As we can see, this stub is indeed PIC code, meaning it is shared by all binaries protected by Ryujin. In the snippet below:

    mov rdx, 1234567812345678h
    mov rcx, 1234567812345678h
    jmp short $+2
    

This snippet is nothing more than the RyujinMiniVm prologue, where RDX and RCX are configured based on the bytecodes and the context to be interpreted by it.

Right below, specifically at the label **loc\_16** identified by IDA, we can just mark it as the prologue of a function using the letter "P".

![#117](/posts/images/2025-11-14/img117.png)

Marking it as a function allows IDA to decompile it and gives us an excellent view of the **RyujinMiniVm code**. I anticipated the analysis and already renamed the arguments and the function name so we can understand how it works.

![#118](/posts/images/2025-11-14/img118.png)

The logic is extremely simple: RyujinMiniVm is just a mathematical VM, that is, unlike complex virtual machines with many states, opcodes, flags and registers, Ryujin only emulates mathematical operations which, when used in large quantities, hinder third-party analysis.

This VM is not called directly, but indirectly, as in the example below:

![#119](/posts/images/2025-11-14/img119.png)

Notice that the function call is made by resolving the **PEB** and adding the **ImageBase** to a fixed **RVA**. Also, the arguments are obfuscated, meaning the real bytecode to be interpreted by **RyujinMiniVm** is not visible directly. We just reverse the **XOR** to obtain the original input bytecodes for RyujinMiniVm: `0x33E51E ^ 0x0E414 = 0x33010A`. That gives us the initial execution state for **RyujinMiniVm.** This initial state is loaded into register RDX. RCX loads the former RAX with the previous calculation value; this way we get the states needed to simulate an input. Let’s rewrite **RyujinMiniVm** in Python:

    def run_ryujin_minivm(current_state, ryujin_bytecode):  
      
        opcode = (ryujin_bytecode >> 8) & 0xFF  
        operand = ryujin_bytecode & 0xFF
        
        if opcode == 1:  
            return current_state + operand  
        elif opcode == 2:  
            return current_state - operand  
        elif opcode == 3:  
            return current_state * operand  
        elif opcode == 4:  
            return current_state / operand  
      
        return 0  
      
      
    print(run_ryujin_minivm(0, 0x33010A)) # Result here should be 10 because our operand is 0x0A and theres no current_state register
    

With **RyujinMiniVm** rewritten in Python we can write an automation script to extract the bytecodes used by routines and feed them to our script above, inserting a comment with the result and translation, including the exact value of the mathematical operation that would be performed. See the automation result:

    with ida_domain.Database.open("RyujinTestingBinary.ryujin.exe.i64") as idb:  
      
        ryujin_section = idb.segments.get_by_name(".Ryujin")  
      
        current_ea = ryujin_section.start_ea  
        instr = idb.instructions.get_at(current_ea)  
        while True:  
      
            operand = idb.instructions.get_operand(instr, 0)  
            mnemonic = idb.instructions.get_mnemonic(instr)  
      
      
            # Wrapper porque o ida-domain sucks  
            def safe_operand_str(op):  
                try:  
                    return str(op)  
                except ValueError:  
                    return None  
      
            op_str = safe_operand_str(operand)  
            if op_str and mnemonic:  
                if "rdx" in op_str and mnemonic == "mov":  
                    instr1 = idb.instructions.get_at(current_ea + instr.size)  
                    operand1 = idb.instructions.get_operand(instr1, 0)  
                    mnemonic1 = idb.instructions.get_mnemonic(instr1)  
      
                    op1_str = safe_operand_str(operand1)  
                    if op1_str and mnemonic1:  
                        if "rdx" in op1_str and mnemonic1 == "xor":  
                            instr2 = idb.instructions.get_at(current_ea + instr.size + instr1.size)  
                            if idb.instructions.get_mnemonic(instr2) == "rdgsbase":  
                                bytecodesryujin = instr.Op2.value ^ instr1.Op2.value  
                                string_info = f"Executing: 0x{instr.ea:x} bytecode({bytecodesryujin:x}) -> 0x{run_ryujin_minivm(0, bytecodesryujin) :x}"  
    							idb.comments.set_at(instr.ea, string_info)  
    							print(string_info) 
      
            current_ea += instr.size  
            if current_ea >= ryujin_section.end_ea:  
                break  
      
            instr = idb.instructions.get_at(current_ea)  
            if not instr:  
                break  
      
        idb.close()
    

**Execution result:**

![#120](/posts/images/2025-11-14/img120.png)

Now that we have the interpreter for **RyujinMiniVm**, let's move on to analyze how **Ryujin** uses Hyper-V to run it in isolation, making analysis harder.

#### Analyzing Ryujin's virtualization implementation via Microsoft Hyper-V APIs to run RyujinMiniVM

Before we analyze this implementation, we need to import some new types into IDA. This is done through an adjusted header file. This time we will import a modified version of `WinHvApiDefs.h` that is [**available in the following gist**](https://gist.github.com/keowu/24ba5cb52b338bd2205e7c0de70572f9). With the gist content copied and the Ryujin IDB open, go to `Views -> Open Subviews -> Local Types`, right-click and select `Add Type`, then click **OK**. That provides everything necessary to find the types and function declarations; some will be automatically recognized by IDA’s decompiler and reflected in the pseudocode:

![#121](/posts/images/2025-11-14/img121.png)

With everything ready, IDA already discovered some types automatically, and for others, like ENUMs, you may need to define them manually, as in the example below (key **M**):

![#122](/posts/images/2025-11-14/img122.png)

Let's separate the analysis results and demonstrate how each part works in its place.

**RyujinMiniVM** operation is based on these steps:

1.  Find **Kernel32** exports: `VirtualAlloc`, `VirtualFree`.
2.  Find the `LdrLoadDll` export from **NTDLL**.
3.  Load `WinHvPlatform.dll` using `LdrLoadDll`.
4.  Check virtualization capability, and create a partition if virtualization is enabled and the host supports it.
5.  Allocate memory on the host and map it into the guest with `MapGpaRange`.
6.  Configure the environment for a minimal x64 runtime, setting up page tables **(PML4/PDPT/PD/PT)**, **reserving GPAs**, **stack**, **and so on**.
7.  Configure the **RyujinStub arguments (previous register context, bytecode to execute)**, ensuring a `hlt` instruction.
8.  Create a **Virtual Processor** and set the **register context (RIP, RSP, CR0, CR3, CR4, EFER, segment descriptors, GDTR, IDTR, PAT and MSRs)**.
9.  Prepare a **loop** and **run the Virtual Processor**, capturing each exception in **search of a HLT**.
10.  Extract the execution result from the **register context (RAX)**.
11.  Clean up and return.

Many steps? Indeed, since a full guest is being configured.

![#123](/posts/images/2025-11-14/img123.jpg)

During the explanation I will not focus on steps I consider basic for anyone reading this article (like PEB resolution). Therefore we will stick to what actually matters.

**A note about Hyper-V:** it does not require the process to have an elevated administrator token, unlike other operating systems. In other words, any process, as long as virtualization is enabled, can configure a guest and run it. Is that good? Depends, would you trust that? **This technique is quite different from Microsoft VBS / Secure Enclave, for example.** While in VBS / Secure Enclaves we are limited to predefined APIs that are, in a way, less risky, with Hyper-V and a properly configured guest this is not a limitation... yes, I am referring to malware and APTs here.

Configuring the **RyujinMiniVM Stub** shellcode:

![#124](/posts/images/2025-11-14/img124.png)

Each byte is moved to the stack to build an "array" with the bytes that will be mapped into guest memory for execution.

Loading `WinHvPlatform.dll` via `LdrLoadDll`:

![#125](/posts/images/2025-11-14/img125.png)

Resolving `WhvGetCapability`, `WHvCreatePartition`, `WHvSetupPartition`, `WHvMapGpaRange`, `WHvCreateVirtualProcessor`, `WHvSetVirtualProcessorRegisters`, `WHvGetVirtualProcessorRegisters`, `WHvDeleteVirtualProcessor`, `WHvUnmapGpaRange`, `WHvDeletePartition` and `WHvRunVirtualProcessor` via the Export Directory:

![#126](/posts/images/2025-11-14/img126.png)

Checking hypervisor **support capability, creating and configuring a partition and configuring a processor to execute** the RyujinMiniVM Stub in that partition:

![#127](/posts/images/2025-11-14/img127.png)

Mapping **virtual memory** for emulation and **mapping GPA** for the **guest**:

![#128](/posts/images/2025-11-14/img128.png)

Setting up **page tables** and the **GDT** in guest memory:

![#129](/posts/images/2025-11-14/img129.png)

Defining **the entry stub register context and setting the Ryujin bytecode for execution in the RyujinMiniVM entry shellcode**, ensuring a final **HLT instruction** to trigger an exception for the **HOST**: ![#130](/posts/images/2025-11-14/img130.png)

Preparing the **Virtual Processor** and **setting up registers to start execution** of the **guest's** single processor:

![#131](/posts/images/2025-11-14/img131.png) Execution loop: running the **Virtual Processor** while waiting to reach the **HLT interrupt** so we can extract the result processed by the **guest** for the **host**:

![#132](/posts/images/2025-11-14/img132.png)

**Cleaning up** and returning the result extracted from the **guest** to the **host** so the original code can resume:

![#133](/posts/images/2025-11-14/img133.png)

That concludes the analysis of RyujinMiniVM and its variants, but it's not over yet. Next we'll explore auxiliary protection techniques such as **Anti-Debug**, **Memory Protection** and **Anti-Tamper**. Let’s go!

![#134](/posts/images/2025-11-14/img134.png)

#### Analyzing auxiliary protection techniques

Now we arrive at the final topic for manual deobfuscation of Ryujin. We'll now focus on extra techniques that, in the context of difficult analysis, are considered cheap tricks for someone doing static analysis: Anti-Debug (with and without the Troll Reverser feature), Memory Protection and Anti-Dumper. I will skip over topics I consider extremely basic, such as resolving modules via the PEB and similar.

##### Analyzing Anti-Debug and Troll Reversers

After running the script to remove the **Junkcode/Mutation** and, of course, **ignoring the NOP instructions**, we can see the stub inserted by **Ryujin** to apply its **Anti-Debug** technique with the **Troll Reverser** feature.

![#135](/posts/images/2025-11-14/img135.png)

The mechanism is extremely simple. If I had to summarize it: **stupid, overused techniques.** However, there is something relevant here: the **Troll Reverser**. I expect at least a minimal knowledge from anyone reading this article about the **PEB → BeingDebugged** (internal wrapper around `IsDebuggerPresent`) and Debug Control. I will skip the basics and focus, as briefly as possible, on how Troll Reverser works.

Snippet with complete debugger detection, using **NtSystemDebugControl**, **NtQuerySystemInformation** and the **BeingDebugged** flag:

![#136](/posts/images/2025-11-14/img136.png)

The most interesting point here is how a **blue screen (BSOD)** is triggered as soon as a debugger is detected. This is done by exploiting an OS behavior where, with just a token holding the **SE\_SHUTDOWN\_PRIVILEGE** permission, it is possible to call **RaiseHardError** to provoke an unrecoverable multiplication error. This API is exposed for use by **lsass.exe** to recover from such errors, but it has been abused not only by Ryujin but also by malware, anticheats and others.

##### Analyzing Anti-Dumper

After running the **mutation/junkcode** removal script and hiding the **NOP instructions**, we can easily identify the **anti-dump routine** that corrupts the binary resulting from dumps taken by tools like **Scylla Hide** or **OllyDumpEx**.

![#137](/posts/images/2025-11-14/img137.png)

The technique for this anti-dumper feature is already known and common, used by several **anti-cheat** solutions and protectors. Abstracting the API resolution via the PEB and similar, there is a parsing of the PE header looking for the first section and, from there, we unprotect the memory page to allow writing, **zero out all bytes of the section header structure**, and restore the permission to read-only.

![#138](/posts/images/2025-11-14/img138.png)

##### Analyzing Memory Protection

After running the script to remove **Junk Code/Mutation** and hide the **NOP instructions**, we can easily find the stub responsible for the memory protection of the binary protected by **Ryujin**.

![#139](/posts/images/2025-11-14/img139.png)

Skipping basic concepts like resolving the PEB to locate **ntdll** and its exports in search of **NtTerminateProcess**, and focusing only on what matters, the operation of this feature is quite simple at first glance: it finds the **.Ryujin** section, then **calculates the CRC of the section's contents**, and finally **compares the calculated CRC with the stored CRC**.

Abstracting basic concepts, such as resolving the PEB to `ntdll` and exporting it to find **NtTerminateProcess**, and focusing only on what matters, the behaviour is, in principle, the following: the **.Ryujin** section is located; the **CRC of that section's contents is calculated**; then the **calculated CRC is compared with the stored CRC**.

![#140](/posts/images/2025-11-14/img140.png) After locating the **.Ryujin** section, we save its **IMAGE\_SECTION\_HEADER** structure to be used in the **CRC calculation**:

![#141](/posts/images/2025-11-14/img141.png)

Finally, with the calculated CRC result, we compare that value with the **value stored by Ryujin** and, if they differ, a call to **NtTerminateProcess** is made to end execution:

![#142](/posts/images/2025-11-14/img142.png)

The **CRC value is stored by Ryujin during the obfuscation process**, where the same algorithm is applied and the CRC result is saved in the **PointerToLinenumbers** field of the **IMAGE\_SECTION\_HEADER**. This feature works well, but when the reverser understands how it works, one can easily patch it: recalculate the CRC and write it back into the header, allowing the process to run normally.

![#143](/posts/images/2025-11-14/img143.png)

So, we have reached the end of another Ryujin deobfuscation topic. From here, we will cover a plugin developed by a friend to help with automatic deobfuscation; we will present some practical tips for the reader and, finally, the conclusion. Ready to finish this journey?!

![#144](/posts/images/2025-11-14/img144.png)

#### Writing a Universal Deobfuscation Plugin

While writing this article, one of my reviewers developed a plugin nicknamed **Ryujin-RE**, based on the scripts and the deobfuscation topic. You can find and study it in the **[following GitHub repository](https://github.com/rem0obb/ryujin-re)**.

Using the plugin is straightforward. Here’s an example of decrypting Ryujin’s section with it:

    python .\cli.py -f DemoObfuscation.ryujin.exe  -d
    

![#146](/posts/images/2025-11-14/img146.png)

In the end, we’ll get the decrypted file without any major issues:

![#147](/posts/images/2025-11-14/img147.png)

For other commands, features, and to study the implementation of the **Ryujin-RE** plugin, check the **[project’s README on GitHub](https://github.com/rem0obb/ryujin-re/blob/dev/README.md)**.

#### Practice

In this section, I’ve prepared a hands-on exercise for you, dear reader. I’ll provide a code sample that you can compile and follow step-by-step to analyze a binary protected by Ryujin on your own, so you can better understand all the material covered in this article.

Consider the following code and compile it in **Release-x64** mode using any compiler you prefer (as long as it generates a **.pdb** file):

    #include <windows.h>
    #include <iostream>
    #include <cstdio>
    #include <string>
    #include <cstdint>
    
    uint32_t sum(uint32_t n20) {
    
        return n20 + 10;
    }
    
    uint32_t sub(uint32_t n10) {
    
        return 20 - n10;
    }
    
    uint32_t subadd(uint32_t n400) {
    
        return n400 + 8;
    }
    
    int __cdecl main(int argc, const char** argv, const char** envp) {
    
        std::cout << "Hello World!\n";
        std::printf("Hello World..\n");
        std::printf("Xdxd..\n");
    
        uint32_t v3 = sum(20);
        std::printf("%x\n", v3);
    
        uint32_t v4 = sub(10);
        std::printf("%x\n", v4);
    
        uint32_t v5 = subadd(400);
        std::printf("%x\n", v5);
    
        char username[256] = { 0 };
        DWORD username_len = sizeof(username);
        if (GetUserNameA(username, &username_len))
            std::printf("Username: %s\n", username);
    
        SYSTEMTIME st;
        GetSystemTime(&st);
        std::printf("Current system time: %02u:%02u:%02u\n",
            static_cast<unsigned>(st.wHour),
            static_cast<unsigned>(st.wMinute),
            static_cast<unsigned>(st.wSecond));
    
        char computerName[256] = { 0 };
        DWORD comp_len = sizeof(computerName);
        if (GetComputerNameA(computerName, &comp_len))
            std::printf("Computer Name: %s\n", computerName);
    
        MessageBoxA(nullptr, "Ola mundo...", "Ola Mundo...", MB_ICONINFORMATION);
        
        Beep(0x2EEu, 0x12Cu);
    
        std::cin.get();
    
        return 0;
    }
    

With the binary and PDB ready, and with the Ryujin binaries available, run the following command:

    RyujinConsole.exe --input DemoObfuscation.exe --pdb DemoObfuscation.pdb --output DemoObfuscation.Ryujin.exe --junk --encrypt --iat --procs main
    

We’ll use the maximum obfuscation settings in this exercise. After execution, you’ll see something like this:

![#145](/posts/images/2025-11-14/img145.png)

Based on this protected binary, analyze it and implement the following extra feature by extending Ryujin through custom passes:

1.  Deobfuscate the protected binary and write a report detailing the steps taken.
2.  Write a script to analyze **Ryujin**, or use the **Ryujin-RE** plugin mentioned earlier.
3.  Implement a **Custom Pass** in the **Ryujin Console**, recompile it, and demonstrate its execution.

Once completed, if you’d like personalized feedback or assistance, feel free to contact me on Discord or X.

**Bonus:** Writing an _MBA Obfuscation Pass_ for Ryujin
-------------------------------------------------------

As a bonus topic, we’ll **extend** Ryujin’s capabilities by implementing a **completely new obfuscation pass** based on **Linear-MBA (Mixed Boolean-Arithmetic)**, using only **a single callback** that will be registered during Ryujin’s setup.

For this feature’s implementation, I’ll use **Z3-Solver-C** to ensure **result equivalence**. Additionally, I’ll generate expressions that reproduce the same behavior as the basic mathematical instructions (**add, sub, xor, and, or**), making sure they are properly obfuscated while preserving the expected final outcome.

First, we’ll add a sample code containing several basic mathematical operations to assist in developing this pass. Consider the following code:

![#148](/posts/images/2025-11-14/img148.png)

The test code is simple and only exists to validate our implementation of the Ryujin pass. You can get the full code from [Ryujin Repository](https://github.com/keowu/Ryujin/blob/b50f2cebc1cfba3561100605f02bbf5646d2e4d2/TestsBinary/DemoObfuscation/DemoObfuscation.cc#L8). Consider using it if you want to modify or study the logic used to generate the MBAs.

As a first step, we’ll define a new callback following the signature expected by Ryujin:

    void RyujinMBAObfuscationPass(RyujinProcedure* proc) 
    

And, during the Ryujin Core startup, we’ll register/configure it so Ryujin Core can recognize and use it:

![#149](/posts/images/2025-11-14/img149.png)

As covered earlier, this callback receives the `RyujinProcedure` class, which manages the procedure candidate for obfuscation and its entire composition.

The MBA obfuscation logic works by enumerating each **basic block** and, for each one, its respective **Opcodes** and **Instructions**, with the goal of identifying arithmetic operation instructions and extracting immediate values, only for procedures whose name has the `mba_` prefix. Then it checks whether the instructions can accept a new **expression** based on the **equivalence** technique with Z3. If the `Linear-MBA` and `Original` expressions are equivalent, they are replaced by the new ones.

Let’s break that down in detail, starting with checking the `mba_` prefix in the candidate procedure name (`proc->name`), followed by enumerating every **opcode** in each **basic block** of that procedure:

![#150](/posts/images/2025-11-14/img150.png)

For each **Opcode/Instruction** we check whether it’s an arithmetic operation candidate to receive a **Linear-MBA expression** (`ADD`, `SUB`, `XOR`, `AND`, `OR`).

![#151](/posts/images/2025-11-14/img151.png)

We test equivalence between the **Original Expressions** and the **Linear-MBA Expressions** using Z3:

![#152](/posts/images/2025-11-14/img152.png)

If the **Original** and **Linear-MBA** expressions are equivalent (i.e., satisfiable `"sat"`) and produce the **same expected final result**, new instructions are inserted with the **modified expressions**, ensuring obfuscation without altering the procedure’s behavior, while significantly increasing its complexity.

![#153](/posts/images/2025-11-14/img153.png)

Since the **expressions are linear in the Linear-MBA**, they are not generated dynamically, they are **static**, and Z3 guarantees they produce the expected result. The expressions are categorized according to the candidate instruction type (`add`, `sub`, `xor`, `and`, `or`). The algorithm also correctly preserves the register context, preventing interference with other registers, aligning address references, and handling other necessary details. Note that this entire implementation was done **solely by extending Ryujin with a Custom Pass**, demonstrating how you can modify and build even more advanced passes.

After processing, the new opcodes with **MBA-Linear expressions** are generated via **ASMJIT** and inserted into the corresponding **Basic Blocks**, so that the **Ryujin Core** reflects these modifications and updates the context after the pass execution, impacting the final output binary:

![#154](/posts/images/2025-11-14/img154.png)

All implementation code supporting **MBA-Linear** is available in [RyujinCustomPass.hh - RyujinMBAObfuscationPass](https://github.com/keowu/Ryujin/blob/1a96cc67e664c68c97eb8de2556ff2c68ed7940a/RyujinConsole/RyujinConsole/RyujinCustomPasses.hh#L50).

The End
-------

We’ve reached the end of another article. Developing Ryujin was quite an adventure, along with my reviewers and friends who contributed to this work. It was a valuable learning experience for all of us, and despite the challenges, we managed to overcome them. I’ve done my best to share the knowledge I gained throughout this project in this article. I hope I’ve made a meaningful contribution to you, dear reader, and perhaps sparked your interest in Bin2Bin protectors. I’m truly grateful for the time you spent reading this. If you have any questions, feel free to reach out to me on X or Discord.

Thank you so much, Keowu

References
----------

As a demonstration of respect and consideration for the authors studied during the writing of this article, we followed the standards set by [ABNT Guidelines](https://www.marilia.unesp.br/#!/laboratorio-editorial/procedimentos-publicacoes/normas-da-abnt--citacoes-e-referencias/). Knowledge is never built alone.

A dive into the PE file format - PE file structure - Part 1: Overview. Disponível em: [https://0xrick.github.io/win-internals/pe7/](https://0xrick.github.io/win-internals/pe7/).

BACK.ENGINEERING's Bin2Bin TECHNOLOGY Will Change Everything! \[vídeo online\]. YouTube. Disponível em: [https://www.youtube.com/watch?v=3LOGxOHfUHg](https://www.youtube.com/watch?v=3LOGxOHfUHg).

BinaryShield: a bin2bin x86-64 code virtualizer. Disponível em: [https://connorjaydunn.github.io/blog/posts/binaryshield-a-bin2bin-x86-64-code-virtualizer/](https://connorjaydunn.github.io/blog/posts/binaryshield-a-bin2bin-x86-64-code-virtualizer/).

JIN, Hongjoo et al. asmMBA: Robust Virtualization Obfuscation with Assembly-Based Mixed Boolean-Arithmetic. Disponível em: [https://dl.acm.org/doi/pdf/10.1145/3672608.3707862](https://dl.acm.org/doi/pdf/10.1145/3672608.3707862).

Obfuscating native code for fun: Part 1 - Introduction. Disponível em: [https://blog.es3n1n.eu/posts/obfuscator-pt-1/](https://blog.es3n1n.eu/posts/obfuscator-pt-1/).

Obfuscator.re — OMVLL / Passes / Arithmetic. Disponível em: [https://obfuscator.re/omvll/passes/arithmetic/](https://obfuscator.re/omvll/passes/arithmetic/).

Off-By-One 2025 Day 2: Jordan Wiens - Breaking Decompilers \[vídeo online\]. YouTube. Disponível em: [https://youtu.be/6UlxrDYng88](https://youtu.be/6UlxrDYng88).

TIGRESS — encodeArithmetic. Disponível em: [https://tigress.wtf/encodeArithmetic.html](https://tigress.wtf/encodeArithmetic.html).

weak1337. Alcatraz: x64 binary obfuscator. GitHub. Disponível em: [https://github.com/weak1337/Alcatraz](https://github.com/weak1337/Alcatraz).

Writing a PE packer – Intro. Disponível em: [https://wirediver.com/tutorial-writing-a-pe-packer-intro/](https://wirediver.com/tutorial-writing-a-pe-packer-intro/).

Content Under Creative Commons License

This content is provided under the CC BY 4.0

[Learn More](https://creativecommons.org/licenses/by/4.0/)