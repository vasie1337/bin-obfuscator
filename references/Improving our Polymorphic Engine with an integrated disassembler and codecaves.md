
Same-Same But Better: Improving our Polymorphic Engine with an integrated disassembler and codecaves
====================================================================================================

[

![0x0vid](https://miro.medium.com/v2/resize:fill:64:64/1*HjaAQ_ZKbmwHrLeSI8cdfg.jpeg)





](/@0x0vid?source=post_page---byline--447377ab00e6---------------------------------------)

[0x0vid](/@0x0vid?source=post_page---byline--447377ab00e6---------------------------------------)

14 min read

·

Dec 16, 2023

[

](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fp%2F447377ab00e6&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%400x0vid%2Fsame-same-but-better-improving-our-polymorphic-engine-with-an-integrated-disassembler-and-447377ab00e6&user=0x0vid&userId=ff32b62d4ee&source=---header_actions--447377ab00e6---------------------clap_footer------------------)

\--

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fbookmark%2Fp%2F447377ab00e6&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%400x0vid%2Fsame-same-but-better-improving-our-polymorphic-engine-with-an-integrated-disassembler-and-447377ab00e6&source=---header_actions--447377ab00e6---------------------bookmark_footer------------------)

Listen

Share

_TL;DR — editing straight ASM code in a compiled PE file is hard, and there is little to no room for error … but damn it feels nice when it works!_

In this post, we will be improving on the keyless-polymorpich post-processing script we made last time, the main improvement will be the integration of capstone for disassembly and then since this uses a different format for the output we will also need to re-implement our MOV substitution. In addition to those tasks, we will also be implementing obfuscation via codecaves, i.e. places in the binary where no useful instructions are located. All this will be done in an attempt to change our binary without having to make any changes to the code.

In short, the improvements are:

*   including capstone disassembler
*   cleaning up code
*   implementing code caves

Implementing capstone
---------------------

To start off we take our previous implementation of this concept and rewrite more or less everything using capstone for our disassembler. This will let us skip the manual step of having to run objdump before being able to carry out any modifications.

[

GitHub - qemu/capstone: Mirror of git://qemu.org/capstone.git
-------------------------------------------------------------

### Mirror of git://qemu.org/capstone.git. Contribute to qemu/capstone development by creating an account on GitHub.

github.com



](https://github.com/qemu/capstone/tree/master?source=post_page-----447377ab00e6---------------------------------------)

The reason I did not use it in the original implementation was that I had some issues with the documentation and how to effectively use it in my code, but after looking at many examples and the limited documentation available I got to a level of knowledge where it made sense to implement it here.

So now we have a proper disassembler and a general idea of what we want to do, so let's get started.

[

Create your own disassembler in python (pefile & capstone)
----------------------------------------------------------

### Without any introductions, if you want to disassemble an exe file using python, you will need two libraries: pefile and…

isleem.medium.com



](https://isleem.medium.com/create-your-own-disassembler-in-python-pefile-capstone-754f863b2e1c?source=post_page-----447377ab00e6---------------------------------------)

First let's see if the code above produces the correct results, since we are using 64-bit applications we first need to change the architecture used (_md = Cs(CS\_ARCH\_X86, CS\_MODE\_64)_), while we are doing this we can also clean up the code a bit to remove the dependency on comments.

Press enter or click to view image in full size

Output compared to disassembly

The code is still not as clean as we like it but we will deal with that later, for now, we just need our PoC. here is the code to produce the result above.

import pefile  
from capstone import \*  
  
def getAddressOfSections(sections):  
    addresses = \[\]  
    for section in sections:   
        addresses.append(section.VirtualAddress)  
    return addresses  
  
def getMainCodeSection(sections, base\_of\_code):  
    addresses = \[\]  
    addresses = getAddressOfSections(sections)  
          
    #if the address of section corresponds to the first instruction then  
    #this section should be the main code section  
    if base\_of\_code in addresses:      
        return sections\[addresses.index(base\_of\_code)\]  
    #otherwise, sort addresses and look for the interval to which the base of code  
    #belongs  
    else:  
        addresses.append(base\_of\_code)  
        addresses.sort()  
        if addresses.index(base\_of\_code)!= 0:  
            return sections\[addresses.index(base\_of\_code)-1\]  
        else:  
            #this means we failed to locate it  
            return None  
  
def getDisassembly(exe):  
    mainCodeSection = getMainCodeSection(exe.sections, exe.OPTIONAL\_HEADER.BaseOfCode)  
    #define architecutre of the machine   
    md = Cs(CS\_ARCH\_X86, CS\_MODE\_64)  
    md.detail = True  
    beginOfCodeSection = mainCodeSection.PointerToRawData  
    endOfCodeSection = beginOfCodeSection + mainCodeSection.SizeOfRawData  
  
    data = exe.get\_memory\_mapped\_image()\[beginOfCodeSection:endOfCodeSection\]  
    j = 0  
    for i in md.disasm(data, beginOfCodeSection):  
        j += 1  
        if j < 200:  
            print(i.mnemonic, i.op\_str)  
  
  print("\[+\] Done")  
  
exe\_file\_path = '.\\calc.bak.exe'  
  
try:  
    parsedPeFile = pefile.PE(exe\_file\_path)  
except:  
    print('\[Error\] pefile cannot parse this file')  
    quit(-1)  
  
try:  
    getDisassembly(parsedPeFile)  
except:  
    print('\[Error\] something is wrong with this exe file')  
    quit(-1)

(Re)Implementing MOV substitution
---------------------------------

Reusing the code from the last article, we can quickly re-implement the MOV substitution.

def getOldRegisters(op\_str): # i.e. RAX, RCX, but not r10 etc.  
    registers = \[\]  
    if not re.findall("word", op\_str):  
        registerRegex = "(\[r\]\[abcd\]x|\[r\]\[bsd\]\[ip\])"  
        registers = re.findall(registerRegex, op\_str)  
    return registers  
  
def substituteMov(registers):  
    print("\\tRegisters:", registers)  
    REG = getMovRegByte("push", registers\[1\]) + 0x50  
    REG1 = getMovRegByte("pop", registers\[0\]) + 0x50  
    print("\\tTransformed to: PUSH", registers\[1\], "; POP", registers\[0\], "| bytes:", hex(REG), ";", hex(REG1) )  
    return REG, REG1  
  
def getMovRegByte(instruction, reg):  
    regByte = 0  
    reg = reg.replace('%','')  
    match reg:  
        case "eax" | "rax":  
            regByte = 0  
        case "ecx" | "rcx":  
            regByte = 1  
        case "edx" | "rdx":  
            regByte = 2  
        case "ebx" | "rbx":  
            regByte = 3  
        case "esp" | "rsp":  
            regByte = 4  
        case "ebp" | "rbp":  
            regByte = 5  
        case "esi" | "rsi":  
            regByte = 6  
        case "edi" | "rdi":  
            regByte = 7  
    if instruction == "pop":  
        regByte += 8  
    return regByte  
  
for i in disassembly:  
    if i.op\_str != "":  
        registers = getOldRegisters(i.op\_str)  
  
    if i.mnemonic == 'mov' and len(registers) == 2:  
        print("MOV found", i.mnemonic, i.op\_str, "@", hex(i.address - 0x400))  
        reg, reg1 = substituteMov(registers)  
        modifiedByteArray.append(bytearray(\[reg\]))  
        modifiedByteArray.append(bytearray(\[reg1\]))  
        modifiedByteArray.append(bytearray(b'\\x90'))  
    else:  
        modifiedByteArray.append(i.bytes)

When we run the code we now see that the instructions where the R\*X registers are being MOV’ed are getting “replaced”.

Modified instructions

\[Originally here I had a whole thing where I tried to append additional bytes to the file, but that is way beyond the scope of what I'm trying to do here so let's move on to something fun instead … if you are curious it failed miserably\]

Writing to File
---------------

Now we know that the correct bytes are getting modified, next, we need to write the updated .text section to the binary. For this, we basically just do the same as in my original post on polymorphism:

[

Same-Same but different: A Dive Into Keyless-polymorphism
---------------------------------------------------------

### TL;DR: Change bytes to change the look and signature of your files without changing the functionality and without…

medium.com



](/@0x0vid/same-same-but-different-a-dive-into-keyless-polymorphism-7570c1def3e2?source=post_page-----447377ab00e6---------------------------------------)

The code looks like this, and when we run the binary it works!

print("Creating Morphed binary")  
  
src = "calc.bak.exe"  
dst = "morphed\_calc.bak.exe"  
print("\[+\] Copying file. From: ", src, "to:", dst)  
shutil.copyfile(src, dst)  
  
\# then this is just used to update the .text section  
print(len(modifiedByteArray))  
finalTextSection = bytearray(b'')  
for morphedBytes in modifiedByteArray:  
    for byteInMorphedBytes in morphedBytes:  
        finalTextSection.append(byteInMorphedBytes)  
  
textSectionOffset = 0  
for section in parsedPeFile.sections:   
    if section.Name == mainCodeSection.Name:  
        print("\[+\] Getting info for:",section.Name)  
        textSectionOffset = section.PointerToRawData  
  
with open("morphed\_calc.bak.exe", "rb+") as binary\_file:  
    binary\_file.seek(textSectionOffset)  
    print(hex(textSectionOffset))  
    binary\_file.write(finalTextSection)

The code above is still missing randomization, but we can steal this as well from the implementation in the post.

Codecaves for Obfuscation
-------------------------

Quicky, what are code caves? in short, codecaves are just pieces of “dead”/unused code that we can modify without it impacting the function of the application, for more see the excellent article below:

[

The Beginners Guide to Codecaves
--------------------------------

### This is a complete beginners guide to codecaves that covers the main topics of: what a codecave is, what a codecave can…

www.codeproject.com



](https://www.codeproject.com/Articles/20240/The-Beginners-Guide-to-Codecaves?source=post_page-----447377ab00e6---------------------------------------#CodecaveAttributes2)

So what will we be using them for is that we will fill some of them with junk code to add to the obfuscation of the binary and ensure that both the signature will be random each time as well as obfuscate the codeflow.

Example of codecave

Finding codecaves
-----------------

to find codecaves we will scan through the binary and identify places in the code where multiple INT3 instructions are placed back to back. For this, we just add a similar rule to the one looking for MOV instructions. For this we will also need a data structure to keep track of all the codecaves we find, since we are using a list to keep track of the changes we make to the .text section we can just use the index of the list for the address. We add the following code to our walk through the disassembly.

if i.mnemonic == 'int3':  
        print("\\t\[>\] INT3 found", "@", hex(i.address - 0x400), "getting size and adding to codecavesList")  
        modifiedByteArray.append(i.bytes)  
        codecaveSize += 1  
        while True:  
            tempDissas = next(disassembly)  
            if tempDissas.mnemonic == 'int3':  
                modifiedByteArray.append(i.bytes)  
                codecaveSize += 1  
            else:  
                break  
        codecavesList.append(codecave(len(modifiedByteArray) - codecaveSize, codecaveSize))

to test this we use the following code to set a NOP at the start of each codecave. we then inspect the resulting binary

for cc in codecavesList:  
    modifiedByteArray\[cc.index\]= b'\\x90'

Codecaves now start with NOP instruction

Success! The next step is to find uses for them

Using codecaves
---------------

Now that we have a list of code caves let's figure out a smart way of using these. The first thing that comes to mind is just the example of useless code from SpiderPIC as well as just adding and subtracting random numbers and other weird math. Example from SpiderPIC:

var uselessInst = \[...\]string{  
 "\\tnop\\n",  
 "\\txchg \[REG\], \[REG\]\\n",  
 "\\tcmova \[REG\], \[REG\]\\n",  
 "\\tcmovb \[REG\], \[REG\]\\n",  
 "\\tcmovc \[REG\], \[REG\]\\n",  
 "\\tcmove \[REG\], \[REG\]\\n",  
 "\\tcmovg \[REG\], \[REG\]\\n",  
 "\\tcmovl \[REG\], \[REG\]\\n",  
 "\\tpush \[REG\]\\n\\tpop \[REG\]\\n",  
}

Other examples like the one we will do manually could be just increasing and decreasing registers.

For our example here, we will find a ret instruction before a code cave, use this instruction to jump to a code cave, execute some useless instructions with no influence on the running of the application, and then do the original ret. As always let's first do the process manually.

### Manual Example: simple

In this very simple example, we just make a short jump and then increase and decrease RAX to then return. The code serves no functionality and the program executes just fine.

Press enter or click to view image in full size

Added random mnemonics to codecave

### Manual Example: Trampolines

In the above example, we used a jump instructions to skip some bytes, if we add more this is known as jmp trampolines, let's try to get an example up and running manually.

Trampolines

In this example much more is going on, we are jumping around several times while also using the useless instructions from before. The challenge for this one will be automating the creation of the trampolines.

Automation of codecaves and junk instructions
---------------------------------------------

So to automate the above process we will need to create some rules and success criteria. Starting off I think the following will suffice in terms of both obfuscation and ease of implementation:

*   Loop through cavecodes, and do a dice roll to decide if we will use it for obfuscation.
*   Choose random instruction from the code block above the codecave
*   save the instruction and replace it with a JMP to the code cave
*   In the codecave add the instruction along with a bunch of useless instructions
*   Jump back to after where we removed the instruction.

First to test our hypothesis, let's simply fill in the instructions we want to change with NOPs and see what happens.

Press enter or click to view image in full size

Looks like it is working fine, now let's try with a jump to the codecave.

Now doing the modifications manually, this is how we would like the final result to look:

Example of using a codecave

So to get here we need the following:

*   Check if the instruction we are replacing is big enough for a JMP instruction to the codecave
*   Calculate if the codecave can store the instruction we are replacing plus the instructions for the jump back to the main code
*   Calculate the length of the first jump
*   Calculate the length of the last jump back

### Automating JMP into codecave

so before we jump into making the whole thing automated let's make a small PoC to check if we can modify a single instruction to jump into a code cave. With some trieal and error i got the following code to work:

\# Get info on what we are going to modify  
print("address of current", hex(codecavesList\[1\].address),"index of current", codecavesList\[1\].index)  
startOfCurrentCodecave = codecavesList\[1\].index  
endOfLastCodecave = startOfCurrentCodecave - (codecavesList\[0\].index + codecavesList\[0\].size)  
indexToBeModified = random.randint(endOfLastCodecave, startOfCurrentCodecave)  
print("index to be modified", indexToBeModified)  
print("instruction to be",modifiedByteArray\[indexToBeModified\])  
oldInstruction = modifiedByteArray\[indexToBeModified\]  
lengthOfoldInstruction= len(oldInstruction)  
print("instr len", lengthOfoldInstruction)  
jmpInstructionLength = 2  
  
if lengthOfoldInstruction >= jmpInstructionLength:  
    print("\\t\[+\] Enough room found, modifying isntruction")  
    # Get bytes between instructions  
    bytesBetweenInstructions = 0  
    currentInstruction = indexToBeModified  
    while currentInstruction < startOfCurrentCodecave-1:  
        bytesBetweenInstructions += len(modifiedByteArray\[currentInstruction\])  
        if bytesBetweenInstructions > 256:  
            bytesBetweenInstructions = 999  
            break  
        currentInstruction += 1  
    # modify with jmp instruction into code cave  
    print("bytes between", bytesBetweenInstructions)  
    if bytesBetweenInstructions < 256:  
        jmpInstruction = bytearray(b'\\xeb')  
        nop = 144  
        jmpInstruction.append(bytesBetweenInstructions-1)  
        # adjust for longer instructions  
        byt = 0  
        while byt != len(modifiedByteArray\[indexToBeModified\]) - jmpInstructionLength:  
            jmpInstruction.append(nop)  
            byt += 1  
        print("\\tNumber of NOPs added", byt)  
        modifiedByteArray\[indexToBeModified\] = jmpInstruction

What it does is just get some info that we will be using, like locations and indexes. Next, it checks for the length of the instruction to see if there is enough room for a jmp instruction (4 bytes/2 instructions). the result then looks like this:

Press enter or click to view image in full size

Result of first steps of automation

Note that the process to get here involved a lot of trial and error modifying the code and binary and then seeing what happens. Doing the same for the next code cave gives the same results.

JMP instruction in another codecave

Cool so now we can go ahead and check if there is enough room in the codecave for the instruction we overwrote, I simply do this by adding an additional check on the first if statement checking the size of the code cave.

if lengthOfoldInstruction >= (jmpInstructionLength\*2) and codecavesList\[0\].size > lengthOfoldInstruction:

we can test the check with the following code:

for c in codecavesList:  
    if not c.size > lengthOfoldInstruction):  
        print(c)

This shows that there are a bunch of ‘codecaves’ with only a single INT3 instruction.

### Automating JMP out of codecave

Now let's add the return jump at the end of the code cave. The best example I could find on how backwards jumps work was this:

[

SHORT Jump Instructions
-----------------------

### Using SHORT (Two-byte) Relative Jump Instructions Copyright © 2004, 2013 by Daniel B. Sedory NOT to be reproduced in…

thestarman.pcministry.com







](https://thestarman.pcministry.com/asm/2bytejumps.htm?source=post_page-----447377ab00e6---------------------------------------)

This gives us the following code:

\# get jmp back  
        # we can only jmp back a max of 128 instructions, so we need to update our restrictions  
        # bytesBetween + codecave size -2  
        jmpBackSize = bytesBetweenInstructions + (codecavesList\[1\].size - 2)  
        print("jump back:",jmpBackSize)  
        jmpBackOneConstant = 0xFF  
        jmpBackByte = jmpBackOneConstant - jmpBackSize  
        print("jump back instruction:", jmpBackByte)  
          
        jmpInstruction = bytearray(b'\\xeb')  
        jmpInstruction.append(jmpBackByte)  
        modifiedByteArray\[codecavesList\[1\].index + codecavesList\[1\].size - jmpInstructionLength\] = jmpInstruction  
        modifiedByteArray\[codecavesList\[1\].index + codecavesList\[1\].size - 1\].pop()

And after running the code we see that the results are as we expected:

Automatic addition of JMP instructions

### Automating adding instructions to codecave

Cool! So now we can go into the codecave and back to the original execution flow, now let's re-introduce the code we overwrote with the original jmp as well as add some NOPs as junk bytes in the code.

Code to fill the rest of codecave with NOPs

i = 0  
while i <= codecavesList\[1\].size:  
    if modifiedByteArray\[codecavesList\[1\].index + i\] == bytearray(b'\\xcc'):  
        modifiedByteArray\[codecavesList\[1\].index + i\] = bytearray(b'\\x90')  
    i += 1

And the result looks like so:

Codecave filled with NOPs

Code to write old instructions to code cave

print("\\t\\t\[>\] Adding old instruction to codecave")  
i = 1  
print(modifiedByteArray\[codecavesList\[1\].index\])  
modifiedByteArray\[codecavesList\[1\].index\] = oldInstruction  
print(modifiedByteArray\[codecavesList\[1\].index\])  
while i <= lengthOfoldInstruction:  
    del modifiedByteArray\[codecavesList\[1\].index + i\]  
    i += 1  
i = 0

Press enter or click to view image in full size

Codecave with NOP and old instruction

Awesome, we now have a fully functioning PoC for a single code cave lets try doing the same to other caves and see if our code holds up! But before that the code I have written needs some tender love and caring… and cleanup! … it did not

… After a shit ton of debugging rewriting and considering throwing the computer out the window and moving to an abandoned island and living the Robinson cruso life, I managed to get it working properly! The still very much work in progress PoC then looks like this:

def getBytesBetweenInstructions(indexToBeModified, startOfCurrentCodecave, modifiedByteArray, maxSizeForShortJmp):  
    bytesBetweenInstructions = 0  
    currentInstruction = indexToBeModified  
    while currentInstruction < startOfCurrentCodecave - 1:  
        bytesBetweenInstructions += len(modifiedByteArray\[currentInstruction\])  
        if bytesBetweenInstructions > maxSizeForShortJmp:  
            bytesBetweenInstructions = 999  
            break  
        currentInstruction += 1  
    return bytesBetweenInstructions  
  
def checkForRoomInCave(size, lengthOfoldInstruction, jmpInstructionLength):  
    oldInstructionLength = False  
    codecaveSize = False  
    # check that old instruction is equal or larger than jmp  
    if lengthOfoldInstruction >= jmpInstructionLength:  
        oldInstructionLength = True  
    # Check that ther is room in codecave for old instruction and jmp  
    if size > (lengthOfoldInstruction + jmpInstructionLength + 2):  
        codecaveSize = True  
  
    if oldInstructionLength and codecaveSize:  
        return True  
    return False  
  
def getJmpToCodecave(bytesBetweenInstructions, modifiedByteArray, indexToBeModified, jmpInstructionLength, nop):  
    print("\\t\\t\[>\] Creating bytes for jmp to codecave")  
    jmpInstruction = bytearray(b'\\xeb')  
    jmpInstruction.append(bytesBetweenInstructions - 1)  
    # adjust for longer instructions  
    index = 0  
    while index != len(modifiedByteArray\[indexToBeModified\]) - jmpInstructionLength:  
        jmpInstruction.append(nop)  
        index += 1  
    print("\\t\\t\[>\] Number of NOPs added to replace old instruction", index)  
    return jmpInstruction  
  
def getJmpReturn(bytesBetweenInstructions, size):  
    jmpBackSize = bytesBetweenInstructions + (size - 2)  
    print("\\t\\t\[>\] Jump back length:",jmpBackSize)  
    jmpBackOneConstant = 0xFF  
    jmpBackByte = jmpBackOneConstant - jmpBackSize  
    print("\\t\\t\[>\] Jump back instruction: 0xeb", hex(jmpBackByte))  
    jmpInstruction = bytearray(b'\\xeb')  
    jmpInstruction.append(jmpBackByte)  
    return jmpInstruction  
  
\# Constants  
maxSizeForShortJmp = 128 # Get bytes between instructions, 128 is max jmp size for short jumps  
nop = 144 # int for 0x90  
jmpInstructionLength = 2  
  
\# Do manual to start instead  
def getFileSizeInBytes():  
    b = 0  
    for morphedBytes in modifiedByteArray:  
        for byteInMorphedBytes in morphedBytes:  
            b += 1  
    return b  
  
def modifyCodecave(currentIndex, currentSize, prevIndex, prevSize):  
    #print("\\t\[+\] Getting general info")  
    # Get info on what we are going to modify  
    startOfCurrentCodecave = currentIndex  
    endOfLastCodecave = startOfCurrentCodecave - (prevIndex + prevSize)  
    indexToBeModified = random.randint(endOfLastCodecave, startOfCurrentCodecave)  
    #  
    oldInstruction = modifiedByteArray\[indexToBeModified\]  
    #  
    lengthOfoldInstruction= len(oldInstruction)  
    # Add check to not fuck with jmp instructions  
    if checkForRoomInCave(currentSize, lengthOfoldInstruction, jmpInstructionLength):  
        print("\\t\[+\] Enough room found, modifying isntruction")  
        print("\\t--------------------CAVE INFO--------------------")  
        print("\\t\[+\] Starting use of codecave:", codecavesList\[nextCave\])  
        print("\\t\[>\] Old instruction length", lengthOfoldInstruction)  
        print("\\t\[>\] Index to be modified", indexToBeModified)  
        print("\\t\[>\] Instruction to be moved to cave:",oldInstruction)  
        print("\\t-------------------------------------------------")  
  
        # modify with jmp instruction into code cave  
        bytesBetweenInstructions = getBytesBetweenInstructions(indexToBeModified, startOfCurrentCodecave, modifiedByteArray, maxSizeForShortJmp)  
        print("\\t\\t\[>\] Bytes between instructions", bytesBetweenInstructions)  
        if bytesBetweenInstructions - 2 < maxSizeForShortJmp:  
            jmpBytes = getJmpToCodecave(bytesBetweenInstructions, modifiedByteArray, indexToBeModified, jmpInstructionLength, nop)  
            modifiedByteArray\[indexToBeModified\] = jmpBytes  
  
            endOfCave = currentIndex + currentSize  
            # we are getting the start correctly  
            print("\\t\\t\[>\] Adding old instruction to codecave")  
            i = 0  
              
            byteObject = bytes(oldInstruction)  
            for val in byteObject:  
                #print(hex(val),' ', end='')  
                #print("\\n",val)  
                bytesToAdd = bytearray(b'')  
                bytesToAdd.append(val)  
                modifiedByteArray\[currentIndex + i\] = bytesToAdd  
                i += 1  
  
            print("\\t\\t\[>\] Adding junk instructions to codecave")  
            i = 0  
            # could just do a sum of all bytes in binary and if excess exsists then just delete them from nop?   
            # chnge this to something that will reverse walk the end of the cave to get a spot with 2 nops to owewrite  
            while i <= currentSize:  
                #print(modifiedByteArray\[currentIndex + i\])  
                if modifiedByteArray\[currentIndex + i\] == bytearray(b'\\xcc'):  
                    modifiedByteArray\[currentIndex + i\] = bytearray(b'\\x90')  
                i += 1  
  
            returnJmp = getJmpReturn(bytesBetweenInstructions, currentSize)  
  
            i = 0  
            #modifiedByteArray\[endOfCave\]  
            byteObject = bytes(returnJmp)  
            for val in byteObject:  
                #print(hex(val),' ', end='')  
                #print("\\n",val)  
                bytesToAdd = bytearray(b'')  
                bytesToAdd.append(val)  
                modifiedByteArray\[endOfCave - jmpInstructionLength + i\] = bytesToAdd  
                i += 1  
  
            print("\\t\[+\] Cave updated!")  
            return True  
    return False  
  
codecavesUpdated = 0  
originalFileSize = getFileSizeInBytes()  
print("file size:", originalFileSize)  
oldCave = 0  
nextCave = 1  
for cave in codecavesList:  
    #print("\[+\] Starting use of codecave:", codecavesList\[nextCave\])  
    #print("\\t\\t\[>\] Address of current", hex(codecavesList\[nextCave\].address),"index of current", codecavesList\[nextCave\].index)  
    if modifyCodecave(codecavesList\[nextCave\].index, codecavesList\[nextCave\].size, codecavesList\[oldCave\].index, codecavesList\[oldCave\].size):  
        codecavesUpdated += 1  
      
    oldCave += 1  
    nextCave += 1  
    if nextCave >= len(codecavesList):  
        break

The code will go through codecaves found in the binary and then pick an instruction at random, then check if the instruction is big enough to be replaced with a short jump instruction and also check that the codecave has enough room for the original instruction and the return jump. when that is figured out it goes through and does the following:

*   add a short jump to the codecave where the original instruction was
*   fill out the remainder of the original instruction with NOPs
*   in the codecave, it replaces all INT3 instructions with NOPs
*   in the last two bytes of the codecave it creates a return jump to the NOPs in the original instruction.

The final result when comparing the original with a morphed version looks like this:

Press enter or click to view image in full size

Comparison showing updated codecave

There are still plenty of places where improvements can be made, such as using other instructions than just NOPs and changing the way the applications iterate through the code caves to ensure that more replacements are made, at current only a very small percentage is replaced due to how the picking of random instructions works.

Conclusion
----------

So this concludes our adventures for this time in modifying bytes in PE files, integrating disassemblers, and using codecaves. For this to work a lot of work was done with how to create the proper instructions and dealing with filesizes etc. Further ideas for work to be done is to add other instructions to the codecaves other than NOPs. Also, additional substitutions throughout the code could be used to add even more randomness to the whole thing. But here it's only creativity that is the limit. I hope it was at least a bit informative and that you learned something, else I hope that it was a bit entertaining! Until next time!
