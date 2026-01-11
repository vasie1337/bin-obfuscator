# asmMBA: Robust Virtualization Obfuscation with

# Assembly-Based Mixed Boolean-Arithmetic

## Hongjoo Jin

### Korea University

### Seoul, Republic of Korea

### realredwine@korea.ac.kr

## Jiwon Lee

### Korea University

### Seoul, Republic of Korea

### hisdory728@korea.ac.kr

## Taehun Kim

### Korea University

### Seoul, Republic of Korea

### taehoon1310@korea.ac.kr

## Mu Yeol Sung

### Korea University

### Seoul, Republic of Korea

### smy4024169@korea.ac.kr

## Dong Hoon Lee

### Korea University

### Seoul, Republic of Korea

### donghlee@korea.ac.kr

## Abstract

```
Commercial virtualization obfuscation tools like VMProtect and
Themida, which rely on transforming original code into virtual
instructions, have been successfully reverse engineered by attack-
ers. To safeguard the intellectual property of the virtualization
obfuscation architecture from reverse engineering, recent works
have applied complex Mixed Boolean-Arithmetic (MBA) obfusca-
tion to the handler code responsible for the core functions of the
virtualization obfuscation.
In this paper, we first show that a state-of-the-art MBA-based
protection method such as Loki can be efficiently deobfuscated and
then we introduceLoki-Blast. The proposed method effectively
simplifies nested MBA expressions, revealing weaknesses in current
MBA-based obfuscation methods used in virtualization obfusca-
tion tools. In light of these vulnerabilities, we proposeasmMBA, a
novel assembly-based MBA obfuscation technique. Applying MBA
transformations directly at the assembly level,asmMBAintroduces
a layer of complexity that complicates the static and dynamic anal-
ysis, which enables the software to resist modern deobfuscation
tools like MBA-Blast and Chosen-Instruction Attack effectively. Our
evaluation shows thatasmMBAcan generate up to 1042 distinct ob-
fuscated versions of a simple program depending on the protection
level. This makes it difficult for attackers to acquire reusable knowl-
edge from the target program, and it also significantly increases
the complexity of program analysis. We experimentally demon-
strate thatasmMBAexpressions are not deobfuscated by the MBA
deobfuscation tool. These results demonstrate thatasmMBAprovides
strong protection against deobfuscation attacks while maintaining
manageable performance overhead, making it a practical solution
for real-world software protection.
```
## CCS Concepts

- Security and privacy→Software and application security;
Software reverse engineering;Software security engineering;

This work is licensed under a Creative Commons Attribution 4.0 International License.
SAC ’25, March 31-April 4, 2025, Catania, Italy
©2025 Copyright held by the owner/author(s).
ACM ISBN 979-8-4007-0629-5/25/
https://doi.org/10.1145/3672608.

## Keywords

```
Man-At-The-End (MATE) attack, Virtualization obfuscation, Mixed
Boolean-Arithmetic (MBA) obfuscation
ACM Reference Format:
Hongjoo Jin, Jiwon Lee, Taehun Kim, Mu Yeol Sung, and Dong Hoon Lee.
```
2025. asmMBA: Robust Virtualization Obfuscation with Assembly-Based
Mixed Boolean-Arithmetic. InThe 40th ACM/SIGAPP Symposium on Applied
Computing (SAC ’25), March 31-April 4, 2025, Catania, Italy.ACM, New York,
NY, USA, 10 pages. https://doi.org/10.1145/3672608.

## 1 Introduction

```
In recent years, virtualization obfuscation has become a crucial
technique for protecting software from reverse engineering and
tampering attacks [ 19 ]. Virtualization obfuscation transforms the
original program into a set of virtual instructions that run on a
custom virtual machine (VM), thereby significantly increasing the
difficulty for attackers in understanding or analyzing the underlying
code [ 18 ]. Recent works have successfully employed commercial vir-
tualization obfuscation tools like VMProtect [ 22 ] and Themida [ 14 ]
to safeguard the intellectual property of software, even when at-
tackers have complete control of the target system [5, 24].
There are several reverse engineering techniques [ 9 , 11 , 24 ] that
can uncover the internal structure of a VM by targeting its instruc-
tion mapping and analyzing the virtualization handler code [ 21 ].
To further defend against these reverse engineering attacks, some
researchers have adopted Mixed Boolean-Arithmetic (MBA) [ 26 ]
obfuscation as a complementary layer of protection. By embedding
complex MBA expressions within the virtualization handler, this
mode of obfuscation makes it much harder for attackers to under-
stand the virtualized software, thereby increasing the complexity
of static [ 8 , 18 , 19 ] and dynamic [ 17 ] analysis. However, simple
MBA-based obfuscation techniques are vulnerable to advanced de-
obfuscation methods like MBA-Blast [ 13 ] and MBA-Solver [ 23 ].
These methods, in particular, exploit the fact that MBA transfor-
mations on 1-bit variables hold for𝑛-bit variables, and vice versa,
for any integer𝑛[ 13 , 26 ], and this allows them to simplify the
expressions and expose the original program logic systematically.
In response, more advanced nested MBA obfuscation techniques
emerged to overcome these vulnerabilities. Unlike simple MBA
expressions, nested MBA expressions involve more profound layers
of complexity, making it more challenging for deobfuscation tools
to simplify the obfuscation. Loki [ 21 ], a state-of-the-art MBA-based
```

```
SAC ’25, March 31-April 4, 2025, Catania, Italy H. Jin et al.
```
protection method, applies nested MBA expressions within virtual-
ization handlers and significantly increases the difficulty of reverse
engineering.
Our approach demonstrates that even advanced MBA protec-
tions like Loki can be systematically reversed with the right tech-
nique. The results emphasize that while nested MBA techniques
offer more robust protection than simple MBA, the software still
needs additional layers of defense to guard against increasingly so-
phisticated deobfuscation attacks. We then proposeasmMBA, which
applies MBA transformations directly to the assembly-level instruc-
tions of the target software before virtualization obfuscation. When
asmMBAis applied to assembly-level instructions of a relatively sim-
ple benchmark program, it generates up to 1042 different versions,
and the sheer number of versions burdens reverse engineers to
find and acquire reusable knowledge. Additionally, we introduce
theNEGinstruction into the MBA expression to ensure that MBA
transformations on𝑛-bit variables do not hold for 1-bit variables,
thus rendering MBA deobfuscation methods ineffective.asmMBA,
in sum, adds a new layer of complexity that hinders reverse engi-
neering and resists standard MBA deobfuscation tools as well as
specialized attacks like the Chosen-Instruction Attack [ 11 ]. Our
method targets the obfuscation of critical code at the assembly
level to offer greater protection level and application scope flexibil-
ity. Additionally,asmMBAis designed to balance robust protection
with manageable performance overhead, making it well-suited for
real-world software applications.
The main contributions of this paper are as follows.

- Loki-Blast: We introduce a novel deobfuscation method that
    simplifies nested MBA expressions and exposes vulnerabili-
    ties in state-of-the-art MBA-based protections like Loki.
- asmMBA: We proposeasmMBA, an assembly-based MBA ob-
    fuscation technique that significantly amplifies instruction
    complexity and enhances the protection of commercial vir-
    tualization obfuscation tools by resisting advanced deobfus-
    cation attacks.
- Comprehensive Evaluation: We present an in-depth analy-
    sis ofasmMBA’s correctness, diversity, protection strength
    against deobfuscation, and performance efficiency to show
    that our method offers robust protection with reasonable
    performance overhead when applied to real-world crypto-
    graphic software.

## 2 Background and Related Works

## 2.1 Virtualization Obfuscation

```
Virtualization obfuscation is an advanced security method that safe-
guards software against reverse engineering and tampering. This
method converts the original program’s instructions into a custom
instruction set designed specifically for the VM, and these instruc-
tions are then executed by the VM instead of the native processor.
The core concept of virtualization obfuscation is to encapsulate a
program’s logic within layers of complex, hard-to-decipher virtual
instructions. This greatly complicates software analysis, as the orig-
inal code is no longer directly accessible in its native form, and the
VM must instead dynamically interpret it at runtime.
A typical virtualization obfuscation process consists of the fol-
lowing steps (Figure 1): (i) Disassembly of the target binary’s code
```
```
55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c3 55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c
TargetBinary
VM Section
```
```
Code Section btr lea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]dword ptr [0x69fe64], %edx
cmpleacrc32teststosdword ptr [0x69fdd0], %ecx%ecx, dword ptr [0x69fe64]dword ptr [0x69fd9c], %ecx%edx, dword ptr [0x69fdd0]dword ptr [0x69fe7c], %edx
sarlea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]cmp dword ptr [0x69fdd0], %ecxbtr dword ptr [0x69fe64], %edx%edx, dword ptr [0x69fdd0]
```
```
cmovnp %ecx, dword ptr [0x69fe58]cmplea %ecx, dword ptr [0x69fe64]crc32 dword ptr [0x69fd9c], %ecxtestdword ptr [0x69fdd0],%edx,dword ptr [0x69fdd0]%ecx
stos dword ptr [0x69fe7c], %edxsarleapshufw %ecx, dword ptr [0x69fe58]pdeppext%edx,dword ptr [0x69fe58],dword ptr [0x69fdd0],dword ptr [0x69fe64], %edxdword ptr [0x69fdd0]%ecx%ecx
outteststos dword ptr [0x69fe7c], %edxsar%edx,dword ptr [0x69fd9c], %ecx%edx,dword ptr [0x69fdd0]dword ptr [0x69fdd0 ]
```
```
VM Context
DispatcherHandlers
VM Exit...
```
```
VM Entry
```
```
btrlea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]cmpdword ptr [0x69fe64],dword ptr [0x69fdd0], %ecx%edx
leacrc32teststos%ecx, dword ptr [0x69fe64]dword ptr [0x69fd9c], %ecx%edx, dword ptr [0x69fdd0]dword ptr [0x69fe7c],%edx
sarlea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]cmp dword ptr [0x69fdd0], %ecx%edx, dword ptr [0x69fdd0]
btr dword ptr [0x69fe64], %edx
```
```
crc32test %edx, dword ptr [0x69fdd0]stos dword ptr [0x69fe7c], %edxsar %edx, dword ptr [0x69fdd0]dword ptr [0x69fd9c],%ecx
lea dword ptr [0x69fe58], %ecxpshufw %ecx, dword ptr [0x69fe58]pdeppextdword ptr [0x69fdd0], %ecxdword ptr [0x69fe64],%edx
outtest %edx, dword ptr [0x69fdd0]stossardword ptr [0x69fd9c], %ecxdword ptr [0x69fe7c],%edx,dword ptr [0x69fdd0]%edx
```
```
leacmovnp %ecx, dword ptr [0x69fe58]cmp dword ptr [0x69fdd0], %ecxbtr dword ptr [0x69fe64], %edxdword ptr [0x69fe58],%ecx
lea dword ptr [0x69fe58], %ecxlsskmovqdpps%ecx, dword ptr [0x69fe58]dword ptr [0x69fdd0], %ecx%ecx,dword ptr [0x69fe64]
crc32 dword ptr [0x69fd9c], %ecxtest %edx, dword ptr [0x69fdd0]stosdword ptr [0x69fe7c],%edx
sar %edx, dword ptr [0x69fdd0]pshufw %ecx, dword ptr [0x69fe58]
```
```
Virtualized Instructions
```
```
Original Instruction
xor %edx, %ecx
sub %edx, %eax
```
```
and %ecx, %eax
add %ecx, 0x1d
```
```
Insert
```
```
Mapping
```
```
Call VMReturn
```
```
Virtualization Obfuscation Obfuscated Binary
```
```
... ... ...
```
```
... ...
```
```
Select Target
```
```
Disassemble
```
```
Target Program
```
```
CriticalCode
```
```
AssemblyCode
```
```
AssemblyCode
```
```
xor %edx, %ecx
sub %edx, %eax
and %ecx, %eax
add %ecx, 0x1d
or %eax, %edx
```
```
Target Instructions
```
```
...
```
```
Figure 1: Virtualization obfuscation process to protect critical
code in software
```
```
section into assembly code; (ii) Selection of critical code that is to be
protected from the assembly code of the target program; (iii) Con-
version of the selected instructions into virtualized instructions that
can only be executed on a VM and insertion of those instructions
into the code section of the obfuscated binary; (iv) Creation of a VM
section in the obfuscated binary and insertion of VM components
such asVM Context,VM Entry/Exit,Dispatcher, andHandlers.
Most virtualization obfuscation techniques obscure analysts’ under-
standing by concealing the mapping rules between the original and
virtualized instructions during this process. When the obfuscated
binary executes, the code in the VM section is invoked, ensuring
that the original instructions are executed correctly based on the
interpretation of the virtualized instructions each time a handler is
called.
VMProtect [ 22 ] is the most well-known commercial implemen-
tation of virtualization obfuscation. This tool employs a powerful
virtualization engine to convert sections of a program into virtual
instructions that are then executed at runtime by a user-defined VM.
VMProtect replaces critical native code instructions with virtual
instructions that the VM interprets. This VM is engineered with
complexity and security in mind and includes techniques like dy-
namic instruction set switching—where the virtual instruction set
changes during execution—and multi-layer virtualization to obscure
the original program further and complicate reverse engineering
efforts.
Sophisticated attackers conducting reverse engineering often
target the virtualization handler code to reverse engineer and de-
code the virtual instruction set. To defend against such attacks,
obfuscation methods like Control Flow Flattening [ 10 ] and MBA
are applied within the handler code itself, adding further layers of
complexity.
```
## 2.2 Mixed Boolean-Arithmetic Obfuscation

```
MBA obfuscation is an advanced technique that protects software
by transforming basic arithmetic operations (e.g.,+,−,∗) into far
more complex representations that integrate both arithmetic and
Boolean logic [ 12 ]. For example, a basic addition operation like𝑥+𝑦
can be obfuscated into a much more complex expression such as
(𝑥∨𝑦)+𝑦−(¬𝑥∧𝑦)
where bitwiseAND,OR, andXORbecome integrated with the original
arithmetic operations. The resulting expression is mathematically
equivalent to the original, but it is far more challenging for an
attacker to understand or simplify.
```

```
asmMBA SAC ’25, March 31-April 4, 2025, Catania, Italy
```
```
MBA obfuscation techniques are effective because they create
expressions that resist symbolic execution and algebraic simpli-
fication two widely used methods in reverse engineering. MBA
transformations blend Boolean and arithmetic logic, which makes
it difficult for attackers attempting symbolic execution engines to
track how inputs propagate through a program, leading to path ex-
plosion or incorrect symbolic representations. Symbolic execution
analyzes a program to determine which inputs trigger the execu-
tion of each part, which becomes challenging with MBA-obfuscated
code. Similarly, algebraic simplification tools, which aim to reduce
expressions to their simplest form, often fail to simplify MBA ex-
pressions effectively due to the complex interleaving of arithmetic
and Boolean operations. These intertwined operations obscure the
underlying arithmetic structure, thereby making it difficult for the
simplification algorithms to apply standard reduction techniques.
```
## 2.3 Deobfuscation of MBA Expressions

While MBA expressions have proven to be powerful tools for soft-
ware obfuscation by blending arithmetic and Boolean operations
to complicate reverse engineering, there are still several deobfus-
cation techniques that exploit the underlying linearities in some
MBA expressions. Techniques such as MBA-Blast and MBA-Solver
can efficiently simplify and deobfuscate basic forms of MBA obfus-
cation, particularly those that involve less intricate combinations
of arithmetic and Boolean logic.
MBA-Blast [ 13 ] introduces a groundbreaking approach to sim-
plifying MBA expressions by leveraging the fact that MBA transfor-
mations on 1-bit variables hold for𝑛-bit variables, and vice versa,
for any integer𝑛[ 13 , 26 ]. This allows for applying well-established
Boolean simplification techniques to reduce complex arithmetic
expressions. MBA-Blast begins by converting the MBA expression
into a Boolean representation within 1-bit space, which allows stan-
dard Boolean simplification techniques to be applied. Operating
in 1-bit space also allows us to apply well-known Boolean simpli-
fication rules and identities to the expressions. After simplifying
the Boolean representation, MBA-Blast converts the expression
back to its original𝑛-bit form, effectively reducing the complexity
introduced by a mix of Boolean and arithmetic operations. This
reduction process enables deobfuscation tools to simplify complex
MBA expressions effectively.
Existing SMT solvers [ 3 , 6 ] are optimized to handle either pure
arithmetic or pure bitwise operations. However, when these two
types of operations are combined in an MBA expression, the solver
struggles to efficiently resolve the complex interdependencies be-
tween the Boolean and arithmetic components, leading to perfor-
mance bottlenecks. Standard reduction techniques become ineffec-
tive, forcing a fallback to brute force methods that are computation-
ally expensive and time-consuming. MBA-Solver [ 23 ] addresses
the performance bottlenecks encountered by SMT solvers when
analyzing MBA expressions by preprocessing these expressions to
reduce the occurrence of MBA shifts or instances where the expres-
sion frequently alternates between Boolean and arithmetic opera-
tions. MBA alternation refers to the frequent switching between
bitwise and arithmetic operations within an expression. This alter-
nation disrupts the solver’s ability to apply traditional reduction

```
techniques, as the transitions between domains create complex in-
terdependencies that are difficult to resolve efficiently. MBA-Solver
analyzes the expression to detect these shifts and transforms it
into a more straightforward form that reduces the occurrence of
interdependencies. This tool was tested on a large dataset of 3,
MBA expressions from various sources and demonstrated its ability
to simplify over 96.5% of the expressions.
```
## 2.4 Hardening MBA Obfuscation

```
Loki [ 21 ], a technique specifically created to harden virtualization
obfuscation tools through the use of MBA transformations, aimed
to make reverse engineering of these methods even more compli-
cated. Loki employs nested MBA transformations to prevent attacks,
particularly in cases where the structure of the handler is known to
the attacker. By increasing the complexity of the transformations
through nesting, it becomes notably more challenging to deduce
the original instructions from the virtualized code. Loki applies
MBA obfuscation by rewriting expressions to a desired level of
complexity using identity-based transformation rules. For exam-
ple, suppose we start with the simple arithmetic operation𝑥+𝑦.
To obfuscate𝑥+𝑦, we can transform the operation into an MBA
expression as follows.
```
#### (𝑥⊕𝑦)+ 2 ×(𝑥∧𝑦).

```
To further obfuscate it, we nest the MBA expression equivalent to
𝑥⊕𝑦as follows.
```
#### (𝑥+𝑦− 2 ×(𝑥∧𝑦))+ 2 ×(𝑥∧𝑦).

```
This process adds complexity and creates a nested MBA expres-
sion that is much harder to reverse engineer. This process creates
a nested MBA expression with a depth of 2, meaning the expres-
sion has undergone two levels of rewriting. Each additional level
of depth exponentially complicates the resulting expression fur-
ther and makes it more convoluted for an attacker to reverse the
transformations. In this manner, a rewriting rule is selected and
applied with each transformation, and the depth of the nested MBA
expression reflects the number of times it has been rewritten.
Loki employs nested MBAs to increase syntactic complexity.
By repeatedly applying MBA transformations in an overlapping
manner—where Boolean and arithmetic components are combined
multiple times—the overall length and syntactic complexity of the
expression can be significantly extended. Furthermore, because
MBA analysis tools like MBA-Blast are not meant to handle the
complexity introduced by nested MBA transformations, this ap-
proach provides effective protection even against some of the most
advanced deobfuscation tools currently available.
We propose an effective deobfuscation method for Loki’s nested
MBA. Because the nested MBA technique in Loki relies on the
repeated application of the same rewrite rules, our proposed de-
obfuscation method (detailed in Section 4) demonstrates that if an
expression with a depth of 1 can be simplified, the same approach
can be applied to simplify deeper, more complex MBA expressions.
This method offers a promising avenue for countering the security
measures introduced by nested MBAs.
```

```
SAC ’25, March 31-April 4, 2025, Catania, Italy H. Jin et al.
```
## 3 Adversary Model

In our adversary model, attackers have direct access to software run-
ning on untrusted client devices and employ open-source deobfusca-
tion tools like MBA-Blast [ 13 ] and Chosen-Instruction Attack [ 11 ].
Their objective is to reverse engineer software protected by vir-
tualization obfuscation and recover code resembling the original.
Uncovering instruction-mapping rules through Chosen-Instruction
Attack gives attackers "reusable knowledge," enabling them to com-
promise other software using the same obfuscation. This model,
known as a Man-At-The-End (MATE) attack [ 1 ], poses a signif-
icant threat (Section 3.1). Attackers exploit Chosen-Instruction
Attack [ 11 ] to simplify the analysis of virtualized code (Section 3.2).

## 3.1 Man-At-The-End Attack

MATE attack [ 1 ] is a severe security threat in which attackers gain
physical access, administrative privileges, and full control over the
target device or system and, thus, have the ability to carry out
highly targeted and sustained attacks. Unlike remote-based attacks,
where attackers interact with the system from afar, MATE attackers
have direct, physical access to the target system [ 2 ]. This direct ac-
cess allows them to bypass many traditional security mechanisms,
convoluting detection and mitigation. MATE attacks frequently
occur when software is deployed on client devices or untrusted
platforms, such as gaming consoles, mobile devices, or embedded
systems outside the developer’s direct control. In terms of software
protection, MATE attacks primarily focus on reverse engineering
or tampering with protected software to disable license checks,
steal intellectual property, and/or introduce malicious code. These
attacks often target advanced protection mechanisms, such as virtu-
alization obfuscation or MBA obfuscation, which aim to complicate
reverse engineering efforts.

## 3.2 Chosen-Instruction Attack

The Chosen-Instruction Attack [ 11 ] is a powerful reverse engineer-
ing technique that helps attackers extract critical details about a
VM’s instruction mappings and internal structure. This attack is
highly effective against commercial virtualization obfuscators, such
as VMProtect [ 22 ], Themida [ 14 ], Code Virtualizer [ 15 ], and Ob-
sidium [ 16 ], which convert native code into virtual instructions
executed by a custom VM. Through controlled input programs, the
attacker reveals how specific native instructions are translated into
virtual instructions, thus weakening the protection that virtualiza-
tion obfuscation techniques offer. The attack works by selecting
target instructions (e.g., arithmetic or control flow commands) and
examining how they are virtualized to give the attacker insight into
the core operations of the VM.
Attackers use carefully selected target instructions placed be-
tween anchor instructions (e.g., system calls or interrupts) to create
simple programs that are not virtualized. These anchor instructions
help to clearly define the boundaries of virtualized code during
execution, which tells the attacker how to track transformations in
the target instructions. After virtualization obfuscation is applied,
the virtualized instructions derived from the selected target set, ex-
cluding additional obfuscator instructions, are known as the kernel.
Attackers then use symbolic execution tools to verify whether this
kernel matches the original program, and from this point, they can

```
extract the instruction-mapping rules. In Section 7.3, we provide
a detailed explanation of the Chosen-Instruction Attack process
along with our experimental results.
When software protected by virtualization obfuscation and MBA
obfuscation is deployed on untrusted devices, MATE attackers can
use tools like MBA-Blast, MBA-Solver, and the Chosen-Instruction
Attack to extract intellectual property, bypass licensing mechanisms
and/or insert malicious code. To counter these sophisticated attacks,
we first highlight the vulnerabilities of existing nested MBA obfus-
cation techniques in Section 4 and introduce a robust virtualization
obfuscation method in Section 5 that is able to resist both MBA
deobfuscation and the Chosen-Instruction Attack.
```
## 4 Loki-Blast

```
In this paper, we introduceLoki-Blast, a method specifically de-
signed to deobfuscate the deeply nested MBA expressions employed
in Loki’s obfuscation technique. While Loki relies on repeatedly
applying the same rewrite rules to create highly nested expressions,
our Loki-Blast approach differs from existing recursive methods
(e.g., those discussed in [ 21 ]) by combining aSimplifystep with a
truth table analysis at each operator. This allows us to systemati-
cally reduce an MBA expression’s complexity, even when its nesting
depth extends beyond what standard tools like MBA-Blast [ 13 ] can
readily handle. Nested MBA expressions in Loki apply algebraic
rewrite rules multiple times, increasing the expression’s complexity
with each application.Loki-Blastrests on the hypothesis that
if an expression at depth 1 can be simplified, then an expression
at higher depths can also be broken down by iterating over each
operator and applying a uniform format transformation [ 13 ]. To im-
plement this strategy, we leverage the publicly available MBA-Blast
tool^1 within our own multi-step procedure.
The detailed process of our proposed MBA deobfuscation method
is outlined in Algorithm 1.Loki-Blastanalyzes the operators and
operands of nested MBA expressions to reduce their complexity
systematically. Boolean operators (e.g., AND, OR) are treated as
straightforward cases with no additional complexities. Arithmetic
operators require a deeper analysis, so the operands are simpli-
fied before the operator is applied. This reduces complex MBA
expressions or represents them in a simplified form for easier un-
derstanding. The algorithm works by analyzing an MBA expres-
sion and processing the arithmetic and Boolean operations it con-
tains. The key steps of theLoki-Blastalgorithm are as follows:
MBA-Deobfuscation(𝑒)iterates through the operators within the
nested MBA expression𝑒, analyzing each operator and its operands.
It extracts the left and right operands of each operator within𝑒.
𝑙𝑒𝑓𝑡_𝑒𝑥𝑝and𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝represent the left and right operands of the
operator, respectively, and play a crucial role in the subsequent anal-
ysis. If the current operator is a𝑏𝑜𝑜𝑙𝑒𝑎𝑛 𝑜𝑝𝑒𝑟𝑎𝑡𝑜𝑟, simply add the
operator and its operands to the expression. This process is straight-
forward, as Boolean operations do not require additional complex
processing, and it is managed by calling theAppendExpression
function. When an arithmetic operator is encountered, additional
processing executes on the left and right operands.
```
(^1) MBA-Blast, https://github.com/softsec-unh/MBA-Blast


asmMBA SAC ’25, March 31-April 4, 2025, Catania, Italy

Algorithm 1:Algorithm forLoki-Blastto perform MBA
deobfuscation
Input:A Mixed Boolean-Arithmetic expression𝑒
Output:A deobfuscated version of the expression𝑒′
1 FunctionMBA-Deobfuscation(𝑒):
2 foroperator𝑜𝑝in𝑒do
3 𝑙𝑒𝑓𝑡_𝑒𝑥𝑝←left operand of𝑜𝑝;
4 𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝←right operand of𝑜𝑝;
5 if𝑜𝑝is a Boolean operatorthen
6 AppendExpression(𝑙𝑒𝑓𝑡_𝑒𝑥𝑝,𝑜𝑝,𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝);
7 end
8 else
9 Simplify(𝑙𝑒𝑓𝑡_𝑒𝑥𝑝);
10 Simplify(𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝);
11 𝑙𝑒𝑓𝑡_𝑡𝑏←TruthTable(𝑙𝑒𝑓𝑡_𝑒𝑥𝑝);
12 𝑟𝑖𝑔ℎ𝑡_𝑡𝑏←TruthTable(𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝);
13 𝑙𝑒𝑓𝑡_𝑚𝑏𝑎←MBA-Blast(𝑙𝑒𝑓𝑡_𝑡𝑏);
14 𝑟𝑖𝑔ℎ𝑡_𝑚𝑏𝑎←MBA-Blast(𝑟𝑖𝑔ℎ𝑡_𝑡𝑏);
15 ifFail(MBA-Blast)then
16 return𝑒;
17 end
18 else
19 ComputeArithmetic(𝑙𝑒𝑓𝑡_𝑚𝑏𝑎,𝑜𝑝,
𝑟𝑖𝑔ℎ𝑡_𝑚𝑏𝑎);
20 end
21 end
22 end
23 return𝑒′;

The following outlines how arithmetic operators are handled.
Simplify(𝑙𝑒𝑓𝑡_𝑒𝑥𝑝)andSimplify(𝑟𝑖𝑔ℎ𝑡_𝑒𝑥𝑝)reduce their re-
spective operands to the greatest extent possible. This process
helps eliminate unnecessary duplication or complexity within the
operands. Next,TruthTableis generated for each operand, listing
the output values for all possible input combinations. This step is
critical for understanding how each operand behaves across a range
of inputs, allowing the algorithm to detect patterns and simplify the
MBA expression more effectively.Loki-Blastcan identify opportu-
nities to eliminate unnecessary complexities or redundancies by an-
alyzing theTruthTable. This process enables a clear analysis of the
operand’s behavior. Additionally, we invokeMBA-Blast(𝑙𝑒𝑓𝑡_𝑡𝑏)
andMBA-Blast(𝑟𝑖𝑔ℎ𝑡_𝑡𝑏)to analyze the MBA expression using
theTruthTablefor each operand. MBA-Blast is a tool designed to
simplify or analyze the meaning of complex MBA expressions. If
MBA-Blast fails (Fail(MBA-Blast)), the algorithm concludes that no
further deobfuscation is possible and returns the original expres-
sion𝑒unchanged. IfMBA-Blast()succeeds, the algorithm gener-
ates simplified MBA expressions for the left and right operands,
and these expressions are applied to the arithmetic operatoropto
compute the final arithmetic result. The operation executes using
ComputeArithmetic(). After processing all operators, the deob-
fuscated expressione’is returned.

```
0 5 10 15 20 25 30
Recursive Expression Rewriting Bound
```
```
0
```
```
20
```
```
40
```
```
60
```
```
80
```
```
100
```
```
Deobfuscation Success Rate (%)
```
```
Deobfuscation of 1,000 MBAs
```
```
Loki-Blast
LokiAttack
MBA Blast
Loki Default Range (20-30)
```
```
Figure 2: Deobfuscation success rates of nested MBA expres-
sions successfully deobfuscated
```
```
We evaluatedLoki-Blaston the original nested MBA datasets
from Loki’s experiments^2 , which range in depth from 1 to 30. These
datasets include operations such as𝑥+𝑦and𝑥−𝑦, with extensive
nesting to replicate Loki’s real-world complexity rather than arti-
ficially simplified expressions. Overall, we tested 150,000 nested
MBA expressions (1,000 variants each for five basic operations
over 30 levels of nesting). We then compared our method with
Lokiattack [ 21 ] and MBA-Blast [ 13 ] to assess its deobfuscation per-
formance. Figure 2 illustrates our findings, with the x-axis denoting
the nesting depth and the y-axis showing thepercentageof expres-
sions successfully simplified.Loki-Blastachieves a 100% success
rate at depth 1, around 87% at depth 20, and about 80% at the maxi-
mum depth of 30, yielding an overall success rate of roughly 91%.
Compared to existing tools,Loki-Blastoutperforms them, even
for high nesting depths.
Our results demonstrate thatLoki-Blasteffectively simplifies
deeply nested MBAs—up to depth 30—with a 91% overall suc-
cess rate. By systematically combiningSimplify,TruthTable, and
MBA-Blastwithin each operator’s scope,Loki-Blastoffers a ro-
bust alternative to purely recursive approaches. In the following
section (Section 5), we build on these insights to propose a novel
obfuscation method that further strengthens virtualization-based
```
## 5 asmMBA

## 5.1 Overview

```
In this section, we introduceasmMBA, a novel obfuscation technique
that applies an additional layer of MBA transformations at the as-
sembly level before virtualization. By operating on assembly code,
asmMBAaccommodates scenarios where source code is unavailable
and can provide finer control over instruction-level transformations.
As a result, reverse engineering becomes more challenging than tra-
ditional approaches. Figure 3 illustrates howasmMBAintegrates into
the virtualization obfuscation workflow. OnceasmMBAis applied
to assembly instructions, the corresponding handler subsequently
virtualizes each MBA-obfuscated instruction.
asmMBAworks as follows. First,asmMBAscans the designated sec-
tion of the original program to identify instructions suitable for
```
(^2) Loki and Lokiattack, https://github.com/RUB-SysSec/loki


```
SAC ’25, March 31-April 4, 2025, Catania, Italy H. Jin et al.
```
```
gcc/g++ Compiler CommercialObfuscatorVM
```
```
AssemblyCodes
```
```
int main(){int i = 0;if (i == 0)else}return 0;return 1; c LFB13:.cfi_startprocpushebp.cfi_def_cfa_offset 8.cfi_offset 5, -8mov c
.C/C++ Files InstructionAnalysis
```
```
Instruction
Rewriter
```
```
c
Instruction Info.
```
```
@Dwrygqergj@Ghethjreh@1gfEWERT@WEH1GE@hewtgh2F
@fdahf%asdg@hdfshrtrRh@fadfherh
```
```
c
Rewriting Rule
```
```
@Dwrygqergj@Ghethjreh@1gfEWERT@WEH1GE@hewtgh2F
@fdahf%asdg@hdfshrtrRh@fadfherh
```
```
asmMBA
```
```
Assembly Codes
```
```
LFB13:.cfi_startprocpushebp.cfi_def_cfa_offset 8.cfi_offset 5, -8mov c
```
```
Assembly Codes
```
```
LFB13:.cfi_startprocpushebp.cfi_def_cfa_offset 8.cfi_offset 5, -8mov c
```
```
InstructionMapping
```
```
55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c3 55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c
```
```
VM
CPU
```
```
asmMBABinary
```
```
55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c3 55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c
VirtualizedBinary
```
```
Compile 55 48 89 e5 48 8d 3d 00 00 00 00 e8 00 00 00 00 5d c3 55 48 89 e5 48 8d 3d c
00 00 00 00 e8 00 00 00 00 5d
VirtualizationObfuscated
Binary
```
```
Figure 3: Overview of the asmMBA method applied to virtual-
ization obfuscation techniques
```
MBA obfuscation. This process focuses on arithmetic operations,
such as ADD and SUB, that can be effectively transformed using
MBA techniques; operations like floating-point arithmetic or divi-
sion, which cannot be represented within the MBA framework, are
excluded. For each selected operator,asmMBAincreases syntactic
complexity by replacing the original instruction with a series of
MBA expressions that maintain the same functionality. In particu-
lar, our MBA expression incorporatesNEGinstruction, which is not
used in experiments for MBA-Blast. We note thatNEGinstruction
computes a 2’s complement whileNOTcomputes a 1’s complement.
SinceNEGinstruction for the 1-bit variable does not correctly work,
identities in 1-bit space may not hold for𝑛-bit space, which is the
core concept for simplifying MBA expressions in MBA-Blast. The
effect of usingNEGis further discussed in Section 5.2. The assembly-
based MBA obfuscation process is repeated multiple times, with
each transformation adding a layer of complexity to the assembly
code. This notably increases the difficulty of reverse engineering
while preserving the original program behavior. The substituted
MBA expression is converted into assembly instruction form and
then replaces the original instruction, which is replaced by a set of
instructions with MBA obfuscation.
asmMBAallows users to specify the desired complexity level for
MBA expressions as well as the percentage of instructions to be
obfuscated. The complexity level, ranging from 1 to 5, controls the
structural intricacy of the generated expressions, while the percent-
age parameter allows for selective obfuscation of only critical parts
of the program. This flexibility balances security with performance,
minimizing overhead by reducing the degree of obfuscation where
necessary. UsingasmMBAputs the burden on reverse engineers to
determine which parts of the code have been obfuscated, as the
MBA-obfuscated instructions are indistinguishably mixed in with
the original instructions and others added by the virtualization
obfuscation tool. By maintaining the same execution semantics
and blending the obfuscated instructions with non-obfuscated code,
asmMBAensures that identifying and isolating the obfuscated re-
gions becomes a highly complex task. This means that programs can
be effectively protected without obfuscating all instructions while
also reducing overhead by reducing the proportion of instructions
to be obfuscated.
After being generated as an intermediate output throughasmMBA,
the obfuscated program can be fed into a commercial virtualiza-
tion obfuscator to produce the final result. The obfuscation process
proposed in this study is divided into two stages: MBA obfusca-
tion throughasmMBAand standard virtualization obfuscation. This

```
two-stage approach offers more robust protection by first adding
syntactic complexity through MBA transformations and then vir-
tualizing the program to obscure its execution flow. Combining
these techniques makes it significantly more challenging for re-
verse engineers to break down the obfuscated code. In this paper,
we implemented the MBA obfuscation tool for the first stage and
evaluated the commercial virtualization obfuscation in the second
stage with VMProtect v3.6.
```
## 5.2 Enhanced Assembly-based MBA

```
We propose an enhanced assembly-based MBA mechanism that
leverages theNEGinstruction to disrupt the standard 1-bit-based
simplification assumptions prevalent in deobfuscation tools like
MBA-Blast. WhereasNOTperforms a 1’s complement (flipping each
bit directly),NEGexecutes a 2’s complement, effectively computing
(−𝑥)by subtracting the operand from zero. In multi-bit contexts
(e.g., 8-bit, 32-bit), this operation may trigger carry or overflow
flags, which do not manifest in a naive 1-bit truth table. Hence,
expressions incorporatingNEGpose a significant challenge for tools
that align𝑛-bit logic with simplified 1-bit identities [13].
For instance, in a purely 1-bit world, valid values are limited
to {0, 1}. ApplyingNEGto𝑥= 0 in 1-bit space could theoretically
yield a “2,” which lies entirely outside the 1-bit range. This paradox
undermines the equivalences and reduction rules that MBA-Blast
or MBA-Solver typically use for deobfuscation, as they assume that
an expression can be safely mapped between 1-bit and𝑛-bit rep-
resentations. Consequently, attackers must separately disentangle
both the arithmetic and logical components ofNEG-based transfor-
mations, increasing the time and expertise needed to reconstruct
the original code.
While symbolic execution or the Chosen-Instruction Attack
might uncover parts of a VM’s instruction mappings,asmMBAcom-
plicates these efforts by embedding diverse and nested MBA con-
structs at the assembly level. Even if specific VM handlers are iden-
tified, the presence ofNEGinstructions and other complex MBA
operators can thwart consistent rule extraction because each arith-
metic transformation may behave unpredictably when forced into
a 1-bit framework.
As shown in Figure 4,asmMBAreplaces original assembly in-
structions with more complex MBA expressions, many of which
incorporateNEG. During the subsequent virtualization step, these
expressions are re-mapped to custom VM opcodes, further obscur-
ing the control flow. To add another layer of confusion, developers
may insert “dummy” instructions or craft irregular control-flow
paths that do not match the original sequence. This combined
approach—assembly-level MBA plus virtualization—provides ro-
bust resistance to static analyses and dynamic traces.
In summary,asmMBAincreases the number and complexity of
virtualization handler mappings, generating complex MBA expres-
sions for automated tools (e.g., MBA-Blast or chosen-instruction-
based attacks) to simplify. UsingNEGto exploit the mismatch be-
tween 1-bit and𝑛-bit behavior,asmMBAeffectively invalidates key
assumptions underlying typical MBA deobfuscation strategies. In
Section 7, we present a detailed empirical analysis demonstrating
how these features thwart advanced deobfuscation attempts and
```

asmMBA SAC ’25, March 31-April 4, 2025, Catania, Italy

```
xor %edx, %ecx
```
```
sub %edx, %eax
```
```
and %ecx, %eax
```
```
add %ecx, 0x1d
```
```
add %ecx, %edx
neg %edx
or %edx, %ecx
not %eax
add %eax, ¬%eax
neg %eax
xor -21, %ebx
...
...
...
...
...
...
```
```
MBA
Obfuscated
Instructions
```
```
Original Assembly asmMBA
```
```
add Handler
neg Handler
or Handler
not Handler
add Handler
neg Handler
xor Handler
... Handler
... Handler
... Handler
... Handler
... Handler
... Handler
Virtualization
Obfuscation
Tool
```
```
btr lea dword ptr [0x69fe58], cmovnp %ecx, dword ptr [0x69fe58]dword ptr [0x69fe64], %edx%ecx
cmpleadword ptr [0x69fdd0], %ecx, dword ptr [0x69fe64]%ecx
crc32teststos%edx, dword ptr [0x69fe7c], dword ptr [0x69fd9c],dword ptr [0x69fdd0]%edx%ecx
sarlea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]%edx, dword ptr [0x69fdd0]
cmp dword ptr [0x69fdd0], %ecxbtrdword ptr [0x69fe64],%edx
lea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]cmpdword ptr [0x69fdd0],%ecx
lea %ecx, dword ptr [0x69fe64]crc32 dword ptr [0x69fd9c], %ecx
teststos dword ptr [0x69fe7c], %edxsar %edx, dword ptr [0x69fdd0]%edx,dword ptr [0x69fdd0]
leapshufw %ecx, dword ptr [0x69fe58]pdepdword ptr [0x69fe58],dword ptr [0x69fdd0], %ecx%ecx
pextoutdword ptr [0x69fd9c], %ecxdword ptr [0x69fe64], %edx
test %edx, dword ptr [0x69fdd0]stos dword ptr [0x69fe7c], %edxsar%edx,dword ptr [0x69fdd0]
lea dword ptr [0x69fe58], %ecxcmovnp %ecx, dword ptr [0x69fe58]cmp dword ptr [0x69fdd0], %ecx
btr dword ptr [0x69fe64], %edxleadword ptr [0x69fe58],%ecx
lsskmovqdpps%ecx, dword ptr [0x69fe58]%ecx, dword ptr [0x69fe64]dword ptr [0x69fdd0], %ecx
crc32test %edx, dword ptr [0x69fdd0]dword ptr [0x69fd9c],%ecx
stos dword ptr [0x69fe7c], %edxsarpshufw %ecx, dword ptr [0x69fe58]%edx,dword ptr [0x69fdd0]
pdep dword ptr [0x69fdd0], %ecxpextout dword ptr [0x69fd9c], %ecxdword ptr [0x69fe64],%edx
test %edx, dword ptr [0x69fdd0]lss%ecx, dword ptr [0x69fe58]
kmovq dword ptr [0x69fdd0], %ecxdpps %ecx, dword ptr [0x69fe64]pext dword ptr [0x69fe64], %edx
out dword ptr [0x69fd9c], %ecxtest %edx, dword ptr [0x69fdd0]lss %ecx, dword ptr [0x69fe58]
kmovqstos dword ptr [0x69fe7c], %edxdword ptr [0x69fdd0],%ecx
Virtualized
Instructions
```
```
(asm)MBA
Obfuscation
```
```
Handler
Mapping ObfuscationVM
```
```
...
```
```
...
MBA
Obfuscated
Instructions
```
Figure 4: An example of applying **asmMBA** to assembly code
and handler mapping in a virtualization obfuscation tool

help protect intellectual property in real-world software. By care-
fully selecting which instructions to obfuscate and controlling the
nesting depth of these transformations, developers can tailor the
security-performance trade-off to meet the specific needs of their
applications without wholly sacrificing runtime efficiency.

## 6 Implementation

asmMBAtakes the source code of the original program as input and
produces MBA-obfuscated assembly code as output. Obfuscation
is applied at the assembly level after compiling the source code
into assembly language. By operating directly on the assembly
code,asmMBAallows for fine-grained control over which instruc-
tions become obfuscated, which makes it possible to apply MBA
transformations at a more fundamental level before generating the
final binary. The assembly code is parsed to analyze each instruc-
tion, enablingasmMBAto identify which operations are suitable
for obfuscation. For the selected instructions,asmMBAgenerates
new assembly code by applying MBA transformations and replac-
ing the original instructions with more complex MBA-obfuscated
counterparts.
The assembly code is parsed to analyze each instruction and
identify which operations suit MBA obfuscation.asmMBAspecif-
ically focuses on transforming arithmetic and logical operations
such asADD,SUB,AND,OR, andXOR. However, specific instructions,
likeMUL, are excluded due to the excessive complexity they would
introduce during MBA transformation, andDIVis omitted entirely,
as no effective MBA transformation exists for division. Addition-
ally, instructions involving theESPandEIPregisters—critical for
managing stack operations and control flow—are excluded to avoid
destabilizing the program’s execution.
MBA expressions inherently generate many intermediate results
during execution, which can exceed the available registers. To ad-
dress this,asmMBAoptimizes the storage of intermediate values by
utilizing the stack. Rather than popping values, performing opera-
tions, and pushing results back, our method directly accesses and

```
manipulates values in place on the stack. This reduces the overhead
caused by excessivePUSHandPOPoperations, thereby improving
both speed and efficiency.
```
## 7 Evaluation

```
In this section, we comprehensively evaluateasmMBAusing five key
metrics: Correctness (Section 7.1), Diversity (Section 7.2), Defense
against the Chosen-Instruction Attack (Section 7.3), Resistance to
MBA Deobfuscation (Section 7.4), and Performance Overhead (Sec-
tion 7.5). These metrics are chosen to assessasmMBA’s ability to
obfuscate code effectively while maintaining functional correct-
ness, resisting known deobfuscation attacks, and minimizing per-
formance impact.
To ensure reliable results, we used program benchmarks previ-
ously used to evaluate Loki’s MBA obfuscation and the Chosen-
Instruction Attack. These benchmarks provide a reliable basis for
assessingasmMBA’s performance against known deobfuscation tools
and attack vectors. We evaluated the effectiveness ofasmMBAby
protecting input programs with bothasmMBAand VMProtect virtu-
alization obfuscation tools and compared the results against pro-
grams protected with only VMProtect. This comparison allowed
us to isolate the contributions ofasmMBAand assess how much
added complexity and security it introduced beyond standard virtu-
alization obfuscation. Additionally, we varied the protection level
ofasmMBA(ranging from level 1 to 5) as well as the proportion of
the target program to which it was applied (25% and 100%). This
variation allowed us to evaluate the trade-offs between security
and performance and determine how different obfuscation levels
impact both protection and efficiency.
The target program for our evaluation implements encryption
algorithms commonly used in real-world applications, such as
AES, DES, MD5, RC4, and SHA1 (as referenced in Loki’s exper-
iments [ 21 ]). These algorithms are ideal for benchmarking because
they are computationally intensive and widely deployed in intellec-
tual property protection and DRM systems, making them highly
relevant to real-world security scenarios.
The test environment consisted of an Intel Core i9-10900 CPU @
2.80GHz running Windows 10 Pro (64-bit). We used MinGW-w
gcc-8.1.0 [ 7 ], which supports the GCC compiler for Windows, to
applyasmMBAduring the compilation of the target programs. The
build process involved the following steps:
```
- The source code was compiled using GCC with the options
    -O3,-nasm=intel,-m32, and-S, generating optimized 32-bit
       assembly code.
- asmMBAwas applied to obfuscate selected instructions in the
    assembly code.
- The MBA-obfuscated assembly code was compiled into a
    binary.
- VMProtect v3.6 was applied to produce the final obfuscated
    software.

## 7.1 Correctness

```
Evaluating the correctness ofasmMBAis crucial to confirm that
obfuscated programs retain their original functionality, especially in
security-sensitive environments where even minor deviations can
be exploited [ 4 , 20 ]. Maintaining logical and operational stability
```

```
SAC ’25, March 31-April 4, 2025, Catania, Italy H. Jin et al.
```
```
Table 1: Number of Target Instructions for Various Programs
```
```
Program AES DES MD5 RC4 SHA
Target Instructions 134 135 25 29 78
```
ensures that the obfuscated code behaves identically to the original
under all valid inputs, preventing unintended side effects such as
crashes or compromised outputs.
asmMBAapplies randomly selected MBA rewrite rules to des-
ignated instructions, potentially increasing complexity by intro-
ducing additional arithmetic or Boolean operations. During this
process, errors may arise from excessive stack usage (PUSH/POP), al-
tered register states, or unanticipated instruction interactions. Such
issues stem from the heavy interplay of arithmetic and bitwise logic,
which can disrupt normal data flow if not carefully managed.
To verify correctness, we extensively tested multiple real-world
cryptographic programs (Table 1), each subjected to various input
ranges. Five obfuscated instances were generated for each program
by altering two parameters: the nesting depth of MBA rewrites
(level 3 vs. level 5) and the percentage of instructions transformed
(25% vs. 100%). This produced 100 unique configurations, each
evaluated with 10,000 test cases covering typical and edge-case
inputs. Throughout these tests, every obfuscated instance produced
outputs identical to those of the unobfuscated original, indicating
that the obfuscation process introduced no functional discrepancies.
Notably, this correctness held even under high-complexity con-
ditions, where deeper nesting and full coverage might significantly
alter the structure of the assembly code. Such consistency demon-
strates thatasmMBA’s transformation rules, though extensive, pre-
serve the program’s intended behavior across a wide range of ob-
fuscation intensities.
In conclusion,asmMBAmaintains correctness across diverse work-
loads and obfuscation settings, making it a dependable solution
for software requiring robust protection without risking logical or
operational integrity.

## 7.2 Diversity

```
Diversity in obfuscation techniques is the capacity to generate mul-
tiple distinct versions of the same program, preventing attackers
from reusing reverse-engineered knowledge [ 25 ]. If one obfuscated
instance is compromised, a diverse scheme ensures that another
instance—created under different rewrite rules—does not share
identical or easily predictable patterns. Thus, an attacker who suc-
cessfully deobfuscates a single variant cannot automatically apply
the same insights to all other variants, significantly raising the
overall level of protection.
asmMBAachieves high diversity by independently applying MBA
transformations to each instruction in the program. Since these
transformations are chosen randomly and can differ for each build,
even repeated obfuscations of the same source code produce signif-
icantly different outputs. The degree of diversity depends on two
main factors: (1) the total number of instructions eligible for MBA
obfuscation and (2) the variety (or “pool”) of MBA representations
available per instruction.
(number of MBA representations)(number of target instructions)
```
```
Table 2: The number of kernels based on the level of asmMBA
and the corresponding number of kernels successfully at-
tacked by a Chosen-Instruction Attack
```
```
asmMBA
Level
```
```
Number of
Instruction
lines
```
```
kernel
```
```
Num. of programs
successful in a
Chosen-
Instruction Attack
0 (origin) 1105 26 21
1 5331 175 3
3 9895 328 2
5 33296 1361 0
```
```
In our implementation,asmMBAprovides 50 rewrite rules for
each operator (e.g., ADD, SUB, AND). Each time an operator is
encountered, one of the 50 rules is randomly selected and poten-
tially layered with additional nested rewrites, especially at higher
protection levels. This independent, repeated application of rules
leads to an exponential growth in possible outcomes, ensuring that
even small programs (e.g., MD5 with 25 obfuscate instructions) can
yield on the order of 5025 ≈ 1042 unique variants.
This vast potential for diversity makes it highly unlikely that two
obfuscated binaries will be structurally identical. Attackers must,
therefore, analyze each instance from scratch, as any “reusable” de-
obfuscation knowledge gleaned from one version may not apply to
another with different rewrite choices. The result is a substantially
higher reverse engineering workload, curtailing automated pattern
recognition and mass deobfuscation attempts.
Overall, by ensuring each obfuscated instance is distinct,asmMBA
amplifies the cost and complexity of reverse engineering. This ap-
proach strengthens resistance to advanced attacks like the Chosen-
Instruction Attack and makes common deobfuscation strategies
less efficient. Diversity becomes a core pillar ofasmMBA’s defen-
sive capability, discouraging attackers from leveraging uniform
exploitation techniques across multiple protected binaries.
```
## 7.3 Chosen-Instruction Attack

```
The Chosen Instruction Attack is designed to uncover how commer-
cial virtualization obfuscation tools map native instructions to their
virtualized equivalents. It achieves this by inserting anchor instruc-
tion pairs around a target instruction (the knowledge-leaking code)
and observing how these instructions are virtualized. The goal is
to reveal the rules the virtualization obfuscator’s handler uses for
specific instructions. In this process, attackers isolate a kernel of
core instructions that encapsulate the program’s essential logic
after virtualization. These instructions are critical, representing
how the VM operates at its core. Attackers then convert both the
knowledge-leaking code and the kernel into symbolic formulas and
compare them. If the formulas match, it confirms that the kernel
has been accurately extracted, allowing the attacker to deduce the
mapping rules used by the virtualization tool. However, if equiv-
alence between the two formulas cannot be verified, it questions
the accuracy of the kernel extraction, significantly reducing the
effectiveness of the Chosen Instruction Attack. Thus, a failure to
extract a correct kernel directly hampers the attack’s success in
reverse-engineering the virtualization logic.
```

```
asmMBA SAC ’25, March 31-April 4, 2025, Catania, Italy
```
```
MBA-Blast MBA-Solver Loki-Blast
Deobfuscation Tools
```
```
0
```
```
20
```
```
40
```
```
60
```
```
80
```
```
100
```
```
X(0%) X(0%) X(0%) X(0%)
```
```
(91~100%)
```
```
X(0%)
```
```
Comparison of Deobfuscation Success Rates
Loki-MBA
asmMBA
```
```
Figure 5: MBA-Blast, MBA-Solver, and Loki-Blast tools mea-
sure the deobfuscation success rate, comparing the proposed
asmMBA with Loki’s MBA expressions
```
To evaluateasmMBA’s resilience against this attack, we specifi-
cally targeted instructions that were successfully used in previous
Chosen Instruction Attack attempts. Our test focused on five stan-
dard instructions—ADD,SUB,AND,OR, andXOR—chosen for their rele-
vance in deobfuscation attempts. We created several input programs
using various operand types (registers, memory, and immediate
values) to assess whetherasmMBAobfuscation would disrupt the
extraction of kernels and the reconstruction of mapping rules. Af-
ter applying VMProtect virtualization obfuscation and running the
Chosen Instruction Attack^3 on 21 programs, we re-appliedasmMBA
obfuscation at protection levels 1, 3, and 5. The results, shown in
Table 2, demonstrate thatasmMBAsignificantly reduces the attack’s
success rate. Higher protection levels increase code complexity,
which makes it much harder to reconstruct the mapping rules
through symbolic execution.
At protection level 3, the total instruction count increased to
9,895, with 328 kernels, representing an approximate 10x and 13x
increase over the original, respectively. Consequently, the success
rate of the Chosen Instruction Attack dropped from 21 success-
ful cases to only 2. At protection level 5, the attack’s success rate
dropped even further. The length of the kernel increased more
than 50 times compared to the original, making heuristic analy-
sis extremely difficult. This demonstrates thatasmMBAeffectively
mitigates the threat posed by the Chosen Instruction Attack by
substantially increasing the complexity of the code and the number
of instructions to be analyzed. Both static and dynamic analysis
become significantly more challenging, affirmingasmMBA’s ability
to strengthen the security of virtualized software against advanced
deobfuscation techniques.

## 7.4 MBA Deobfuscation

```
MBA-based obfuscation, including ourasmMBA, is most vulnera-
ble when expressions remain shallow or rely on easily recognized
rewrite rules. Tools such as MBA-Blast and MBA-Solver leverage 1-
bit equivalences to systematically reduce more straightforward for-
mulas. Loki attempted to combat this by nesting MBA expressions,
yet our Loki-Blast attack (Section 4) showed that Loki’s patterns,
although advanced, could still be partially unraveled.
```
(^3) Chosen-Instruction Attack, https://github.com/chosen-instruction-attack
3 (25%) 3 (100%) 5 (25%) 5 (100%)
**Protection Levels and Percentages**
1.
1.
2.
2.
3.
3.
**Code Section Overhead (times)
Code Section Overhead with asmMBA Applied to Test Target Programs**
Target Programs
AES
DES
MD
RC
SHA
Figure 6: Code section overhead of programs with **asmMBA**
To bolster MBA complexity,asmMBAincorporates additional
rewriting rules—especially those involvingNEG—to disrupt 1-bit-
based simplifications. At higher levels (3 and 5), these nested con-
structs become resistant to standard deobfuscation techniques, as
they no longer adhere to the assumptions (e.g., consistent bitwise
transforms) that allow for algebraic or symbolic reduction. Com-
pared to Loki’s approach, which can be undone by reducing nesting
depth,asmMBAdesigns its transformations so that expressions can-
not be easily flattened, preserving the obfuscation layers.
Figure 5 illustrates howasmMBAfully resists MBA-Blast, MBA-
Solver, and Loki-Blast, whereas Loki remains vulnerable to the
latter, with a 91% deobfuscation success. These results confirm
that integrating more profound and more diverse rewrite rules,
along withNEGinstructions, substantially raises the difficulty for
automatic deobfuscation tools.

## 7.5 Performance Overhead

```
asmMBAsignificantly strengthens a program’s resilience against
MBA-centric and chosen-instruction-based attacks, but this im-
provement comes with increased code size and runtime costs. To
quantify this overhead, we measured the code section growth and
execution time using cryptographic algorithms under typical multi-
layered protection (i.e.,asmMBA+ VMProtect). We then compared
these to a baseline with VMProtect alone, isolatingasmMBA’s impact.
Figure 6 demonstrates how code size grows with higher protec-
tion levels. While level 3 inflates code sections by about 1.1x, level
5 can reach 1.8x. Such an increase may be justified for security-
critical environments if preventing reverse engineering is a top
priority. Similarly, Figure 7 shows that runtime overhead can range
from 2–3x at level 3 with partial obfuscation (25%) to as high as 10x
at level 5 with full coverage (100%). Such a trade-off suits scenarios
where security requirements outweigh performance constraints.
In practice, developers often apply virtualization selectively to
high-value functions rather than the entire codebase. Adopting a
similar selective strategy forasmMBAcan moderate the performance
penalty. Hence, although level 5 with 100% coverage yields maximal
protection, it may be overkill for certain applications, and a lower-
level or partial obfuscation can strike a better balance.
Our findings indicate thatasmMBAdelivers robust security gains
against modern deobfuscation efforts, with overhead that can be
```

```
SAC ’25, March 31-April 4, 2025, Catania, Italy H. Jin et al.
```
```
3 (25%) 3 (100%) 5 (25%) 5 (100%)
Protection Levels and Percentages
```
```
5
```
```
10
```
```
15
```
```
20
```
```
25
```
```
30
```
```
Runtime Overhead (times)
```
```
Runtime Overhead with asmMBA Applied to Test Target Programs
Target Programs
AES
DES
MD
RC
SHA
```
```
Figure 7: Runtime overhead of programs with asmMBA
```
tuned based on the desired protection level. Where performance is
less critical,asmMBAcan be deployed more extensively; conversely,
where speed remains vital, partial or moderate-level obfuscation
can still significantly raise the bar for attackers.
In conclusion,asmMBArepresents a viable solution for scenarios
demanding advanced obfuscation, provided that the resulting per-
formance trade-offs align with the application’s security priorities.
Selective or partial deployment can mitigate the cost while retain-
ing significant protection advantages, makingasmMBAadaptable to
various real-world software protection strategies.

## 8 Conclusion

```
In this paper, we presentedasmMBA. This assembly-based MBA
obfuscation technique augments virtualization obfuscation with
more complex transformations and theNEGinstruction, disrupting
advanced deobfuscation strategies like MBA-Blast and the Chosen-
Instruction Attack. This heightened complexity challenges both
static and dynamic analysis, strengthening the overall security
posture of protected software.
We demonstratedasmMBAon real-world cryptographic algo-
rithms often targeted by reverse engineering. While this approach
increases complexity, the resulting performance overhead—about
a 1.1x increase in code size and a 2–3x increase in runtime for se-
lectively protected regions—can be justified in scenarios requiring
robust defense against sophisticated attacks.asmMBAalso provides
flexibility to balance security and performance based on specific
application needs.
In conclusion,asmMBAoffers a tangible and effective means of re-
inforcing virtualization obfuscation against modern deobfuscation
techniques. By blending assembly-level transformations with strate-
gic MBA constructs, our approach delivers enhanced resilience and
an adaptable performance profile suitable for security-critical ap-
plications.
```
## Acknowledgments

```
This research was funded by the Institute of Information & Commu-
nications Technology Planning & Evaluation (IITP) grant number
RS-2024-00399389, funded by the Korea government (MSIT).
```
## References

```
[1]Adnan Akhunzada, Mehdi Sookhak, Nor Badrul Anuar, Abdullah Gani, Ejaz
Ahmed, Muhammad Shiraz, Steven Furnell, Amir Hayat, and Muhammad Khur-
ram Khan. 2015. Man-At-The-End attacks: Analysis, taxonomy, human aspects,
motivation and future directions.Journal of Network and Computer Applications
48 (2015), 44–57.
[2]Cataldo Basile, Bjorn De Sutter, Daniele Canavese, Leonardo Regano, and Bart
Coppens. 2023. Design, implementation, and automation of a risk management
approach for man-at-the-End software protection.Computers & Security 132
(2023), 103321.
[3]Fabrizio Biondi, Sébastien Josse, Axel Legay, and Thomas Sirvent. 2017. Effec-
tiveness of synthesis in concolic deobfuscation.Computers & Security70 (2017),
500–515.
[4]Matteo Campanelli, Danilo Francati, and Claudio Orlandi. 2023. Structure-
preserving compilers from new notions of obfuscations. InIACR International
Conference on Public-Key Cryptography. Springer, 663–693.
[5]Zhe Chen, Chunfu Jia, Tongtong Lv, and Tong Li. 2018. Harden Tamper-Proofing
to Combat MATE Attack. InAlgorithms and Architectures for Parallel Processing:
18th International Conference, ICA3PP 2018, Guangzhou, China, November 15-17,
2018, Proceedings, Part IV 18. Springer, 98–108.
[6]Leonardo De Moura and Nikolaj Bjørner. 2008. Z3: An efficient SMT solver. In
International conference on Tools and Algorithms for the Construction and Analysis
of Systems. Springer, 337–340.
[7]Material for MkDocs. accessed on 15. November 2023.MinGW-w64 gcc-8.1.0.
https://www.mingw-w64.org/downloads/.
[8]Yoann Guillot and Alexandre Gazet. 2010. Automatic binary deobfuscation.
Journal in computer virology6, 3 (2010), 261–276.
[9]Anatoli Kalysch, Johannes Götzfried, and Tilo Müller. 2017. VMAttack: Deobfus-
cating virtualization-based packed binaries. InProceedings of the 12th International
Conference on Availability, Reliability and Security. 1–10.
[10]Tımea László and Ákos Kiss. 2009. Obfuscating C++ programs via control flow
flattening.Annales Universitatis Scientarum Budapestinensis de Rolando Eötvös
Nominatae, Sectio Computatorica30, 1 (2009), 3–19.
[11]Shijia Li, Chunfu Jia, Pengda Qiu, Qiyuan Chen, Jiang Ming, and Debin Gao. 2022.
Chosen-instruction attack against commercial code virtualization obfuscators. In
In Proceedings of the 29th Network and Distributed System Security Symposium.
[12]Binbin Liu, Weijie Feng, Qilong Zheng, Jing Li, and Dongpeng Xu. 2021. Software
obfuscation with non-linear mixed boolean-arithmetic expressions. InInfor-
mation and Communications Security: 23rd International Conference, ICICS 2021,
Chongqing, China, November 19-21, 2021, Proceedings, Part I 23. Springer, 276–292.
[13]Binbin Liu, Junfu Shen, Jiang Ming, Qilong Zheng, Jing Li, and Dongpeng Xu.
2021.{MBA-Blast}: Unveiling and Simplifying Mixed{Boolean-Arithmetic}
Obfuscation. In30th USENIX Security Symposium (USENIX Security 21). 1701–
1718.
[14] Oreans. accessed on 2. March 2024.Themida. http://www.oreans.com.
[15]Oreans. accessed on 4. March 2024.Code Virtualizer. https://www.oreans.com/
CodeVirtualizer.php.
[16] Oreans. accessed on 4. March 2024.Obsidium. https://www.obsidium.de/home.
[17]J Raber. 2013. Virtual deobfuscator-a darpa cyber fast track funded effort.Proc.
of the 16th Black Hat USA(2013).
[18]Rolf Rolles. 2009. Unpacking Virtualization Obfuscators.WOOT9 (2009), 1–10.
[19]Jonathan Salwan, Sébastien Bardin, and Marie-Laure Potet. 2018. Symbolic deob-
fuscation: From virtualized code back to the original. InInternational Conference
on Detection of Intrusions and Malware, and Vulnerability Assessment. Springer,
372–392.
[20]Moritz Schloegel, Tim Blazytko, Moritz Contag, Cornelius Aschermann, Julius
Basler, Thorsten Holz, and Ali Abbasi. 2021. Technical Report: Hardening Code
Obfuscation Against Automated Attacks.arXiv preprint arXiv:2106.08913(2021).
[21]Moritz Schloegel, Tim Blazytko, Moritz Contag, Cornelius Aschermann, Julius
Basler, Thorsten Holz, and Ali Abbasi. 2022. Loki: Hardening code obfuscation
against automated attacks. In31st USENIX Security Symposium (USENIX Security
22). 3055–3073.
[22] VMPSoft. accessed on 15. April 2023.VMProtect. http://www.vmpsoft.com.
[23]Dongpeng Xu, Binbin Liu, Weijie Feng, Jiang Ming, Qilong Zheng, Jing Li, and
Qiaoyan Yu. 2021. Boosting SMT solver performance on mixed-bitwise-arithmetic
expressions. InProceedings of the 42nd ACM SIGPLAN International Conference
on Programming Language Design and Implementation. 651–664.
[24]Dongpeng Xu, Jiang Ming, Yu Fu, and Dinghao Wu. 2018. VMHunt: A verifiable
approach to partially-virtualized binary code simplification. InProceedings of
the 2018 ACM SIGSAC Conference on Computer and Communications Security.
442–458.
[25]Hui Xu, Yangfan Zhou, Jiang Ming, and Michael Lyu. 2020. Layered obfuscation: a
taxonomy of software obfuscation techniques for layered security.Cybersecurity
3 (2020), 1–18.
[26]Yongxin Zhou, Alec Main, Yuan X Gu, and Harold Johnson. 2007. Information
hiding in software with mixed boolean-arithmetic transforms. InInternational
Workshop on Information Security Applications. Springer, 61–75.
```

