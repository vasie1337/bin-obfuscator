
Padding Matters – Exploring Function Detection in PE Files
==========================================================

Raphael Springer [0009-0008-8298-7895](https://orcid.org/0009-0008-8298-7895 "ORCID identifier") Westphalian University of Applied SciencesInstitute for Internet SecurityGelsenkirchenGermany [springer@internet-sicherheit.de](mailto:springer@internet-sicherheit.de) , Alexander Schmitz [0009-0006-0514-9535](https://orcid.org/0009-0006-0514-9535 "ORCID identifier") Westphalian University of Applied SciencesInstitute for Internet SecurityGelsenkirchenGermany [schmitz@internet-sicherheit.de](mailto:schmitz@internet-sicherheit.de) , Artur Leinweber [0009-0001-7623-1038](https://orcid.org/0009-0001-7623-1038 "ORCID identifier") Westphalian University of Applied SciencesInstitute for Internet SecurityGelsenkirchenGermany [leinweber@internet-sicherheit.de](mailto:leinweber@internet-sicherheit.de) , Tobias Urban [0000-0003-0908-0038](https://orcid.org/0000-0003-0908-0038 "ORCID identifier") Westphalian University of Applied SciencesInstitute for Internet SecurityGelsenkirchenGermany [urban@internet-sicherheit.de](mailto:urban@internet-sicherheit.de) and Christian Dietrich [0009-0001-5523-4467](https://orcid.org/0009-0001-5523-4467 "ORCID identifier") Westphalian University of Applied SciencesInstitute for Internet SecurityGelsenkirchenGermany [dietrich@internet-sicherheit.de](mailto:dietrich@internet-sicherheit.de)

###### Abstract.

Function detection is a well-known problem in binary analysis. While previous research has primarily focused on Linux/ELF, Windows/PE binaries have been overlooked or only partially considered. This paper introduces FuncPEval, a new dataset for Windows x86 and x64 PE files, featuring Chromium and the Conti ransomware, along with ground truth data for 1,092,820 function starts. Utilizing FuncPEval, we evaluate five heuristics-based (Ghidra, IDA, Nucleus, rev.ng, SMDA) and three machine-learning-based (DeepDi, RNN, XDA) function start detection tools. Among the tested tools, IDA achieves the highest F1\-score (98.44%) for Chromium x64, while DeepDi closely follows (97%) but stands out as the fastest by a significant margin.

Working towards explainability, we examine the impact of padding between functions on the detection results. Our analysis shows that all tested tools, except rev.ng, are susceptible to randomized padding. The randomized padding significantly diminishes the effectiveness for the RNN, XDA, and Nucleus. Among the learning-based tools, DeepDi exhibits the least sensitivity and demonstrates overall the fastest performance, while Nucleus is the most adversely affected among non-learning-based tools.

In addition, we improve the recurrent neural network (RNN) proposed by Shin et al. and enhance the XDA tool, increasing the F1\-score by approximately 10%.

1\. Introduction
----------------

Binary code analysis is a building block of several applications addressing threats for Internet users, such as malware analysis or vulnerability research. One of the essential first steps in analyzing (compiled) applications is detecting functions in the code (e.g., as input to decompilation or for function-level similarity methods). For example, Haq and Caballero ([haq2021survey,](https://arxiv.org/html/2504.21520v1#bib.bib11) ) find that 30 out of 61 binary similarity methods operate on a function-level granularity and thus rely on function detection as an initial analysis step. In this scenario, missing a function or incorrectly detecting a false function start might disrupt code similarity pipelines, potentially preventing them from correctly identifying a malware sample as part of a specific malware family. Further, without proper function detection, it is hard to assess the important parts for further analysis (e.g., to identify the malicious capabilities a malware sample might exhibit). Hence, reliably extracting functions from compiled binary software is critical for analyzing binary code.

With millions of hash-unique malware samples emerging every year ([AVInstitute,](https://arxiv.org/html/2504.21520v1#bib.bib14) ), automation is key to scalable analysis tooling in various use cases, e.g., binary similarity and clustering, malware lineage, actor and tool tracking for threat intelligence, or prioritization for dynamic analysis such as sandboxing ([GoogleTI,](https://arxiv.org/html/2504.21520v1#bib.bib22) ). Thus, reliable, fast, and automated function start detection is key.

Currently, existing tools often use heuristic or pattern-based methods to identify function starts ([idapro,](https://arxiv.org/html/2504.21520v1#bib.bib23) ; [ghidra,](https://arxiv.org/html/2504.21520v1#bib.bib1) ; [smda\_github,](https://arxiv.org/html/2504.21520v1#bib.bib20) ). These heuristics are compiled by experts based on their experiences when analyzing binaries. Like all heuristics, these approaches might be incomplete and must be updated regularly. Thus, recent work suggested machine learning-based approaches ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ; [rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ; [xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ; [DeepDi,](https://arxiv.org/html/2504.21520v1#bib.bib28) ) for function detection to increase performance and accuracy and reduce the need for experts to identify new patterns. However, Koo et al. ([Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ) outline challenges and shortcomings when detecting functions in compiled binary code and revisit previous datasets, metrics, and evaluations. They show that previous work has suffered from effects such as overfitting (e.g., due to missing normalization), in the appropriate definition of true negatives, and imbalance due to significant redundancy in the datasets (shared static library), skewing the evaluation ([Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ). Thus, it is unclear whether machine learning-based approaches meet the expectations and can effectively reduce the need for human experts to develop heuristics. Additionally, related work often primarily covers functions in Linux/ELF samples and only analyzes fewer Windows/PE functions, if any. However, with a significant malware set targeting Windows operating systems ([AVInstitute,](https://arxiv.org/html/2504.21520v1#bib.bib14) ), evaluating function detection on PE plays an important role. While the binary code parts of these two formats can use the same instruction set architecture (ISA) (e.g., x64), differences exist in the application binary interfaces (ABI) of Linux and Windows. Factors that may influence the function start detection efficacy include calling conventions and compiler-specific quirks (e.g., padding schemes, inline data, and metadata associated with Windows-specific tools like Microsoft Visual Studio). Thus, it is unclear if and how the proposed methods can be generalized from ELF samples to other formats.

In this work, we shed light on these challenges by comparing eight (five heuristics-based and three machine-learning-based) function start detection tools. We specifically focus on 32-bit and 64-bit Windows PE binaries of benign and malicious code examples. More specifically, based on previous works ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ; [rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ), we train two machine-learning-based tools on a commonly used dataset ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ) to find function starts. We then test the efficiency of these tools and six further tools ([idapro,](https://arxiv.org/html/2504.21520v1#bib.bib23) ; [ghidra,](https://arxiv.org/html/2504.21520v1#bib.bib1) ; [nucleus,](https://arxiv.org/html/2504.21520v1#bib.bib5) ; [DeepDi,](https://arxiv.org/html/2504.21520v1#bib.bib28) ; [smda\_dis,](https://arxiv.org/html/2504.21520v1#bib.bib8) ; [revng,](https://arxiv.org/html/2504.21520v1#bib.bib9) ) on a newly built dataset consisting of samples and ground truth. We evaluate the tools on a Chromium sample for Windows and the _Conti_ ransomware (x86 and x64). On a high level, our results indicate that all tested tools generalize well across file formats but that the effectiveness of machine-learning-based tools collapses when they face toolchain-specific quirks (i.e., different padding schemes).

In summary, we make the following contributions:

*   •
    
    We introduce FuncPEval, a new x86 and x64 Windows PE dataset that contains malicious and benign software samples spanning 1,092,820 functions. Using this dataset, we compare eight tools, proposed within the past decade and commonly used for function start detection in the field. We show that all used tools can generally identify function starts in regular PE files with high precision and recall.
    
*   •
    
    Based on previous work, we train two machine learning-based function start detection tools ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ; [rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ) on a commonly used dataset. For further analysis, we optimize the provided methods, improving XDA’s F1\-score by approximately 10%.
    
*   •
    
    Finally, we demonstrate that modifying the padding between functions in a given sample impacts the function start detection. For some tools, the effectiveness of function start detection methods relies heavily on the unmodified padding between functions as emitted by standard compilers. When this padding is altered, the effectiveness for learning-based methods deteriorates, with F1\-scores down 30 to 70 percent points. Thus, our results indicate that the machine learning approaches might be susceptible to spurious correlation ([dos\_and\_donts\_machine\_learning,](https://arxiv.org/html/2504.21520v1#bib.bib6) ).
    

2\. Related Work
----------------

Function detection can be categorized into heuristics- and pattern-based detection (e.g., signatures on function prologues and epilogues), static analysis techniques (e.g., CFG extraction), and machine learning-based approaches described in more detail in the following subsections.

Table 1. Function start detection methods and evaluation papers. The amount of PE functions for Nucleus ([nucleus,](https://arxiv.org/html/2504.21520v1#bib.bib5) ) is an estimate as the number of samples and the description in the paper indicate that the same dataset as in ([andriesse2016,](https://arxiv.org/html/2504.21520v1#bib.bib4) ) was used. Compilers refers to the compilers that were used to generate the dataset, i.e., GNU Compiler Collection, Clang, Visual Studio, and Intel C/C++ Compiler.

Tool/Paper Compilers Samples Functions ML GCC Clang VS ICC ELF PE ELF PE FuncPEval (our dataset) ✓ ✓ 0 4 0 1,092,820 ✗ FunProbe ([FunProbe,](https://arxiv.org/html/2504.21520v1#bib.bib15) ) ✓ ✓ 19,872 0 3,064,001 0 ✗ DeepDi ([DeepDi,](https://arxiv.org/html/2504.21520v1#bib.bib28) ) ✓ ✓ 1,440 688 n/a n/a ✓ Koo et al. ([Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ) ✓ ✓ 152 0 769,069 0 ✗ FETCH ([pang2021,](https://arxiv.org/html/2504.21520v1#bib.bib18) ) ✓ 43 0 1,105,278 0 ✗ XDA ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ) ✓ ✓ ✓ 2,593 528 n/a n/a ✓ Jima ([Alves-Foss\_Song\_2019,](https://arxiv.org/html/2504.21520v1#bib.bib2) ) ✓ ✓ ✓ 3,790 0 4,913,753 0 ✗ LEMNA ([lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) ✓ 2,064 0 n/a 0 ✓ Nucleus ([nucleus,](https://arxiv.org/html/2504.21520v1#bib.bib5) ) ✓ ✓ ✓ 324 152 n/a est. 378,965 ✗ REV.NG ([revng,](https://arxiv.org/html/2504.21520v1#bib.bib9) ) ✓ ✓ 1,890 0 n/a 0 ✗ Andriesse et al. ([andriesse2016,](https://arxiv.org/html/2504.21520v1#bib.bib4) ) ✓ ✓ ✓ 829 152 1,525,024 378,965 ✗ Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ) ✓ ✓ ✓ 2,064 136 598,359 187,836 ✓ BAP/ByteWeight ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ) ✓ ✓ 2,064 136 598,359 187,836 ✓ Rosenblum et al. ([rosenblum,](https://arxiv.org/html/2504.21520v1#bib.bib24) ) ✓ ✓ ✓ 728 443 283,626 100,427 ✓

### 2.1. Static code analysis and pattern-based approaches

IDA Pro ([idapro,](https://arxiv.org/html/2504.21520v1#bib.bib23) ) uses proprietary patterns to identify function starts. Similarly, Ghidra ([ghidra,](https://arxiv.org/html/2504.21520v1#bib.bib1) ) uses a combination of signatures111Ghidra’s patterns are available from [https://github.com/NationalSecurityAgency/ghidra/blob/b9496de7f573e6a73888abfb51c243723785dbdb/Ghidra/Processors/x86/data/patterns/x86win\_patterns.xml](https://github.com/NationalSecurityAgency/ghidra/blob/b9496de7f573e6a73888abfb51c243723785dbdb/Ghidra/Processors/x86/data/patterns/x86win_patterns.xml) and static analysis techniques. The signatures typically cover machine code instruction sequences in the form of byte patterns that precede a function, such as padding or an epilogue, or that are typically observed at the start of a function, such as a prologue or allocation routines. In September 2022, Ghidra introduced the Random Forest Function Finder Plugin, a machine learning-based approach that is trained on previously recognized functions of the currently analyzed binary and attempts to find similar function starts. This differs from the following machine learning approaches in that it is applied on a per-sample scope and does not attempt to globally model function starts. Andriesse et al. ([andriesse2016,](https://arxiv.org/html/2504.21520v1#bib.bib4) ) evaluate existing disassemblers and their function boundary recovery. They conclude that false negative rates of function starts typically reach 20% or more, indicating significant shortcomings when applied in practice. A follow-up work by Andriesse et al. ([nucleus,](https://arxiv.org/html/2504.21520v1#bib.bib5) ) proposes Nucleus, a compiler-agnostic function detection tool that constructs an inter-procedural control flow graph. Similarly, rev.ng by Di Federico et al. ([revng,](https://arxiv.org/html/2504.21520v1#bib.bib9) ) proposes a set of analyses to extract function starts based on QEMU’s lifter and LLVM’s intermediate representation, thus operating without ISA-specific heuristics.

Alves-Foss and Song ([Alves-Foss\_Song\_2019,](https://arxiv.org/html/2504.21520v1#bib.bib2) ) propose detecting function boundaries using control flow analysis, jump and call targets, exception metadata, and detection of terminal and missing functions. Their approach is implemented in the Jima tool, which supports Linux ELF samples only and is currently only available in compiled form. FETCH by Pang et al. ([pang2021,](https://arxiv.org/html/2504.21520v1#bib.bib18) ) leverages call frames, i.e., frame description entries in the exception handling information as mandated by the x64/amd64 System V Application Binary Interface. Such call frame information is typically added by the compiler at build time. While evaluating against x64 ELF samples only, the authors note that x64 PE and ARM will likely exhibit similar metadata. However, such metadata is not always present, especially in malware.

SMDA by Plohmann ([smda\_dis,](https://arxiv.org/html/2504.21520v1#bib.bib8) ) combines recursive disassembly and heuristics for function entry point discovery and later performs a gap analysis to find missed functions.

In 2023, FunProbe by Kim et al. ([FunProbe,](https://arxiv.org/html/2504.21520v1#bib.bib15) ) proposes a probabilistic model using a Bayesian Network over causal relationships between heuristically identified function entry point candidates. First, an inter-procedural CFG is recovered, and up to 16 function identification hints are collected based on data-driven properties, e.g., FDE, and code-driven properties, e.g., call targets. Then, a Bayesian Network is built, followed by belief propagation. As a result, each byte yields an inferred probability of being a function start when exceeding a given threshold. FunProbe currently only supports ELF files and has been evaluated on a total of 19,872 ELF samples covering x86, x64, ARM, and MIPS architectures.

### 2.2. Machine learning based approaches

Approaches that leverage machine learning have initially been proposed by Rosenblum et al. ([rosenblum,](https://arxiv.org/html/2504.21520v1#bib.bib24) ). They model function start detection as a classification problem using Conditional Random Fields.

In 2014, Bao et al. introduced a function boundary detection approach called ByteWeight ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ). It uses a weighted prefix tree to learn signatures that can be used to detect function starts. In the case of ByteWeight, each branch represents a sequence of bytes or instructions. The depth of the tree determines the length of the sequence. The weighted prefix tree adds a weight to each node in the tree, representing the probability that the branch starts a function. The authors build the weighted prefix tree by training a non-weighted prefix tree with all possible byte or instruction combinations using ground truth data. Therefore, ByteWeight suffers from the same problems as traditional signature-based approaches, e.g., depending on compiler versions. Nevertheless, ByteWeight can automatically generate signatures when ground truth data is available. For each architecture and compiler, ByteWeight has to generate new signatures and, therefore, also requires new ground truth data. While ByteWeight aims to detect function starts, Bao et al. present further analysis techniques that can be applied after the function start detection that lift the approach to detect all instructions belonging to the function.

In 2015, Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ) introduced function boundary detection using a bidirectional recurrent neural network (RNN). The RNN uses a sequence of bytes as input and decides for each byte if it marks the start of a function. Similar to ByteWeight, the weights of the RNN are trained using ground truth data. The trained weights form the model used to detect function starts. The RNN can also detect the boundaries of a function by using two models. One model detects function starts, and the other model detects function ends. The authors do not provide an implementation of their approach. However, a reimplementation was provided by Guo et al. ([lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) as part of their work on the explainability of machine learning-based methods.

In 2021, Pei et al. ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ) propose XDA, which relies on transfer learning of machine code disassembly and also recovers function boundaries. They are motivated by masked language modeling to infer dependencies between specific bytes in machine code. While the paper evaluates on x86 and x86-64 samples, targeting both ELF and PE, a fine-tuned model of XDA has only been published for x86-64. XDA models function boundary detection as a multi-class classification problem where a specific byte can either form the start of a function, the end of a function, or neither of both.

DeepDi, a system published by Yu et al. ([DeepDi,](https://arxiv.org/html/2504.21520v1#bib.bib28) ) in 2022, combines instruction-level sequences with a graph convolutional network to achieve disassembly. First, given a byte string as input, all possible instructions are decoded using a 15-byte sliding window over the input stream, yielding the superset of instructions. Then, an instruction flow graph is constructed that captures the most likely true instructions and their relations. The system also contains heuristics and a classifier for function start detection based on the resulting disassembly. In contrast to previous work, DeepDi is the first learning-based approach that operates on the instruction level instead of the byte level.

### 2.3. Limited focus on PE files in existing work

[Table 1](https://arxiv.org/html/2504.21520v1#S2.T1 "In 2. Related Work ‣ Padding Matters – Exploring Function Detection in PE Files") summarizes the related work, including details such as the number of samples and functions used for evaluation, where available. These figures are presented separately for ELF and PE binaries. The table reveals that only 6 out of 13 studies evaluated PE samples. Comparing the number of samples and functions between ELF and PE in these six cases highlights a significant underrepresentation of PE binaries in the existing literature. Given the importance of function detection in PE samples, particularly in the context of malware analysis ([AVInstitute,](https://arxiv.org/html/2504.21520v1#bib.bib14) ), it becomes evident that a new evaluation focusing on PE binaries with a larger set of functions is necessary.

3\. Background on Function Detection
------------------------------------

![Refer to caption](extracted/6399389/urausy_ida_cropped.png)

(a) IDA Pro. blue: code in functions, brown: instructions outside of functions, grey: data, amber: unexplored.

![Refer to caption](extracted/6399389/urausy_ghidra_cropped.png)

(b) Ghidra. red: undefined data, green: data, purple: code in functions.

Figure 1. Comparison of code, data, and unexplored areas in memory-mapped views of a Urausy malware sample.

\\Description

\[\]

Function detection in compiled code is not straightforward. Different approaches to function detection are likely to yield varying sets of recognized functions stemming from the diverse methodologies employed. The following example highlights the significant differences in the detection of functions in a malware analysis context. [Figure 1](https://arxiv.org/html/2504.21520v1#S3.F1 "Figure 1 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files") shows two memory mapped representations of a Urausy malware sample222SHA256 hash value of \\seqsplit8f4296a0990ec245997bd2bb75edb512aae4e544b7d0c36e945bf19241fda426, produced by IDA Pro ([idapro,](https://arxiv.org/html/2504.21520v1#bib.bib23) ) and Ghidra ([ghidra,](https://arxiv.org/html/2504.21520v1#bib.bib1) ), two popular reverse engineering tools. The colors represent the types of data or code when mapped in memory. The tools differ significantly regarding the detected functions. [1(a)](https://arxiv.org/html/2504.21520v1#S3.F1.sf1 "Figure 1(a) ‣ Figure 1 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files") shows the analysis results of IDA Pro where blue-colored areas represent detected functions, brown-colored areas represent instructions that do not belong to functions, gray-colored areas represent data, and amber-colored areas represent unexplored areas that could not be further specified by IDA. In contrast, [1(b)](https://arxiv.org/html/2504.21520v1#S3.F1.sf2 "Figure 1(b) ‣ Figure 1 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files") shows the analysis results of Ghidra where purple-colored areas represent detected functions, green-colored areas represent data, and red-colored areas represent undefined data. The figures show that the tools differ significantly in the detected functions in this sample. Manual analysis of this sample reveals that the instructions that IDA classified as not belonging to functions actually belong to functions. Similarly, Ghidra misclassified such code as undefined data. In practice, an analyst would need to inspect the code and manually define functions that were missed during function start detection, a labor-intensive task. The example shows that the function detection problem is far from being solved and that an evaluation of the existing tools is appropriate and needed.

Following most related work, we refer to function detection as finding bytes in compiled binary code that belong to the same function in the source code and for which no symbol information is given. There are other terms that refer to the same problem, e.g. function boundary detection, function boundary identification, function identification, and function recognition ([nucleus,](https://arxiv.org/html/2504.21520v1#bib.bib5) ; [byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ; [Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ). We will use the term function _detection_ to avoid confusion with library function recognition ([binshape,](https://arxiv.org/html/2504.21520v1#bib.bib26) ; [library\_function\_identification,](https://arxiv.org/html/2504.21520v1#bib.bib21) ). This different problem may occasionally also be referred to as function identification and describes recovering the semantic meaning of a function given its binary code, which is out of the scope of this paper.

Furthermore, we distinguish between i) function start detection, which only considers the _start_ of functions, and ii) function boundary detection, which typically detects function _start_ and _end_ addresses, and iii) code ranges covering intervals of function code, most relevant for non-continuous functions.

Unless stated otherwise, we focus on function _start_ detection for the remainder of this work because it applies to all related work and thus allows us to include the most tools in our evaluation. Furthermore, it can be modeled as a binary classification problem, enabling the use of well-known and considered evaluation metrics.

To evaluate function start classifiers, we use the _precision_, _recall_, and _F1\-score_ as metrics. To illustrate, [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files") depicts a schematic, fictional binary of size 24 bytes, alongside a hypothetical classification of function starts. Here, the ground truth marks the bytes at offsets 6 and 10 as valid function starts (e.g., obtained via debugging symbols). In contrast, the hypothetical classifier considers the bytes at offsets 4 and 10 to be function starts. True positives (TP) refer to bytes correctly identified as function starts, matching the ground truth, e.g., the byte at offset 10 in [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files"). False positives (FP) are bytes incorrectly classified as function starts, as they do not correspond to function starts in the ground truth (e.g., byte 4 in [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files")). False negatives (FN) are bytes that are not classified as function starts but are function starts according to the ground truth (e.g., all grey-shaded bytes in [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files")).

Note that in [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files"), only two out of 24 bytes represent function starts. This highlights a common characteristic: the number of function starts rarely exceeds a small fraction of the total number of bytes in the file. Since a binary consists of much more than function starts, and each function start is represented by only a single byte, this imbalance is likely prevalent in most datasets. Such imbalance must be accounted for during training (e.g., by initializing the biases accordingly) and evaluation (e.g., by avoiding accuracy as a metric).

As previously described, most bytes in our context will not represent a function start. Given this imbalance, we avoid accuracy as a metric because it factors in true negatives in the computation. The example in [Figure 2](https://arxiv.org/html/2504.21520v1#S3.F2 "Figure 2 ‣ 3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files") would yield an accuracy of 92%, and an F1\-score of 50%. Similarly, while practically useless, a naive classifier that predicts _every_ byte as a non-function start would still result in a (comparatively) high number of true negatives and, consequently, high accuracy. Arp et al. ([dos\_and\_donts\_machine\_learning,](https://arxiv.org/html/2504.21520v1#bib.bib6) ) refer to such a pitfall as inappropriate performance measures.

![Refer to caption](x1.png)

Figure 2. Schematic of function start detection

\\Description

\[\]

4\. Empirical Validation
------------------------

Our work aims to assess all function start detection tools introduced within the past decade that can operate on PE files. To achieve this, we describe the BAP/ByteWeight dataset as it is typically used to train models, and develop models for two learning-based approaches. We reproduce the work of Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ), as their original implementation is not publicly available, and existing reimplementations by other researchers ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ; [lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) do not include trained models. Therefore, we provide a stable, well-documented implementation of Shin’s RNN-based classifier and publish the x86 and x64 Windows PE training data along with the trained models.

Additionally, we discovered a discrepancy in the implementation of XDA ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ), leading to the reproduced results deviating from those reported in the original paper. To rectify this inconsistency, we introduce a novel encoding for the training data, leading to results that more closely align with those presented in the paper.

### 4.1. BAP/ByteWeight Dataset

To reproduce the original implementations of Shin’s RNN and XDA, we use the same dataset for training and evaluation, as used in the original studies. The dataset was initially compiled as part of BAP/ByteWeight ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ). We only use a subset of the dataset, i.e., PE binaries targeting Microsoft Windows and their corresponding ground truth files containing the function starts as virtual addresses (VA). In the following, we refer to it as BAP dataset. This dataset spans a total of 136 hash-unique PE samples, built using Microsoft Visual Studio versions 2010 to 2013. It consists of 68 x86 and 68 x64 PE samples compiled from 17 programs (7z, vim, various PuTTy tools, hidapi, libsodium, sfxsetup, smtpsend), using four optimization levels (Od, O1, Ox, O2). In one case (filename \\seqsplitmsvs\_whatever\_32\_Od\_SfxSetup), the ground truth in the dataset did not match the provided sample as it contains a function VA where no section is mapped in memory. This could potentially be due to a misunderstanding or an error made by the original authors. To avoid label inaccuracy ([dos\_and\_donts\_machine\_learning,](https://arxiv.org/html/2504.21520v1#bib.bib6) ), we exclude this specific x86 sample from our dataset, resulting in a total of 135 samples (67 x86 and 68 x64).

Koo et al. ([Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ) highlight a pitfall of the BAP/ByteWeight dataset, particularly in the ELF subset, that we do not use. When normalizing instructions by blinding immediates and call and jump targets, only 17.6K (12.1%) out of the whole 146K functions of the ELF subset form unique normalized functions ([Koo\_Park\_Kim\_2021,](https://arxiv.org/html/2504.21520v1#bib.bib17) ). In other words, without normalization, overfitting becomes likely, especially when a significant number of normalized functions is present in both the training and the validation set. We decided against normalization in the training part of our pipeline to keep our results comparable with prior work. However, we consider uniqueness and normalization in our new FuncPEval dataset introduced in [Section 5](https://arxiv.org/html/2504.21520v1#S5 "5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files").

### 4.2. Implementation of the RNN-based Classifier

Currently, no public implementation of Shin’s RNN includes trained models for the classification of PE files. To incorporate the RNN into our evaluation in [Section 5](https://arxiv.org/html/2504.21520v1#S5 "5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files"), we reproduce the original implementation and train models for x86 and x64 PE. Based on previous work by Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ) and using the LEMNA reimplementation by Guo et al. ([lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) as basis, we implement the RNN-based classifier in Python using Keras 2.8.0 and TensorFlow 2.8.0 as backend. Considering the function start detection as a binary classification problem, we also implement a second variant with a slightly modified pipeline, namely one output neuron. In contrast, the LEMNA reimplementation uses two output neurons ([3(a)](https://arxiv.org/html/2504.21520v1#S4.F3.sf1 "Figure 3(a) ‣ Figure 3 ‣ 4.2. Implementation of the RNN-based Classifier ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files")). Our modification allows us to adapt the trigger threshold and thereby improve the classification results as shown in [Table 2](https://arxiv.org/html/2504.21520v1#S4.T2 "In 4.2.1. Training and Validation ‣ 4.2. Implementation of the RNN-based Classifier ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files"). The LEMNA-based RNN pipeline and our modified pipeline are shown in [Figure 3](https://arxiv.org/html/2504.21520v1#S4.F3 "Figure 3 ‣ 4.2. Implementation of the RNN-based Classifier ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files").

![Refer to caption](x2.png)

(a) LEMNA-based RNN pipeline with two output neurons

![Refer to caption](x3.png)

(b) Our modified RNN pipeline with one output neuron

Figure 3. Comparison of the original and the modified RNN pipelines

\\Description

\[\]

Shin’s RNN architecture specifies that a sample must be divided into 1000-byte slices. If the last slice is shorter than 1000 bytes, the slice will be padded with zeros. Subsequently, the slice is fed into the RNN, where i) the LEMNA-based RNN outputs two class probabilities for each byte, and ii) our modified RNN yields a prediction score for each byte. Thus, we can predict for each input byte if it is the start of a function in the binary. Finally, a mathematical function assigns a class label to the byte. Guo et al. ([lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) use a⁢r⁢g⁢m⁢a⁢x𝑎𝑟𝑔𝑚𝑎𝑥argmaxitalic\_a italic\_r italic\_g italic\_m italic\_a italic\_x, which determines the class label based on the maximum of the two class probabilities. Our variant uses a heuristic thresholding function:

(1)

CLabel⁢(PScore)\={0if ⁢PScore≤t1if ⁢PScore\>tsubscript𝐶Labelsubscript𝑃Scorecases0if subscript𝑃Score𝑡1if subscript𝑃Score𝑡C\_{{\\text{Label}}}(P\_{{\\text{Score}}})={\\begin{cases}0&{\\text{if }}P\_{{\\text{% Score}}}\\leq t\\\\ 1&{\\text{if }}P\_{{\\text{Score}}}>t\\end{cases}}italic\_C start\_POSTSUBSCRIPT Label end\_POSTSUBSCRIPT ( italic\_P start\_POSTSUBSCRIPT Score end\_POSTSUBSCRIPT ) = { start\_ROW start\_CELL 0 end\_CELL start\_CELL if italic\_P start\_POSTSUBSCRIPT Score end\_POSTSUBSCRIPT ≤ italic\_t end\_CELL end\_ROW start\_ROW start\_CELL 1 end\_CELL start\_CELL if italic\_P start\_POSTSUBSCRIPT Score end\_POSTSUBSCRIPT > italic\_t end\_CELL end\_ROW

If the prediction score PS⁢c⁢o⁢r⁢esubscript𝑃𝑆𝑐𝑜𝑟𝑒P\_{Score}italic\_P start\_POSTSUBSCRIPT italic\_S italic\_c italic\_o italic\_r italic\_e end\_POSTSUBSCRIPT exceeds the threshold t𝑡titalic\_t, the class label CL⁢a⁢b⁢e⁢lsubscript𝐶𝐿𝑎𝑏𝑒𝑙C\_{Label}italic\_C start\_POSTSUBSCRIPT italic\_L italic\_a italic\_b italic\_e italic\_l end\_POSTSUBSCRIPT for the byte will be set to 1111 (i.e., function start), otherwise 00 (i.e., not a function start). To determine the optimal threshold, the training dataset was evaluated with threshold values from 00 to 1111 at intervals of 0.010.010.010.01. Subsequently, the threshold (0.380.380.380.38) with the best F1subscript𝐹1F\_{1}italic\_F start\_POSTSUBSCRIPT 1 end\_POSTSUBSCRIPT\-score was selected and used for the remaining experiments.

Note that when considering function starts on a per-byte level, every dataset containing real-world binaries is imbalanced as shown in [Section 3](https://arxiv.org/html/2504.21520v1#S3 "3. Background on Function Detection ‣ Padding Matters – Exploring Function Detection in PE Files"), because bytes that do not represent a function start appear more often than those that do represent a function start. We randomly initialize the weights of the RNN and take the imbalance into account by changing the bias of the output layer. The initial bias b0subscript𝑏0b\_{0}italic\_b start\_POSTSUBSCRIPT 0 end\_POSTSUBSCRIPT is computed as follows:

(2)

b0\=l⁢o⁢ge⁢(p⁢o⁢sn⁢e⁢g)subscript𝑏0𝑙𝑜subscript𝑔𝑒𝑝𝑜𝑠𝑛𝑒𝑔b\_{0}=log\_{e}\\left(\\frac{pos}{neg}\\right)italic\_b start\_POSTSUBSCRIPT 0 end\_POSTSUBSCRIPT = italic\_l italic\_o italic\_g start\_POSTSUBSCRIPT italic\_e end\_POSTSUBSCRIPT ( divide start\_ARG italic\_p italic\_o italic\_s end\_ARG start\_ARG italic\_n italic\_e italic\_g end\_ARG )

where p⁢o⁢s𝑝𝑜𝑠positalic\_p italic\_o italic\_s is the number of bytes representing the start of a function and n⁢e⁢g𝑛𝑒𝑔negitalic\_n italic\_e italic\_g is the number of bytes that are _not_ the start of a function. Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) ) use the adaptive learning rate optimizer RMSprop ([hinton,](https://arxiv.org/html/2504.21520v1#bib.bib12) ) for training, while we use Adam ([adam,](https://arxiv.org/html/2504.21520v1#bib.bib16) ), the same used in LEMNA.

#### 4.2.1. Training and Validation

We train and validate separately for x86 and x64 PE samples. Given the BAP dataset of 67 x86 PE samples, we perform 10-fold cross-validation as follows: Split the dataset into ten (nearly) equally-sized disjoint subsets where each subset spans ca. 10% of the samples.

In each fold, executable sections from 9 of the 10 subsets (ca. 90% of the samples) are used for training, and executable sections from the remaining subset (ca. 10% of the samples) are used for validation. Shin et al. use a batch size of 32, while Guo et al. ([lemna,](https://arxiv.org/html/2504.21520v1#bib.bib10) ) used 100. We use a batch size of 1,000 for the given dataset to increase training speed. While Shin et al. trained for two hours, we followed LEMNA and trained the RNN for 150 epochs for each fold (taking approximately 55 minutes per fold). We run our experiments on a server with two 2.20 GHz Intel Xeon Silver 4114 CPUs à 20 threads and 128 GB of RAM.

Table 2. Results from 10-fold cross-validation of our RNN models compared to previous work by Shin et al., using the BAP PE dataset. Shin et al. report higher F1\-scores, but their implementation and trained models are unavailable for inspection.

PE x86

PE x64

Method

Precision

Recall

F1\-score

Precision

Recall

F1\-score

Shin et al. ([rnn,](https://arxiv.org/html/2504.21520v1#bib.bib25) )

99.01%

98.46%

98.74%

99.52%

99.09%

99.31%

two output neurons RNN

97.41%

92.42%

94.83%

98.66%

96.43%

97.53%

one output neuron RNN

96.96%

95.65%

96.29%

98.62%

98.29%

98.45%

#### 4.2.2. Evaluation

Table [2](https://arxiv.org/html/2504.21520v1#S4.T2 "Table 2 ‣ 4.2.1. Training and Validation ‣ 4.2. Implementation of the RNN-based Classifier ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") shows the precision, recall and F1\-score, on average. Although they do not exactly match the values from the previous work by Shin et al., we consider the results similar, indicating that our implementation provides a suitable RNN-based function start classifier. Note that our modified variant, referred to as one output neuron RNN, achieves higher F1\-score values for both x86 and x64, compared to the two output neurons RNN. As a result, we use the one output neuron RNN in subsequent experiments.

In the original paper, Shin et al. yield higher F1\-scores compared to our models. However, we lack a precise explanation, as their implementation and trained models are inaccessible. This may be an artifact of different folds or implementation details. For the experiments in [Section 5](https://arxiv.org/html/2504.21520v1#S5 "5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files"), we train models for PE x86 and x64 using the whole BAP dataset. We publish our documented implementation, training data, and models.

### 4.3. Improving XDA

In preparation for the tool comparison in [Section 5](https://arxiv.org/html/2504.21520v1#S5 "5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files"), we noticed discrepancies in the encoding of function starts and ends in the published XDA tooling. Consequently, we reproduce the results to verify their correctness. We utilized the model and code published by the authors for 64-bit PE files and applied it to the x64 part of the BAP dataset (BAP-64). In the original evaluation, 90% of the BAP dataset was used for evaluation because 10% was used to train XDA. Since we do not know which samples were used for training and which for evaluation, we use the entire dataset for evaluation. This should only positively impact the results for XDA, as 10% of the dataset was already seen during training. First, the function starts and ends are predicted using the provided model. Subsequently, we combine these starts and ends into function boundary pairs using the published algorithm333[https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval\_pair\_bound.py#L6](https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval_pair_bound.py#L6), Commit: c3cce2f. Following this, we utilized the F1\-score calculation provided by the authors444[https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval\_pair\_bound.py#L39](https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval_pair_bound.py#L39), Commit: c3cce2f to closely align with the original evaluation. The computed F1\-score is shown in [Table 3](https://arxiv.org/html/2504.21520v1#S4.T3 "In 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") in the column named _our experiment_, and the F1\-score from the original work in the column named _reported_.

We also include Nucleus, Ghidra, and IDA in the evaluation to provide a better comparison with the original evaluation ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ). We chose not to include the bi-RNN, as the XDA authors did not provide trained models for its implementation, making a fair comparison impossible.

Table 3. Improving XDA on the BAP-64 PE dataset. The column _our experiment_ shows the results in our reproduction, the column _reported_ shows the results as presented in ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ), and _adapted GT_ shows the results evaluated against the adapted ground truth, which was potentially used in ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) )

F1\-score (PE x64)

Tool

our experiment

reported ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) )

adapted GT

IDA

91.13%

90.5%

78.66%

Ghidra

78.69%

80.6%

71.22%

Nucleus

79.80%

70%

67.55%

XDA reproduced

82.68%

99.4%

97.81%

XDA new encoding

93.66%

\-

\-

The results in Table [3](https://arxiv.org/html/2504.21520v1#S4.T3 "Table 3 ‣ 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") indicate that the outcomes of our evaluation for IDA and Ghidra are similar to those in the original evaluation. The slight deviation could be attributed to the use of a slightly different dataset (100% of BAP-64 in our evaluation instead of 90%). However, there is a significant discrepancy between our evaluation and the original evaluation in the results for XDA (`~`17 percent points in F1\-score) and Nucleus (`~`10 percent points in F1\-score). To investigate the cause of this discrepancy, we conducted a detailed analysis of XDA’s detection mechanism.

#### 4.3.1. XDA Label Encoding

![Refer to caption](x4.png)

Figure 4. Labeling of Functions in XDA. For two adjacent functions, XDA would need to assign two labels for one byte. That is impossible, and a new encoding is required.

\\Description

\[\]

Upon closer examination of the functions detected by XDA, we noticed that XDA fails to correctly identify functions when they are immediately adjacent to each other, i.e., when one function ends and another begins directly afterward without any bytes in between. This issue stems from the labeling of functions in the BAP dataset. In the BAP dataset, each function is labeled with a start and an end. The start is inclusive, marking the first byte of the function, while the end is exclusive, indicating the first byte that does not belong to the function. When one function directly follows another without intervening bytes, the end of the first function is the same as the start of the second function in the BAP notation. XDA assigns exactly one label per byte, _S_ for a function start, _E_ for a function end, and _N_ for neither. In the scenario of two adjacent functions, XDA either correctly identifies the end of the first function _or_ the start of the second function. Therefore, XDA cannot identify both functions in such cases. Figure [4](https://arxiv.org/html/2504.21520v1#S4.F4 "Figure 4 ‣ 4.3.1. XDA Label Encoding ‣ 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") illustrates this issue. Function B (5,8) directly follows function A (2,5). XDA would need to assign both, the label _S_ and the label _E_, to byte 5 to identify both functions correctly. If XDA classifies byte 5 as the end of a function, there are two function ends, i.e., byte 5 and byte 8, without a function start in between, and XDAs pairing code yields the function boundary pair (2,8), effectively representing a single function starting at byte 2 and ending at byte 8. This would result in one false positive and two false negatives in the evaluation. Note that we do not consider this a shortcoming of the XDA classifier but rather a labeling issue.

In the published artifacts, this issue also affects the training data for XDA. Each byte is assigned exactly one label, and the label _E_ is assigned in case of a label conflict. Consequently, XDA never encounters a function start that immediately follows the end of another function during training. Additionally, the published code555[https://github.com/CUMLSec/XDA/blob/5315918317eda39bf5de8ca56935baabfc30aa7e/scripts/play/eval\_pair\_bound.py#L144](https://github.com/CUMLSec/XDA/blob/5315918317eda39bf5de8ca56935baabfc30aa7e/scripts/play/eval_pair_bound.py#L144), Commit: c3cce2f suggests that the ground truth data for the evaluation was encoded similarly, causing the ground truth in XDA to deviate from the BAP ground truth. We attempted to reconstruct the ground truth as used in the original work by i) dividing the set of functions in the BAP ground truth into pairs of function starts and ends, ii) extracting all function starts in the set of function starts that also appeared in the set of function ends, and iii) forming new function boundary pairs by using the published algorithm666[https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval\_pair\_bound.py#L6](https://github.com/CUMLSec/XDA/blob/main/scripts/play/eval_pair_bound.py#L6), Commit: c3cce2f.

With the adapted ground truth, the evaluation results for XDA and Nucleus are much closer to those in the original evaluation, as shown in [Table 3](https://arxiv.org/html/2504.21520v1#S4.T3 "In 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") in the rightmost column named adapted GT. The minor discrepancies could be attributed to the slightly different datasets used (100% of BAP-64 in our evaluation instead of 90%). However, the results for IDA and Ghidra deviate significantly from the original evaluation compared to the BAP ground truth. Although speculative, one possible explanation is that different tools might have been evaluated differently, using the adapted ground truth for XDA and Nucleus while using the original BAP ground truth for IDA and Ghidra.

#### 4.3.2. Retraining XDA

We aim to address the labeling inaccuracy of the training data encoding by slightly modifying the training data and retraining XDA. In the new encoding, we treat the end of a function as inclusive, just like the start, marking it as the last byte that still belongs to the function (_new encoding_ in [Figure 4](https://arxiv.org/html/2504.21520v1#S4.F4 "In 4.3.1. XDA Label Encoding ‣ 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files")). During evaluation, we account for this new encoding method by increasing the value of each function end by one. This adjustment is also applied when evaluating Ghidra and Nucleus, as both also consider the end of the function to be inclusive. With the help of the new encoding, only labels for one-byte-sized functions would result in a label conflict. In these cases, it is impossible to assign a single correct label, as the first and only byte of the function represents both the start and the end. To address this, a new label would need to be introduced to mark a function’s start _and_ end. Since single-byte-sized functions are extremely uncommon, only occurring in about 0.1% of the functions in the BAP-64 dataset, we decided not to implement this change.

We use a randomly selected 10% of the samples from the BAP-64 dataset to retrain (fine-tuning part only) XDA and evaluate the entire BAP-64 dataset. This should not negatively impact the results of XDA, as 10% of the evaluation dataset was already seen during training.

This newly trained version of XDA achieves significantly better results than the original version, as shown in the last row of Table [3](https://arxiv.org/html/2504.21520v1#S4.T3 "Table 3 ‣ 4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files"), with an increase from 82.68% to 93.66% in the F1\-score. The F1\-score of the newly trained version is still more than 5 percent points lower than the value reported in the original paper ([xda,](https://arxiv.org/html/2504.21520v1#bib.bib19) ). However, in our evaluation, the retrained version of XDA again emerges as the tool with the best results compared to IDA, Ghidra, and Nucleus. This supports our assumption that the XDA approach fundamentally works well, although it does not quite meet the claims of the original paper. To investigate this further, the evaluation could be repeated on other datasets, i.e., SPEC2006, SPEC2017, and the x86 versions. However, the pre-trained models used in the original evaluation would need to be made available for a fair comparison. Our experience underlines the importance of reproducible artifact and dataset publication in our research community to better explain such differences.

{mdframed}

\[style=insightstyle\] Lessons learned. This section shows how Shin’s RNN can benefit from using a one-output-neuron pipeline yielding F1\-scores of 96.29% for PE x86, and 98.45% for PE x64. Similarly, XDA significantly benefits from a different labeling scheme, improving its F1\-score by nearly 11 percent points for PE x64. Adjusting the labeling to account for adjacent functions underscores the critical role of thoroughly understanding and modeling the problem domain.

5\. Comparing Function Start Detection Tools
--------------------------------------------

As demonstrated in [Section 2](https://arxiv.org/html/2504.21520v1#S2 "2. Related Work ‣ Padding Matters – Exploring Function Detection in PE Files"), prior research primarily focused on evaluating function start detection tools using ELF binaries. In contrast, our objective is to evaluate function start detection tools developed over the past decade exclusively on PE binaries. We introduce and release a new Windows PE dataset called FuncPEval to facilitate this. This new PE evaluation dataset spans 549k functions (233k normalized functions) for x86 and 543k functions (316k normalized functions) for x64, more than twice compared to previously available PE datasets. As a result, our dataset allows comparing tool performance using F1\-score and execution speed. Additionally, we investigate the impact of padding bytes between functions on function start detection.

### 5.1. FuncPEval

Table 4. Properties of the training and the evaluation datasets, showing the number of functions and prologues. Normalization includes blinding immediates as well as call and jump targets.

Functions

Prologues (.pdata)

Padding

Dataset

PE sample(s)

Arch

RVAs

unique

norm.

present

unique

norm.

instances

BAP PE

68 samples

x64

94,548

65,733 (70%)

18,169 (19%)

74,057

10,979

1,775

84,069

FuncPEval

Chromium v109

x86

548,534

541,707 (99%)

232,781 (42%)

377,769

FuncPEval

Chromium v109

x64

542,902

536,182 (99%)

315,745 (58%)

470,317

7,488

1,982

390,063

FuncPEval

Conti v3

x86

722

721 (99%)

524 (73%)

310

FuncPEval

Conti v3

x64

662

659 (99%)

450 (68%)

389

179

122

548

To address the limitation of prior research focusing predominantly on ELF binaries, we introduce a new dataset, _FuncPEval_, which exclusively comprises PE binaries. The dataset contains PE binaries targeting Microsoft Windows, stripped off their debugging information. As benign software, the core library chrome.dll of Chromium version 109 is chosen, both as x86 and x64 PE. These samples were compiled and linked by Google using LLVM clang 14.10.25019, using various per-module optimization levels, including Ox, Os, Oy, O1, Ot, and O2. For x64, we use Chromium snapshot 1069922777[http://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Win\_x64/1069922/](http://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Win_x64/1069922/), chrome.dll has a SHA256 hash value of 55f05fe24ebdf8eb263f75e88c8a71a42fb6240b59340a9abf9671ffe79a4f4a, and for x86, we use Chromium snapshot 1069956888[http://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Win/1069956/](http://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Win/1069956/), chrome.dll has a SHA256 hash value of 1ce8b9551709581688a8199a0e0fcb48cfcac7fadf3671622ea8e66fbe39151f, both released 10 Nov 2022. We choose to include Chromium for two main reasons: First, given its wide adoption, relevance in practice, and diverse code base, Chromium is a suitable target for binary code analysis. Second, Chromium for Windows has not been used in previous evaluations, rendering it unlikely that existing tools have been particularly optimized for our dataset.

We extract ground truth on the function start addresses from the associated PDB files using Microsoft’s DIA API and consider functions that are designated as symbol type Function and are listed under the respective compiled modules (\\seqsplit\*.obj). For each module, relative virtual function addresses (RVA) and other symbols (FuncDebugStart, FuncDebugEnd, etc.) are specified, which can be found in the PE file after linking the respective modules. We ignore all other symbol types, e.g. Thunk, because they do not provide any relevant information in the context of the given problem.

In addition to Chromium, we evaluate against the code of the Conti ransomware, a prevalent malicious software made publicly available by a leak in early 2022 ([vxunderground,](https://arxiv.org/html/2504.21520v1#bib.bib27) ). We compiled and linked Conti version 3 using Visual Studio 2022 (version 14.34.31933) for both x86 and x64 and generated PDB files to obtain the ground truth. In the following, we consider the crypter (cryptor.exe), which is the component that encrypts files on the victim machine. To the best of our knowledge, no prior work has evaluated function start detection using malware in combination with reliable ground truth. While it would be beneficial to include a broader range of samples and malware families, obtaining reliable ground truth is challenging, as it necessitates access to either a compilable version of the source code or corresponding debugging symbols.

To highlight the diversity in our evaluation dataset, we analyzed the binary code as shown in Table [4](https://arxiv.org/html/2504.21520v1#S5.T4 "Table 4 ‣ 5.1. FuncPEval ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files"). For example, Chromium x64 exhibits 542,902 distinct RVAs in its chrome.dll that denote the start of a function. However, these represent 536,182 byte-unique functions, i.e. some functions are byte-equal multiples. ByteWeight ([byteweight,](https://arxiv.org/html/2504.21520v1#bib.bib7) ) proposed normalizing instructions by removing immediates and call/jump targets. When normalized, the Chromium x64 sample contains 315,745 distinct normalized functions (roughly 58% of all functions). This shows that Chromium exhibits enough diversity for our evaluation. For reference, the overlap between Chromium x64 and BAP-64 is minimal, consisting of only 95 byte-unique functions (out of 601,820), corresponding to 176 normalized functions.

In addition, we analyzed the function prologues for the x64 samples. Assuming that function start detection tools may consider the bytes at the beginning of a function, which often represent the function prologue, particularly important, their diversity in the dataset becomes particularly noteworthy. Hence, the second-rightmost columns in Table [4](https://arxiv.org/html/2504.21520v1#S5.T4 "Table 4 ‣ 5.1. FuncPEval ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files") describe the diversity of prologues. Information about the prologue is derived from the .pdata section in x64 PE files, and only available for functions that use exception handling 999See [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section). For Chromium x64, a non-zero-sized prologue was present in 470,317 functions, representing 7,488 unique prologue byte sequences. When normalizing the prologue instructions, 1,982 distinct sequences remain. While this number is significantly lower than the number of functions that exhibit a prologue, it is expected, as the diversity of prologues is certainly limited in general. Nevertheless, the number of distinct normalized prologues provides a measure of the diversity of function prologues. Since the tools might also consider the bytes before the function starts in their detection, we have included the number of functions with at least one padding byte before the function start in the rightmost column of Table [4](https://arxiv.org/html/2504.21520v1#S5.T4 "Table 4 ‣ 5.1. FuncPEval ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files").

For comparison, the BAP x64 PE dataset contains 65,733 byte-unique functions, i.e., unique function byte sequences. With normalization, only 18,169 normalized functions (ca. 28%) remain. Similarly, out of 10,979 byte-unique prologues based on .pdata section, 1,775 normalized prologues (ca. 16%) remain. Both the absolute numbers and the relative numbers, i.e., the number of normalized functions over the total number of functions, demonstrate fewer duplicates compared to the BAP dataset, indicating that the FuncPEval dataset contains more diversity, which is a desirable property for an evaluation dataset.

### 5.2. Evaluation and Tool Comparison

To assess the performance of function start detection tools on PE files, we utilize our newly introduced comprehensive FuncPEval dataset to evaluate eight tools, measuring their performance in terms of speed and F1\-score. The research question is as follows: How do function detection tools perform when predicting function starts in PE programs with diverse code that exhibit different build toolchains? For the tool comparison, we select function start detection tools listed in [Table 1](https://arxiv.org/html/2504.21520v1#S2.T1 "In 2. Related Work ‣ Padding Matters – Exploring Function Detection in PE Files") that support PE and have been published within the past decade (2015-2025). This spans the three learning-based approaches Shin et al. RNN, XDA, and DeepDi ([DeepDi,](https://arxiv.org/html/2504.21520v1#bib.bib28) ), the three non-learning-based tools Nucleus ([nucleus\_code,](https://arxiv.org/html/2504.21520v1#bib.bib3) ), SMDA ([smda\_dis,](https://arxiv.org/html/2504.21520v1#bib.bib8) ; [smda\_github,](https://arxiv.org/html/2504.21520v1#bib.bib20) ), and rev.ng ([revng,](https://arxiv.org/html/2504.21520v1#bib.bib9) ), as well as two popular industry tools IDA Pro 7.7 ([idapro,](https://arxiv.org/html/2504.21520v1#bib.bib23) ) and Ghidra 10.0.4 ([ghidra,](https://arxiv.org/html/2504.21520v1#bib.bib1) ). For our one output neuron RNN, we train two models separately for x86 and x64, using the full BAP dataset, described in Section [4.1](https://arxiv.org/html/2504.21520v1#S4.SS1 "4.1. BAP/ByteWeight Dataset ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files"), spanning PE samples with ground truth, compiled and linked with MS Visual Studio versions 2010 to 2013 and using the optimization levels Od, O1, Ox, and O2. Similarly, we use the XDA models described in Section [4.3](https://arxiv.org/html/2504.21520v1#S4.SS3 "4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files"), trained on 10% of the BAP-64 dataset. For DeepDi, we use the provided model, trained on a mixture of PE files from LLVM, SPEC CPU2006, and SPEC CPU2017. Note that in contrast to the training datasets used by the learning-based tools, the evaluation dataset spans PE samples built with newer (MSVS 2022) or different (LLVM clang) compilers. This approach allows us to work towards evaluating the generalizability of the learning-based methods.

![Refer to caption](x5.png)

Figure 5. Precision, recall, and F1\-score when predicting function starts in Chromium and Conti samples. Each cell is shaded in red, with the intensity of the red color increasing as the value deviates further from 100%. _INT3-Padding_ in tool names indicates training on samples with INT3 instruction as padding between functions, while _RND-Padding_ indicates training on samples with random byte values as padding. _RND-padding_ in sample names denotes the replacement of compiler-generated padding with random byte values.

\\Description

\[\]

We evaluated the one output neuron RNN, XDA (in the original and our modified version), DeepDi, SMDA, IDA Pro, Ghidra, Nucleus, and rev.ng on the FuncPEval dataset, specifically Chromium and Conti for both x86 and x64. The experiments for the RNN, SMDA, IDA, Ghidra, Nucleus, and rev.ng ran on a server with two 2.20 GHz Intel Xeon Silver 4114 CPUs à 20 threads and 128 GB of RAM. The experiments for XDA and DeepDi ran on a server with two 2.9 GHz AMD EPYC 7542 CPUs à 64 threads, 256 GB of RAM, and one NVIDIA Quadro RTX 8000.

[Figure 5](https://arxiv.org/html/2504.21520v1#S5.F5 "Figure 5 ‣ 5.2. Evaluation and Tool Comparison ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files") shows the processing time for each tool and sample in seconds, averaged over both the x86 and x64 duration. For Chromium, rev.ng did not finish after 7 days, so we could not obtain results. For Chromium x64, DeepDi is the fastest, completing in seconds, followed by the RNN and Nucleus, both taking minutes. XDA, Ghidra, and IDA ran for hours while SMDA finished after 35 hours.

Concerning F1\-scores on the x64 Chromium sample, IDA (98.44%) performs best, followed by DeepDi (97%), SMDA (95.54%), and Ghidra (92.48%). Nucleus (88.52%), XDA (86.98%), and the RNN (84.66%) score below 90%. Even though the F1\-scores of the RNN and XDA are much lower than in Section [4](https://arxiv.org/html/2504.21520v1#S4 "4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files"), both still detect a significant number of functions in the evaluation dataset, given the difference between training and evaluation datasets. Overall, the RNN and XDA exhibit higher precision than recall. This reflects that most predicted function starts are indeed function starts according to the ground truth, but a significant number of functions is missed (in the worst case, up to 33% for the RNN and 20% for XDA). At first, this might indicate that the tools reliably detect function starts they encountered during training while failing to recognize a significant portion of function starts that were not part of the training data. However, the results of [Section 5.3](https://arxiv.org/html/2504.21520v1#S5.SS3 "5.3. Randomizing the Padding between Functions ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files") raise doubts whether these tools generalize over code properties observed in function starts.

{mdframed}

\[style=insightstyle\] Lessons learned. IDA, DeepDi, SMDA, and Ghidra achieve the best results in function start detection for PE files, with F1\-scores exceeding 90%. While Nucleus, XDA, and the RNN produce slightly lower results, with F1-scores above 80%, they remain valuable tools, particularly due to their relatively fast execution speeds. If precise function detection is the primary focus, IDA is the most suitable tool. However, if execution speed is a critical factor, DeepDi is the preferred choice, as it delivers the second-best F1\-scores while being by far the fastest.

### 5.3. Randomizing the Padding between Functions

To gain a better understanding of which features are predominantly utilized by the ML-based tools, we analyze the overlap between the detected functions and the training dataset. The RNN detects a total of 439,363 functions in Chromium x64, with 415,810 of them (95%) being true positives. For 353,995 of those functions, we have information about the prologue from the .pdata section. Only 138,201 out of those 353,955 functions (39%) have a normalized prologue that also occurs in the training dataset. Therefore, the RNN detects function starts for which the normalized prologue was not seen during training. We observe the same for XDA. Since we do not have training data for DeepDi, we cannot measure the overlap of normalized function prologues.

These values indicate that the RNN and XDA may not primarily rely on function prologues when detecting function starts. Following Compiler Coding Rule 12 of Intel’s Architecture Optimization Reference Manual, compilers align the first instruction of each function at multiples of 16 bytes ([guide\_intel\_opt,](https://arxiv.org/html/2504.21520v1#bib.bib13) ) and pad the area between the end of the preceding function and the beginning of the next with specific bytes. Typically, the padding is filled with opcode 0xcc, which reflects the mnemonic INT 3, or opcode 0x90, which is a single-byte NOP instruction. Such padding forms a characteristic pattern before a function start. Therefore, we suspect that the RNN and XDA learn that a series of padding bytes is directly followed by a function start, a pitfall referred to as a spurious correlation by Arp et al. ([dos\_and\_donts\_machine\_learning,](https://arxiv.org/html/2504.21520v1#bib.bib6) ), as the padding bytes are not required for the execution of a binary and can be arbitrarily altered in value. To confirm our hypothesis, we replace the characteristic padding bytes with random byte values in our evaluation dataset and rerun the previous experiment.

#### 5.3.1. Introducing Random Padding in the FuncPEval Dataset

[⬇](data:text/plain;base64,IyBpdGVyYXRlIG92ZXIgdGhlIDIwIGJ5dGVzIHByZWNlZGluZyB0aGUgZnVuY3Rpb24KZm9yIGkgaW4gcmFuZ2UoMSwgMjApOgogICAgY3VycmVudF9ieXRlID0KICAgICAgICBzYW1wbGVfYnl0ZXNbY3VycmVudF9mdW5jdGlvbl9zdGFydCAtIGldCiAgICAjIG1ha2Ugc3VyZSB0aGUgY3VycmVudCBieXRlIGRvZXMgbm90IGJlbG9uZwogICAgIyB0byBhbm90aGVyIGZ1bmN0aW9uCiAgICBpZiBiZWxvbmdzX3RvX2Z1bmN0aW9uKGN1cnJlbnRfYnl0ZSk6CiAgICAgICAgYnJlYWsKICAgICMgbWFrZSBzdXJlIHRoZSBieXRlIGlzIGFjdHVhbGx5IGEgcGFkZGluZwogICAgIyBieXRlCiAgICBpZiBjdXJyZW50X2J5dGUudmFsdWUgPT0gMHhjYzoKICAgICAgICAjIHJlcGxhY2UgYnl0ZSB2YWx1ZSBieSByYW5kb20gdmFsdWUKICAgICAgICBjdXJyZW50X2J5dGUudmFsdWUgPSByYW5kb21fYnl0ZSgp)

1# iterate over the 20 bytes preceding the function

2for i in range(1, 20):

3 current\_byte \=

4 sample\_bytes\[current\_function\_start \- i\]

5 # make sure the current byte does not belong

6 # to another function

7 if belongs\_to\_function(current\_byte):

8 break

9 # make sure the byte is actually a padding

10 # byte

11 if current\_byte.value \== 0xcc:

12 # replace byte value by random value

13 current\_byte.value \= random\_byte()

Listing 1: Pseudocode of algorithm used to replace padding bytes

\\Description

\[\]

We use the FuncPEval dataset described in [Section 5.1](https://arxiv.org/html/2504.21520v1#S5.SS1 "5.1. FuncPEval ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files") and modify the samples to understand the impact of padding bytes on the evaluation. In our original dataset, we only observe padding with opcode 0xcc (mnemonic INT 3 representing a software interrupt). LABEL:lst:replace\_padding shows the algorithm used to replace the padding bytes. For each function in the samples, we i) collect up to 20 bytes before the beginning of the function, ii) consider only those bytes that do not belong to a preceding function, and iii) replace each padding byte of value 0xcc with a random arbitrary byte value. We select 20 bytes preceding the function to cover any possible padding, which can be up to 15 bytes in length, with an additional margin for tolerance. This modification does not impact the runtime behavior of the samples because the padding is not part of the control flow and is never executed. Therefore, malicious actors could arbitrarily alter the values of the padding bytes as an obfuscation to impede automated analyses. We have observed non-standard padding used by malicious actors in the wild. The wineloader101010SHA256 hash value of: \\seqsplit72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4 malware uses opcode 0xC3 as inter-function padding, which reflects the mnemonic RET. While possibly an artifact of a rare compiler or compiler configuration, or resulting from deliberate manipulation, the intentions for using non-standard padding are unclear in this specific case.

#### 5.3.2. Results

[Figure 5](https://arxiv.org/html/2504.21520v1#S5.F5 "Figure 5 ‣ 5.2. Evaluation and Tool Comparison ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files") shows that the padding significantly impacts the performance of the RNN and XDA. In the case of Chromium x86, the F1\-score dropped from 78.79% to 6.05% for the RNN. For our modified version of XDA, the F1\-score dropped from 86.98% to 11.50% for Chromium x64. The modified padding also negatively affects DeepDi, the third machine learning approach, albeit significantly less (drop from 97% to 65.71% in F1\-score for Chromium x64). We draw two conclusions: First, if a characteristic padding byte pattern is present during training, the RNN and XDA predominantly rely on such a pattern as a delimiter of functions. Second, unlike RNN and XDA, DeepDi is less affected, most likely as it operates on the granularity of machine code instructions instead of raw bytes.

Given a learning-based approach, it may be considered unfair to train on samples with unmodified padding and evaluate against randomized padding. To accommodate, we applied the padding randomization to the samples in the BAP training dataset of the RNN and trained a new model to see if the results improve. The new model (RND-Padding in [Figure 5](https://arxiv.org/html/2504.21520v1#S5.F5 "Figure 5 ‣ 5.2. Evaluation and Tool Comparison ‣ 5. Comparing Function Start Detection Tools ‣ Padding Matters – Exploring Function Detection in PE Files")) performs overall worse on samples without random padding in comparison to the original model. In the case of Chromium x86, the new model even produces worse results for the modified sample. Therefore, we conclude it is not straightforward to train an RNN model that can handle both normal and randomized padding effectively, which raises the question of whether the RNN can identify function start patterns beyond padding. We also finetuned XDA using a randomized-padding version of the newly encoded dataset. Overall, the results were significantly worse for both samples with unmodified padding and samples with randomized padding, even though similar results to those in the experiment in Section [4.3](https://arxiv.org/html/2504.21520v1#S4.SS3 "4.3. Improving XDA ‣ 4. Empirical Validation ‣ Padding Matters – Exploring Function Detection in PE Files") were achieved during validation in training. Consequently, we were unable to train a model for XDA that is robust against randomized padding. Due to the training code of DeepDi not being publicly available, we could not retrain a version of DeepDi.

The randomized padding also negatively affects IDA, Ghidra, and SMDA; however, the impact on their F1\-scores never exceeds 10 percent points. rev.ng is the only tool that is nearly unaffected by the randomized padding; however, we cannot make a statement regarding its results on Chromium.

Nucleus’ detection of function starts is severely negatively impacted by randomized padding. Both precision and recall are similarly affected. In the case of Chromium x86, the F1-score drops from 97.16% to 32.99%. Theoretically, modifying padding bytes should not affect Nucleus’ function start detection, unlike the machine learning tools that have learned with padding during training, since Nucleus operates on the interprocedural control flow graph (ICFG), which does not include padding. Through code review and debugging, we have confirmed that Nucleus is already affected by the randomized padding before creating the ICFG, specifically during disassembling. Nucleus disassembles using linear sweep. The randomized padding bytes are interpreted as instructions by the linear sweep disassembler. This can result in instructions consuming parts of the randomized padding and the beginning of the subsequent function. In this case, at least the function’s first instruction is incorrectly disassembled. The effect is exacerbated by Nucleus detecting that callers point to the middle of an instruction. Nucleus attempts to fix this by shifting the start of the basic block to the beginning of the next instruction. This shift does not resolve the issue, resulting in an incorrect function start being assumed in such cases. Nucleus also provides an experimental recursive traversal disassembling strategy, which shows no significant improvement. While the padding bytes are initially ignored by the recursive strategy, a heuristic111111[https://bitbucket.org/vusec/nucleus/src/e3ab49db579adbdd8451171e980e9b8f8a546a3c/strategy.cc#lines-149](https://bitbucket.org/vusec/nucleus/src/e3ab49db579adbdd8451171e980e9b8f8a546a3c/strategy.cc#lines-149) later reconsiders them, leading to the same problem as with the linear sweep. This heuristic is intended to improve code coverage by assuming another basic block after the end of the current basic block. Removing this heuristic significantly improves precision but also greatly reduces recall, as the overall code coverage becomes very low.

{mdframed}

\[style=insightstyle\] Lessons learned. Function start detection tools are significantly affected by modifications to the compiler-generated padding between functions. When this padding is replaced with random byte values, detection performance deteriorates for the RNN, XDA, DeepDi, and Nucleus. In contrast, IDA, Ghidra, and SMDA are much less impacted. Attempts to retrain the RNN and XDA using samples with randomized padding did not resolve the issue, indicating generalization limitations and leaving it unclear whether these tools can operate effectively on such samples.

6\. Limitations & Conclusion
----------------------------

We conclude that randomized padding between functions in PE binaries significantly diminishes the effectiveness of the RNN, XDA, and Nucleus. Even training on samples with randomized padding does not resolve the issue for the learning-based methods RNN and XDA, highlighting their limitations in generalizability. The remaining tools are also affected by randomized padding, although to a much lesser degree. Threat actors may evade the affected tools through randomized padding impacting subsequent analysis toolchains, e.g., for malware analysis. Among the learning-based tools, DeepDi is the least affected and, overall, the fastest.

When considering the unmodified version of Chromium x64, IDA (98.44%) performs best, closely followed by DeepDi (97%) and SMDA (95.54%). For large-scale applications, DeepDi likely offers the best combination of F1-score and processing speed.

Finally, by modifying the label encoding, we improve XDA’s F1\-score significantly, resulting in an F1\-score of 86.98% for Chromium x64 in comparison to 76.51% for the unmodified version.

Since no pre-trained models for x86 were provided for XDA, we decided not to include XDA in our x86 evaluation. Future work could incorporate a newly pre-trained and finetuned version of XDA for x86 in the evaluation. We assume that the results do not differ significantly between x86 and x64. Another limitation is that our dataset only contains one malware family (Conti), using a C/C++ code base. Ideally, it would be extended to also cover malware using different obfuscation techniques, compilers, and toolchains such as Rust, Nim, Go, and corresponding ground truth. However, obtaining such ground truth data is challenging due to missing or partial debug symbols. Finally, while our work focuses on the Windows PE file format, randomized padding likely also impacts the function detection in other executable file formats, such as ELF, given that padding is an architectural recommendation. Future work could investigate the impact of randomized padding on other file formats.

Code Artifacts
--------------

To foster future research, we publish our source code, data, and other supplementary information online at: [https://github.com/internet-sicherheit/Padding-Matters---Exploring-Function-Detection-in-PE-Files](https://github.com/internet-sicherheit/Padding-Matters---Exploring-Function-Detection-in-PE-Files).

###### Acknowledgements.

The authors gratefully acknowledge funding from the _Federal Ministry of Education and Research_ (grants 13FH101KB1 and 16KIS1746), _nicos AG_, and _Cyberus Technology GmbH_. The authors thank Jan Fedler for his assistance with debugging Nucleus.

References
----------

*   \[1\] National Security Agency. Ghidra Software Reverse Engineering Framework. [https://ghidra-sre.org/](https://ghidra-sre.org/), 2022.
*   \[2\] Jim Alves-Foss and Jia Song. Function boundary detection in stripped binaries. In Proceedings of the 35th Annual Computer Security Applications Conference, ACSAC ’19, page 84–96, New York, NY, USA, Dec 2019. Association for Computing Machinery.
*   \[3\] Dennis Andriesse. Nucleus function detector. [https://bitbucket.org/vusec/nucleus/src/e3ab49db579adbdd8451171e980e9b8f8a546a3c/](https://bitbucket.org/vusec/nucleus/src/e3ab49db579adbdd8451171e980e9b8f8a546a3c/), 2018.
*   \[4\] Dennis Andriesse, Xi Chen, Victor Van Der Veen, Asia Slowinska, and Herbert Bos. An In-Depth Analysis of Disassembly on Full-Scale x86/x64 Binaries. In 25th USENIX Security Symposium (USENIX Security 16), pages 583–600, 2016.
*   \[5\] Dennis Andriesse, Asia Slowinska, and Herbert Bos. Compiler-Agnostic Function Detection in Binaries. In 2017 IEEE European Symposium on Security and Privacy (EuroS P), page 177–189, Apr 2017.
*   \[6\] Daniel Arp, Erwin Quiring, Feargus Pendlebury, Alexander Warnecke, Fabio Pierazzi, Christian Wressnegger, Lorenzo Cavallaro, and Konrad Rieck. Dos and Don’ts of Machine Learning in Computer Security. In 31st USENIX Security Symposium (USENIX Security 22), pages 3971–3988, Boston, MA, August 2022. USENIX Association.
*   \[7\] Tiffany Bao, Jonathan Burket, Maverick Woo, Rafael Turner, and David Brumley. BYTEWEIGHT: Learning to Recognize Functions in Binary Code. In 23rd USENIX Security Symposium (USENIX Security 14), page 845–860, 2014.
*   \[8\] Daniel Johannes Plohmann. Classification, Characterization, and Contextualization of Windows Malware using Static Behavior and Similarity Analysis. PhD thesis, Rheinische Friedrich-Wilhelms-Universität Bonn, July 2022.
*   \[9\] Alessandro Di Federico, Mathias Payer, and Giovanni Agosta. REV.NG: A Unified Binary Analysis Framework to Recover CFGs and Function Boundaries. In Proceedings of the 26th International Conference on Compiler Construction, pages 131–141, 2017.
*   \[10\] Wenbo Guo, Dongliang Mu, Jun Xu, Purui Su, Gang Wang, and Xinyu Xing. LEMNA: Explaining Deep Learning based Security Applications. In Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security, CCS ’18, page 364–379, New York, NY, USA, Oct 2018. Association for Computing Machinery.
*   \[11\] Irfan Ul Haq and Juan Caballero. A survey of binary code similarity. ACM Computing Surveys (CSUR), 54(3):1–38, 2021.
*   \[12\] Hinton. Neural Networks for Machine Learning. [http://www.cs.toronto.edu/~tijmen/csc321/slides/lecture\_slides\_lec6.pdf](http://www.cs.toronto.edu/~tijmen/csc321/slides/lecture_slides_lec6.pdf), 2012.
*   \[13\] Intel. Intel® 64 and IA-32 Architectures Optimization Reference Manual. [https://www.intel.com/content/dam/doc/manual/64-ia-32-architectures-optimization-manual.pdf](https://www.intel.com/content/dam/doc/manual/64-ia-32-architectures-optimization-manual.pdf), 2012.
*   \[14\] AV-TEST-The Independent IT-Security. AV-ATLAS - Malware & PUA. [https://portal.av-atlas.org/malware](https://portal.av-atlas.org/malware), 2024.
*   \[15\] Soomin Kim, Hyungseok Kim, and Sang Kil Cha. Funprobe: Probing functions from binary code through probabilistic analysis. In Satish Chandra, Kelly Blincoe, and Paolo Tonella, editors, Proceedings of the 31st ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering, ESEC/FSE 2023, San Francisco, CA, USA, December 3-9, 2023, pages 1419–1430. ACM, 2023.
*   \[16\] Diederik P. Kingma and Jimmy Ba. Adam: A Method for Stochastic Optimization. [https://arxiv.org/abs/1412.6980](https://arxiv.org/abs/1412.6980), 2014.
*   \[17\] Hyungjoon Koo, Soyeon Park, and Taesoo Kim. A Look Back on a Function Identification Problem. In Annual Computer Security Applications Conference, ACSAC, page 158–168, New York, NY, USA, Dec 2021. Association for Computing Machinery.
*   \[18\] Chengbin Pang, Ruotong Yu, Dongpeng Xu, Eric Koskinen, Georgios Portokalidis, and Jun Xu. Towards optimal use of exception handling information for function detection. In 2021 51st Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), pages 338–349. IEEE, 2021.
*   \[19\] Kexin Pei, Jonas Guan, David Williams-King, Junfeng Yang, and Suman Jana. XDA: accurate, robust disassembly with transfer learning. In 28th Annual Network and Distributed System Security Symposium, NDSS 2021, virtually, February 21-25, 2021. The Internet Society, 2021.
*   \[20\] Daniel Plohmann. SMDA. [https://github.com/danielplohmann/smda](https://github.com/danielplohmann/smda), 2024.
*   \[21\] Jing Qiu, Xiaohong Su, and Peijun Ma. Library functions identification in binary code by using graph isomorphism testings. In 2015 IEEE 22nd International Conference on Software Analysis, Evolution, and Reengineering (SANER), page 261–270, Mar 2015.
*   \[22\] Bernardo Quintero, Alex Berry, Ilfak Guilfanov, and Vijay Bolina. Scaling Up Malware Analysis with Gemini 1.5 Flash. [https://cloud.google.com/blog/topics/threat-intelligence/scaling-up-malware-analysis-with-gemini](https://cloud.google.com/blog/topics/threat-intelligence/scaling-up-malware-analysis-with-gemini), July 2024.
*   \[23\] Hex Rays. IDA Pro. [https://hex-rays.com/ida-pro/](https://hex-rays.com/ida-pro/), 2022.
*   \[24\] Nathan Rosenblum, Xiaojin Zhu, Barton Miller, and Karen Hunt. Learning to analyze binary computer code. In Proceedings of the 23rd national conference on Artificial intelligence - Volume 2, AAAI’08, page 798–804, Chicago, Illinois, Jul 2008. AAAI Press.
*   \[25\] Eui Chul Richard Shin, Dawn Song, and Reza Moazzezi. Recognizing Functions in Binaries with Neural Networks. In 24th USENIX Security Symposium (USENIX Security 15), page 611–626, 2015.
*   \[26\] Paria Shirani, Lingyu Wang, and Mourad Debbabi. BinShape: Scalable and Robust Binary Library Function Identification Using Function Shape. In Michalis Polychronakis and Michael Meier, editors, Detection of Intrusions and Malware, and Vulnerability Assessment, Lecture Notes in Computer Science, page 301–324, Cham, 2017. Springer International Publishing.
*   \[27\] vx-underground.org. Conti v3. [https://github.com/vxunderground/MalwareSourceCode/blob/main/Win32/Ransomware/Win32.Conti.c.7z](https://github.com/vxunderground/MalwareSourceCode/blob/main/Win32/Ransomware/Win32.Conti.c.7z), 2022.
*   \[28\] Sheng Yu, Yu Qu, Xunchao Hu, and Heng Yin. DeepDi: Learning a relational graph convolutional network model on instructions for fast and accurate disassembly. In 31st USENIX Security Symposium (USENIX Security 22), pages 2709–2725, Boston, MA, August 2022. USENIX Association.
