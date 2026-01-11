
IAT Hiding & Obfuscation
========================

Posted Apr 25, 2024 Updated Aug 31, 2025

By _[Noel Carrasco](https://twitter.com/NoelCarrasco16)_ _17 min_ read

The Import Address Table (IAT) holds crucial data about a PE file, including the functions utilized and the DLLs that export them. Such data is pivotal for signature-based detection of binaries. In this post, we’ll delve into various techniques for obscuring our footprint.

Introduction[](#introduction)
-----------------------------

Security solutions such as AVs and EDRs are continuously analyzing the functions binaries import. Some functions such `CreateRemoteThread`, `OpenProcess`, `WriteProcessMemory`, etc. put the security solutions in alert mode, monitoring in more detail the process behavior.

Okey, but how can those EDRs know what functions are the malware importing? One approach (but not the only one) is the Import Address Table (IAT).

The Import Address Table (IAT)[](#the-import-address-table-iat)
---------------------------------------------------------------

The **Import Address Table (IAT)** is a data structure used in the **Windows** operating system to facilitate dynamic linking of executable code. When a Windows program uses functions from **external libraries (DLLs)**, it doesn’t directly call those functions by their memory addresses. Instead, it relies on dynamic linking, where the addresses of the functions are resolved at runtime.

The **IAT** is a table within the program’s executable file that contains addresses of functions imported from DLLs. When the program is loaded into memory, the loader fills in this table with the actual addresses of the functions from the corresponding DLLs. This allows the program to call those functions without knowing their addresses in advance. Pretty useful right?

So the one million dollar question; how can we import functions without getting flagged? One approach is create custom functions that perform the same actions as WinAPIs; easier said than done.

Creating GetProcAddress[](#creating-getprocaddress)
---------------------------------------------------

The [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL), then it searches that address through the exported functions inside the provided DLL. If the address is found, return that value, if not, the return value is NULL. Our objective is to create our alternative to this function.

### The Export Table[](#the-export-table)

The **Export Table** is a data structure **found within Dynamic Link Libraries (DLLs)** on the Windows operating system. It contains a list of functions and variables that the DLL makes available to other programs or DLLs. When a DLL is created, developers can specify which functions and variables should be accessible to other modules.

When another program or DLL wants to use a function or variable from a DLL, it can locate the Export Table within that DLL and find the necessary symbol along with its memory address. This allows the program to call the function or access the variable without needing to know its implementation details.

#### Export Table Structure[](#export-table-structure)

The Export Table serves as a directory of symbols exported by the DLL. This table follows the same structure as `IMAGE_EXPORT_DIRECTORY`.

`1 2 3 4 5 6 7 8 9 10 11 12 13  typedef struct _IMAGE_EXPORT_DIRECTORY {     DWORD   Characteristics;          // Characteristics of the export directory     DWORD   TimeDateStamp;            // Time and date the export data was created     WORD    MajorVersion;             // Major version number     WORD    MinorVersion;             // Minor version number     DWORD   Name;                     // RVA (Relative Virtual Address) of the module name     DWORD   Base;                     // Ordinal base value     DWORD   NumberOfFunctions;        // Number of functions exported by the module     DWORD   NumberOfNames;            // Number of function names     DWORD   AddressOfFunctions;       // RVA of the array of function addresses     DWORD   AddressOfNames;           // RVA of the array of function name pointers     DWORD   AddressOfNameOrdinals;    // RVA of the array of function ordinals } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;`

The most relevant variables of this structure are:

1.  `AddressOfFunctions`: This field contains the RVA (Relative Virtual Address) from the base of the image (DLL) to an array of RVAs. Each RVA in this array points to the address of a function within the DLL. The functions are typically stored in ascending order of their ordinals. To locate a specific function, you would use its ordinal to index into this array and retrieve its RVA, which you can then use to calculate the actual memory address of the function within the loaded DLL.
    
2.  `AddressOfNames`: Similarly, this field contains the RVA to an array of RVAs. Each RVA in this array points to the name of a function exported by the DLL. The names are stored as null-terminated strings. To find the name of a specific function, you would use its ordinal to index into this array and retrieve the RVA of the function’s name, which you can then dereference to access the actual function name.
    
3.  `AddressOfNameOrdinals`: This field contains the RVA to an array of 16-bit ordinals. Each ordinal corresponds to the position of a function name in the `AddressOfNames` array and its associated address in the `AddressOfFunctions` array. To determine the ordinal of a function, you would use its name to search the `AddressOfNames` array and retrieve its index. This index corresponds to the ordinal stored in the `AddressOfNameOrdinals` array. Ordinals will be explained more in depth later.
    

#### Accessing the Export Table[](#accessing-the-export-table)

Within the structure of a **Windows Dynamic Link Library (DLL)**, the **Export Table** is encapsulated within what’s known as the **IMAGE\_EXPORT\_DIRECTORY**. This directory serves as a repository for essential data regarding the functions and symbols that the DLL makes available for other programs to use.

Now, to understand where this **Export Table** resides within the **DLL file**, we need to navigate through its various headers. The starting point is the **IMAGE\_DOS\_HEADER**, which is the initial structure of any executable file in the DOS environment. This header contains basic information like the DOS stub and the file signature. Following the **DOS header**, we encounter the **IMAGE\_NT\_HEADERS**, which represent the **PE (Portable Executable) header** of the file.

The [IMAGE\_DOS\_HEADER](https://0xrick.github.io/win-internals/pe3/) structure has the `e_lfanew` attribute, which is the file **offset** (in bytes) of the **PE header** (also known as the PE signature) relative to the beginning of the file. So to access to the **PE header** we need to know the **DOS header** address and add the offset indicated by the `e_lfanew`:

`1 2  IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule; IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);`

Within the **IMAGE\_NT\_HEADERS**, we find the **OptionalHeader**. The **OptionalHeader** section of the **IMAGE\_NT\_HEADERS** is a **IMAGE\_NT\_HEADERS**.

`1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39  typedef struct _IMAGE_NT_HEADERS {   DWORD                   Signature;   IMAGE_FILE_HEADER       FileHeader;   IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;  typedef struct _IMAGE_OPTIONAL_HEADER {   WORD                 Magic;   BYTE                 MajorLinkerVersion;   BYTE                 MinorLinkerVersion;   DWORD                SizeOfCode;   DWORD                SizeOfInitializedData;   DWORD                SizeOfUninitializedData;   DWORD                AddressOfEntryPoint;   DWORD                BaseOfCode;   DWORD                BaseOfData;   DWORD                ImageBase;   DWORD                SectionAlignment;   DWORD                FileAlignment;   WORD                 MajorOperatingSystemVersion;   WORD                 MinorOperatingSystemVersion;   WORD                 MajorImageVersion;   WORD                 MinorImageVersion;   WORD                 MajorSubsystemVersion;   WORD                 MinorSubsystemVersion;   DWORD                Win32VersionValue;   DWORD                SizeOfImage;   DWORD                SizeOfHeaders;   DWORD                CheckSum;   WORD                 Subsystem;   WORD                 DllCharacteristics;   DWORD                SizeOfStackReserve;   DWORD                SizeOfStackCommit;   DWORD                SizeOfHeapReserve;   DWORD                SizeOfHeapCommit;   DWORD                LoaderFlags;   DWORD                NumberOfRvaAndSizes;   IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;`

The **OptionalHeader** contains additional information about the executable or DLL, **including various optional data directories**. One of these directories is specifically designated for exporting functions, aptly named the **IMAGE\_EXPORT\_DIRECTORY**.

Inside the **IMAGE\_EXPORT\_DIRECTORY**, you’ll find details such as the names of exported functions, their memory addresses, and other relevant information needed for dynamic linking.

`1 2 3 4  typedef struct _IMAGE_DATA_DIRECTORY {   DWORD VirtualAddress;   DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;`

In the following code we access to the **DataDirectory** in the **Export Directory** point and save the **IMAGE\_DATA\_DIRECTORY** structure. After that, we access to the **VirtualAddress** parameter which holds the pointer to the **EXPORT\_DIRECTORY** structure of the DLL:

`1 2  IMAGE_DATA_DIRECTORY exportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(hModule + exportDirectory.VirtualAddress);`

After obtaining a pointer to the **IMAGE\_EXPORT\_DIRECTORY** structure (see start of this section), it’s possible to loop through the exported functions.

The `NumberOfFunctions` member specifies the number of functions exported by `hModule`. As a result, the maximum iterations of the loop should be equivalent to `NumberOfFunctions`.

`1  DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;`

The next step is to build the search logic for the functions. This requires the use of `AddressOfFunctions`, `AddressOfNames`, and `AddressOfNameOrdinals`.

Since these elements are RVAs, the base address of the module, `hModule`, must be added to get the VA.

`1 2 3  DWORD* pAddressOfFunctions = (DWORD*)(hModule + pExportDirectory->AddressOfFunctions); DWORD* pAddressOfNames = (DWORD*)(hModule + pExportDirectory->AddressOfNames); WORD* pAddressOfNameOrdinals = (WORD*)(hModule + pExportDirectory->AddressOfNameOrdinals);`

As mentioned before, `pAddressOfNameOrdinals` is the function’s **ordinal**.

**What is an ordinal?**

An **ordinal** is a numerical value assigned to a function or procedure within a dynamic-link library (DLL). **Ordinals** are used as **identifiers for functions exported by the DLL**. When a DLL exports functions, it assigns each function a unique ordinal number, typically starting from 1 and incrementing by 1 for each subsequent function.

The ordinal number serves as an **alternative** way to reference exported functions within the DLL. Instead of using the function’s name, you can use its ordinal to locate and access the function within the DLL’s Export Table. This can be useful in scenarios where using the function’s name may be inefficient or unnecessary.

For example, when dynamically linking to functions in a DLL, you may choose to use ordinals instead of names to reduce the size of the import table and improve performance. Additionally, using ordinals **can provide a level of obfuscation**, as it’s **less intuitive** to identify functions solely by their ordinal numbers.

> **Note**
> 
> Ordinal value is used to identify a function’s **address** rather than its name. The export table operates this way to handle cases where the function name is not available or is not unique.

That said, the following code snippet will print the ordinal value of each function in the function array of a specified module.

`1 2 3 4 5  for (DWORD i = 0; i < numberOfFunctions; i++){ 	CHAR* pFunctionName	= (CHAR*)(hModule + pAddressOfNames[i]); 	WORD wFunctionOrdinal = pAddressOfNameOrdinals[i]; 	printf("[ %0.4d ] NAME: %s -\t ORDINAL: %d\n", i, pFunctionName, wFunctionOrdinal); }`

### Full code[](#full-code)

`1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57  #include <windows.h> #include <stdio.h> // Define the structure of the Export Directory typedef struct _IMAGE_EXPORT_DIRECTORY {     DWORD   Characteristics;     DWORD   TimeDateStamp;     WORD    MajorVersion;     WORD    MinorVersion;     DWORD   Name;     DWORD   Base;     DWORD   NumberOfFunctions;     DWORD   NumberOfNames;     DWORD   AddressOfFunctions;     DWORD   AddressOfNames;     DWORD   AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;  int main() {     // Load the DLL into memory     HMODULE hModule = LoadLibrary(TEXT("YourDll.dll"));     if (hModule == NULL) {         printf("Failed to load DLL.\n");         return 1;     }      // Get the base address of the DLL     DWORD dwBaseAddress = (DWORD)hModule;      // Locate the Export Directory     IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;     IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);     IMAGE_DATA_DIRECTORY exportDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];      if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0) {         printf("Export Directory not found.\n");         return 1;     }      // Access the Export Directory     PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwBaseAddress + exportDirectory.VirtualAddress);      // Access Exported Function Information     DWORD* pAddressOfFunctions = (DWORD*)(dwBaseAddress + pExportDirectory->AddressOfFunctions);     DWORD* pAddressOfNames = (DWORD*)(dwBaseAddress + pExportDirectory->AddressOfNames);     WORD* pAddressOfNameOrdinals = (WORD*)(dwBaseAddress + pExportDirectory->AddressOfNameOrdinals);     DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;  	for (DWORD i = 0; i < numberOfFunctions; i++){ 	 		CHAR* pFunctionName	= (CHAR*)(hModule + pAddressOfNames[i]); 	 		WORD wFunctionOrdinal = pAddressOfNameOrdinals[i]; 	 		printf("[ %0.4d ] NAME: %s -\t ORDINAL: %d\n", i, pFunctionName, wFunctionOrdinal); }      // Free the loaded DLL     FreeLibrary(hModule);     return 0; }`

Creating GetModuleHandle[](#creating-getmodulehandle)
-----------------------------------------------------

The [GetModuleHandle](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) function retrieves a handle to the specified module if it’s already loaded into the address space of the calling process. A module handle is a unique identifier that represents a loaded module (typically a DLL or an executable file). This function is commonly used to obtain a handle to the module of the current process or to find the handle of another loaded module by specifying its module name.The function returns a handle to the DLL (`HMODULE`) or `NULL` if the DLL does not exist in the calling process.

`HMODULE` is a handle to a module, typically a DLL or an executable file. It’s a pointer to the base address of the module when it is loaded into memory. In Win32 programming, `HMODULE` is defined as a pointer to a `HINSTANCE__` structure. It’s important to note that `HMODULE` and `HINSTANCE` are essentially the same data type; they are interchangeable and can be used interchangeably in most situations.

Our goal is to create a function to retrieve the base address of a specified DLL. For this purpose we are gonna use the **Process Environment Block (PEB)**, which contains information regarding the loaded DLLs.

### The Process Environment Block (PEB)[](#the-process-environment-block-peb)

The Process Environment Block (PEB) is a data structure in Windows operating systems that holds various pieces of information about a running process. The PEB comes from the Thread Environment Block (TEB) data structure, which stores stores thread-specific information.

Having the PEB within the TEB allows a thread to access information about the process it belongs to, such as loaded modules, process parameters, and environment variables. The TEB serves as a bridge between the per-thread context and the process-wide context provided by the PEB.

> **Note** In x64 systems, an offset to the TEB pointer is stored in the GS (Global Segment) register; a special-purpose register in x86 and x86-64 architectures. By storing the offset to the TEB in the GS register, the operating system can efficiently access thread-specific data without needing to perform additional memory lookups. This register is used to optimize access to thread-specific data in 64-bit operating systems.

The PEB structure is defined as follows:

`1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21  typedef struct _PEB {   BYTE                          Reserved1[2];   BYTE                          BeingDebugged;   BYTE                          Reserved2[1];   PVOID                         Reserved3[2];   PPEB_LDR_DATA                 Ldr;   PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;   PVOID                         Reserved4[3];   PVOID                         AtlThunkSListPtr;   PVOID                         Reserved5;   ULONG                         Reserved6;   PVOID                         Reserved7;   ULONG                         Reserved8;   ULONG                         AtlThunkSListPtr32;   PVOID                         Reserved9[45];   BYTE                          Reserved10[96];   PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;   BYTE                          Reserved11[128];   PVOID                         Reserved12[1];   ULONG                         SessionId; } PEB, *PPEB;`

The most important member of the PEB structure is the `Ldr` variable of type `PEB_LDR_DATA`. The `Ldr` member provides information about the modules currently loaded into the process’s address space, such as DLLs and their dependencies. Additionally, it may contain details about module initialization and deinitialization routines. Therefore, our first step is to retrieve the PEB structure.

> **Note** The “TIB” (Thread Information Block) and “TEB” (Thread Environment Block) are slightly the same but with some differences:

TIB (Thread Information Block)

TEB (Thread Environment Block)

Architecture

x86 (32-bit)

x86-64 (64-bit)

Access Method

Accessed through FS segment register

Accessed through GS segment register

Contains

Thread-specific information

More detailed thread-specific information

Mainly there are two different approaches to retrieve the PEB pointer: one is using the `__readgsqword` macro from Vistual Studio (VS) and the other is implement it in assembly.

> **Note** All information sources I found said that to access to the PTEB structure you had to retrieve a quadword from the offset `0x30` in the GS or doubleword from `0x18` offset in the FS for 32-bit. The same happens for the PPEB at offsets `0x60` and `0x30` respectively
> 
> Why those offsets? As where I could investigate, that offset comes from the design decisions made by Microsoft when defining the layout of thread-specific information within the GS segment.

Therefore are two possibilities:

1.  Access the PTEB and the access to the PPEB:

`1 2 3 4 5 6 7  # For 64 bit PTEB pTeb = (PTEB)__readgsqword(0x30); PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;  # For 32 bit PTEB pTeb = (PTEB)__readgsqword(0x18); PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;`

1.  Access directly to the PPEB:

`1 2 3 4 5  # For 64 bit PPEB pPeb = (PPEB)__readgsqword(0x60);   # For 32 bit PPEB pPeb = (PPEB)__readgsqword(0x30);` 

After obtaining the PEB structure, the subsequent task involves accessing its `PEB_LDR_DATA Ldr` member, which holds information about the loaded DLLs within the process. Within this structure, the crucial member to focus on is `LIST_ENTRY InMemoryOrderModuleList`.

`1 2 3 4 5  typedef struct _PEB_LDR_DATA {   BYTE       Reserved1[8];   PVOID      Reserved2[3];   LIST_ENTRY InMemoryOrderModuleList; } PEB_LDR_DATA, *PPEB_LDR_DATA;`

The `LIST_ENTRY` structure functions as a doubly-linked list, with one member pointing forwards (`Flink`) and the other pointing backwards (`Blink`).

According to [Microsoft’s definition](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data) for the `InMemoryOrderModuleList` member, each item in the list is a pointer to an `LDR_DATA_TABLE_ENTRY` structure, which represents a DLL inside the linked list of loaded DLLs for the process, with each `LDR_DATA_TABLE_ENTRY` representing a unique DLL.

As Microsoft shows most of the members as reserved, we put the one from the [Windows Vista Kernel Structures](https://www.nirsoft.net/kernel_struct/vista/index.html) research. More on this later.

`1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34  typedef struct _LIST_ENTRY {    struct _LIST_ENTRY *Flink;    struct _LIST_ENTRY *Blink; } LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;  typedef struct _LDR_DATA_TABLE_ENTRY {     LIST_ENTRY InLoadOrderLinks;     LIST_ENTRY InMemoryOrderLinks;     LIST_ENTRY InInitializationOrderLinks;     PVOID DllBase;     PVOID EntryPoint;     ULONG SizeOfImage;     UNICODE_STRING FullDllName;     UNICODE_STRING BaseDllName;     ULONG Flags;     WORD LoadCount;     WORD TlsIndex;     union {         LIST_ENTRY HashLinks;         struct {             PVOID SectionPointer;             ULONG CheckSum;         };     };     union {         ULONG TimeDateStamp;         PVOID LoadedImports;     };     PACTIVATION_CONTEXT EntryPointActivationContext;     PVOID PatchInformation;     LIST_ENTRY ForwarderLinks;     LIST_ENTRY ServiceTagLinks;     LIST_ENTRY StaticLinks; } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;`

### Hands-on coding[](#hands-on-coding)

Based on everything mentioned so far, the required actions are:

1.  Retrieve the PEB
2.  Retrieve the Ldr member from the PEB
3.  Retrieve the first element in the linked list
4.  Normalize the DLL name to match with the provided one
5.  Check the Microsoft’s version of the `LDR_DATA_TABLE_ENTRY` to know what to return

`1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36  HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {  // Getting PEB #ifdef _WIN64 // if compiling as x64 	PPEB					pPeb		= (PEB*)(__readgsqword(0x60)); #elif _WIN32 // if compiling as x32 	PPEB					pPeb		= (PEB*)(__readfsdword(0x30)); #endif 	// Getting Ldr 	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr); 	// Getting the first element in the linked list (contains information about the first module) 	PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink); 	 	while (pDte) { 		 		if (pDte->FullDllName.Length != NULL) {  			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) { 				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer); 			#ifdef STRUCTS 				return (HMODULE)(pDte->InInitializationOrderLinks.Flink); 			#else 				return (HMODULE)pDte->Reserved2[0]; 			#endif 			} 		} 		else { 			break; 		} 		 		// Next element in the linked list 		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte); 	} 	return NULL; }`

The `pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);` line of code may look complex but all it is doing is dereferencing the value stored at the address pointed to by `pDte` and then casting the result to a pointer to the `PLDR_DATA_TABLE_ENTRY` structure.

Here is an image to depict the and understand better how this works:

[![Double linked list](/assets/img/posts/peb_walk.png)](/assets/img/posts/peb_walk.png) _Double-linked list structure_

The following code go as follows: depending on whether the macro `STRUCTS` is defined. If the Microsoft’s version of the `LDR_DATA_TABLE_ENTRY` structure is being used or the one from Windows Vista Kernel Structures the code returns either the value of `Flink` member of `InInitializationOrderLinks` or the first element of the `Reserved2` array, both casted to `HMODULE`.

`1 2 3 4 5  #ifdef STRUCTS 	return (HMODULE)(pDte->InInitializationOrderLinks.Flink); #else 	return (HMODULE)pDte->Reserved2[0]; #endif // STRUCTS`

[Malware Development](/categories/malware-development/), [Anti-Analysis Techniques](/categories/anti-analysis-techniques/)

This post is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) by the author.

Share[](https://twitter.com/intent/tweet?text=IAT%20Hiding%20&%20Obfuscation%20-%20N10h0ggr&url=https%3A%2F%2Fn10h0ggr.github.io%2Fposts%2FIAT-Hiding%2F "Twitter")[](https://www.facebook.com/sharer/sharer.php?title=IAT%20Hiding%20&%20Obfuscation%20-%20N10h0ggr&u=https%3A%2F%2Fn10h0ggr.github.io%2Fposts%2FIAT-Hiding%2F "Facebook")[](https://t.me/share/url?url=https%3A%2F%2Fn10h0ggr.github.io%2Fposts%2FIAT-Hiding%2F&text=IAT%20Hiding%20&%20Obfuscation%20-%20N10h0ggr "Telegram")

Recently Updated
----------------

*   [Hardware Breakpoints: Una Alternativa Silenciosa a los Hooks Tradicionales](/posts/Hardware-Breakpoints/)
*   [Building an Anti-Evasion Malware Analysis Lab](/posts/Building-a-Hardened-Malware-Analysis-Lab/)
*   [A Deep Dive into Legacy Bootkits and Rootkits](/posts/The-Legacy-Boot-Process-A-Deep-Dive-into-MBR-VBR-and-IPL-Bootkits/)
*   [Process Enumeration](/posts/Process-Enumeration/)
*   [Adobe PDF Exploit](/posts/Adobe-PDF-Exploit/)

Trending Tags
-------------

[cve-2007-5659](/tags/cve-2007-5659/) [cve-2008-2992](/tags/cve-2008-2992/) [cve-2009-0927](/tags/cve-2009-0927/) [cve-2017-11882](/tags/cve-2017-11882/) [spanish](/tags/spanish/)

Contents
--------

### Further Reading

[

Apr 21, 2024

#### Process Argument Spoofing

Process argument spoofing involves concealing the command-line arguments of a newly spawned process. This tactic aims to enable command execution without disclosing the commands to logging services...





](/posts/Process-Argument-Spoofing/)

[

Aug 20, 2025

#### Process Enumeration

Explanation on how to implement process enumeration in Windows and Linux, showing examples with APIs, access to the PEB, and use of the /proc system What does this technique consist of? Process en...





](/posts/Process-Enumeration/)

[

May 19, 2024

#### Implementing Early Bird APC Injection in Rust

In this post, I’ll walk you through one of the challenges from Maldev Academy: creating a program in Rust that connects to an HTTP/HTTPS web page, downloads a shellcode, and performs Early Bird APC...





](/posts/Early-Bird-APC-Injection/)

[

Process Argument Spoofing

](/posts/Process-Argument-Spoofing/)[

Kerberos Delegation

](/posts/Kerberos-Delegation/)

© 2025 [Noel Carrasco](https://twitter.com/NoelCarrasco16). Some rights reserved.
