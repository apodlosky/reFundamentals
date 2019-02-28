//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 2, Example 3 - Use PEB to Locate Kernel32, Obfuscated Strings and TLS
//
// Can we hide all of our imports? So far we have either had LoadLibrary and
// GetProcAddress or the EnumProcessModules functions in our import table.
//
// If Ntdll.dll and Kernel32.dll are automatically loaded into every process
// by the loader, Windows stores a list of these modules.
//
// TEB and PEB structures (very limited information):
// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-teb
// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-peb
//
// TEB and PEB structures (reverse engineered by ReactOS):
// https://doxygen.reactos.org/d2/d3d/peb__teb_8h_source.html
//
// PE TLS Callbacks:
// https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#tls-callback-functions
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nt_internal.h"

//
// Type definitions for Windows API functions
//

typedef HANDLE (WINAPI *PFN_GETSTDHANDLE)(
    DWORD nStdHandle);

typedef BOOL (WINAPI *PFN_WRITEFILE)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped);

typedef VOID (WINAPI *PFN_EXITPROCESS)(
    UINT uExitCode);

//
// Pointers to dynamically resolved kernel32.dll functions
//

static PFN_EXITPROCESS    p_ExitProcess;
static PFN_GETSTDHANDLE   p_GetStdHandle;
static PFN_WRITEFILE      p_WriteFile;

//
// Buffer to output (obfuscated).
//
// for i = 0..OUTPUT_SIZE
//   xorOutput[i] = output[i] ^ OUTPUT_XOR
//
#define OUTPUT_SIZE     13
#define OUTPUT_XOR      0x64

//static const char m_output[] = "hello, world\n";

static const BYTE m_xorOutput[OUTPUT_SIZE] = {
    0x0c, 0x01, 0x08, 0x08, 0x0b, 0x48, 0x44,
    0x13, 0x0b, 0x16, 0x08, 0x00, 0x6e
};

//
// CRC32 values of strings (NOT including the terminating null character).
//

#define CRC_KERNEL32DLL  0x6AE69F02 // "kernel32.dll"
#define CRC_EXITPROCESS  0x251097CC // "ExitProcess"
#define CRC_GETSTDHANDLE 0xDADD89EB // "GetStdHandle"
#define CRC_WRITEFILE    0xCCE95612 // "WriteFile"

//
// Calcuates the CRC32 checksum of a given buffer.
//
static UINT32 crc32(const VOID *buffer, SIZE_T length)
{
    const BYTE *data;
    UINT32     crc;
    UINT32     i;
    UINT32     tmp;

    data = (const BYTE *)buffer;
    crc = 0xFFFFFFFF;

    while (length--) {
        crc ^= *data++;

        for (i = 0; i < 8; i++) {
            tmp = ~((crc & 1) - 1);
            crc = (crc >> 1) ^ (0xEDB88320 & tmp);
        }
    }

    return ~crc;
}

//
// Determines the length of a null-terminated string.
//
static SIZE_T stringLengthA(const CHAR *str)
{
    const CHAR *end;

    for (end = str; *end != '\0'; end++);

    return end - str;
}

//
// Calcuates the CRC-32 checksum of a null-terminated string.
//
static UINT32 stringCrc32A(const CHAR *str)
{
    return crc32(str, stringLengthA(str));
}

//
// Converts a wide-character string to a lower-case ANSI string. Note, this
// function ignores ALL Unicode correctness and really should not be used
// outside of this limited application.
//
static VOID stringWToLowerA(const WCHAR *in, SIZE_T inLen, CHAR *out, SIZE_T *outLenPtr)
{
    SIZE_T i;

    for (i = 0; i < inLen && i < *outLenPtr; i++) {
        if (in[i] == '\0') {
            break;
        }

        // WCHAR-to-CHAR kludge
        out[i] = (CHAR)(in[i] & 0x00FF);

        // Convert to lower case
        if (out[i] >= 'A' && out[i] <= 'Z') {
            out[i] -= ('A' - 'a');
        }
    }

    // Truncate if needed, add terminating null
    if (i >= *outLenPtr) {
        i--;
    }
    out[i] = '\0';
    *outLenPtr = i;
}

//
// Locates the base of kernel32.dll by walking the PEB's loader data.
//
// Returns NULL on failure, or the module's base address on success.
//
static HMODULE locateKernel32Module(VOID)
{
    PEB                  *peb;
    PEB_LDR_DATA         *ldrData;
    LDR_DATA_TABLE_ENTRY *ldrEntry;
    LIST_ENTRY           *entry;
    LIST_ENTRY           *start;
    CHAR                 baseName[128];
    SIZE_T               baseNameLen;

    //
    // Retrieve the PEB and locate the loader data, which contains several
    // lists of modules modules currently loaded in this process.
    //
    peb = GetPEB();
    ldrData = peb->Ldr;

    // The address of the first LIST_ENTRY structure will mark our end
    start = &(ldrData->InMemoryOrderModuleList);

    // Iterate through the linked list of LIST_ENTRY structures
    for (entry = start->Flink; entry != start && entry != NULL; entry = entry->Flink) {

        // Locate the base of the LDR_DATA_TABLE_ENTRY structure
        ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks);

        // Convert the wide-character name to a lower-case ANSI string
        baseNameLen = sizeof(baseName);
        stringWToLowerA(ldrEntry->BaseDllName.Buffer,
            ldrEntry->BaseDllName.Length, baseName, &baseNameLen);

        if (crc32(baseName, baseNameLen) == CRC_KERNEL32DLL) {
            // Found kernel32, return the base address
            return (HMODULE)ldrEntry->DllBase;
        }
    }

    return NULL;
}

//
// Returns the base pointer adjusted to the specified offset.
//
#define RVA_TO_PTR(base, offset) ((VOID *)(((BYTE *)base) + offset))

//
// Simple implementation of GetProcAddress for resolving the addresses of
// exported functions by CRC32 of names. Note, there is very limited validation
// of PE structures and no support for forwarded functions.
//
// Returns NULL on failure, or a pointer to the function on success.
//
static VOID *getProcByCrc32(HMODULE base, UINT32 crcProcName)
{
    CHAR                   *name;
    DWORD                  *tblFuncs;
    DWORD                  *tblNames;
    WORD                   *tblNameOrds;
    DWORD                  i;
    DWORD                  ordinal;
    IMAGE_DOS_HEADER       *dosHdr;
    IMAGE_NT_HEADERS       *ntHdr;
    IMAGE_EXPORT_DIRECTORY *expDir;

    // The HMODULE for a loaded module is also its base virtual address
    dosHdr = (IMAGE_DOS_HEADER *)base;

    // Verify the DOS header signature (16bit magic value 'MZ')
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    // Use the DOS header to locate the NT header (RVA from image base)
    ntHdr = RVA_TO_PTR(base, dosHdr->e_lfanew);

    // Verify the NT header signature (32bit magic value 'PE00') and optional-
    // header size, and the optional-header's magic value
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE ||
        ntHdr->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER) ||
        ntHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        return NULL;
    }

    //
    // NOTE: There is NO bounds checking done to ensure the RVAs have not
    // exceeded the image size. Do NOT use this code with potentially hostile
    // DLL files.
    //

    // Use the NT header to locate the export directory (RVA from image base)
    expDir = RVA_TO_PTR(base, ntHdr->OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Use the export directory to locate the names, ordinals, and funcs tables
    tblNames = RVA_TO_PTR(base, expDir->AddressOfNames);
    tblNameOrds = RVA_TO_PTR(base, expDir->AddressOfNameOrdinals);
    tblFuncs = RVA_TO_PTR(base, expDir->AddressOfFunctions);

    for (i = 0; i < expDir->NumberOfNames; i++) {
        // The Names table, containing RVAs to C-style strings, is indexed
        // from 0 to NumberOfNames-1.
        name = RVA_TO_PTR(base, tblNames[i]);
        if (stringCrc32A(name) != crcProcName) {
            continue;
        }

        //
        // To calculate the ordinal value of an exported function, the value
        // obtained from the ordinals table must be added with the Base.
        //   RelativeOrdinal = NameOrdinals[IndexOfName]
        //   ActualOrdinal = RelativeOrdinal + OrdinalBase
        //
        // The Functions table, containing RVAs to function addresses, is
        // indexed from 0 to NumberOfFunctions-1 by 'relative' ordinal values.
        //   FuncAddr = Funcs[ActualOrdinal - OrdinalBase]
        // or simply:
        //   FuncAddr = Funcs[RelativeOrdinal]
        //
        ordinal = tblNameOrds[i];

        // Verify function index is not out-of-bounds
        if (ordinal >= expDir->NumberOfFunctions) {
            return NULL;
        }
        return RVA_TO_PTR(base, tblFuncs[ordinal]);
    }

    return NULL;
}

//
// Dynamically resolves functions from the kernel32.dll library on runtime.
//
// Returns 0 (FALSE) on failure, and non-zero (TRUE) on success.
//
static BOOL resolveFuncs(VOID)
{
    HMODULE module;

    // Locate the kernel32.dll module in this process
    module = locateKernel32Module();
    if (module == NULL) {
        return FALSE;
    }

    //
    // Look-up functions by the CRC32 value of their names
    //

    p_ExitProcess = (PFN_EXITPROCESS)getProcByCrc32(module, CRC_EXITPROCESS);
    if (p_ExitProcess == NULL) {
        return FALSE;
    }

    p_GetStdHandle = (PFN_GETSTDHANDLE)getProcByCrc32(module, CRC_GETSTDHANDLE);
    if (p_GetStdHandle == NULL) {
        return FALSE;
    }

    p_WriteFile = (PFN_WRITEFILE)getProcByCrc32(module, CRC_WRITEFILE);
    if (p_WriteFile == NULL) {
        return FALSE;
    }

    return TRUE;
}

//
// Entry point (EP) for our executable.
//
void __stdcall EntryPoint(void)
{
    // No-op, instead the TLS callback will do our usual work
}

//
// TLS callback will be executed by the Windows PE Loader.
//
void __stdcall TlsCallback(HMODULE instance, DWORD reason, void *reserved)
{
    CHAR   output[OUTPUT_SIZE];
    HANDLE stdOutput;
    UINT   result;
    SIZE_T i;
    static UINT count = 0;

    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(reserved);

    // This callback is executed twice when tested on Windows 10 (called from
    // ntdll.dll), yet once on Windows 7. Could be process detach notification,
    // need to debug further...use a static counter to prevent second execution.
    if (++count != 1) {
        //__debugbreak();
        return;
    }

    if (!resolveFuncs()) {
        return;
    }

    //
    // Decode string from a simple XOR obfuscation:
    //  str[i] = xor[i] ^ 0x64
    //
    for (i = 0; i < OUTPUT_SIZE; i++) {
        output[i] = m_xorOutput[i] ^ OUTPUT_XOR;
    }

    stdOutput = p_GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdOutput == INVALID_HANDLE_VALUE) {
        result = 1;
    } else if (!p_WriteFile(stdOutput, output, OUTPUT_SIZE, NULL, NULL)) {
        result = 2;
    } else {
        // Success
        result = reason;
    }

    p_ExitProcess(result);

    // Unreachable
    __assume(0);
}

//
// Setup .tls PE section
//

#pragma section(".CRT$XLA", long, read)
#pragma section(".CRT$XLB", long, read)
#pragma section(".CRT$XLZ", long, read)
#pragma section(".rdata$T", long, read)

ULONG _tls_index = 0;

#pragma data_seg(".tls")

#ifdef _M_X64
__declspec(allocate(".tls"))
#endif
char _tls_start = 0;

#pragma data_seg(".tls$ZZZ")

#ifdef _M_X64
__declspec(allocate(".tls$ZZZ"))
#endif
char _tls_end = 0;

#pragma data_seg()

//
// TLS callback array
//

__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK __xl_b = TlsCallback;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;

//
// TLS directory
//

#ifdef _WIN64
__declspec(allocate(".rdata$T"))
extern const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)&_tls_start,
    (ULONGLONG)&_tls_end,
    (ULONGLONG)&_tls_index,
    (ULONGLONG)(&__xl_a+1),
    0,
    0
};
#else /* _WIN64 */
__declspec(allocate(".rdata$T"))
extern const IMAGE_TLS_DIRECTORY _tls_used = {
    (ULONG)&_tls_start,
    (ULONG)&_tls_end,
    (ULONG)&_tls_index,
    (ULONG)(&__xl_a+1),
    0,
    0
};
#endif /* _WIN64 */
