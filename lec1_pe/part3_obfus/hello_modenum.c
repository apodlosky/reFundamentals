//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 2, Example 2 - Finding Kernel32 in Memory
//
// Can we remove LoadLibrary and GetProcAddress from our import table? We
// could locate the kernel32.dll image that is mapped into our process' address
// space using the EnumProcessModules  API, then parse the kernel32's IAT and
// locate GetProcAddress ourselves.
//
// EnumProcessModules:
// https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-enumprocessmodules
// https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-modules-for-a-process
//
// PE format:
// https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

//
// Type definitions for Windows API functions
//

typedef FARPROC (WINAPI *PFN_GETPROCADDRESS)(
    HMODULE hModule,
    LPCSTR lpProcName);

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

static PFN_GETPROCADDRESS p_GetProcAddress;
static PFN_GETSTDHANDLE   p_GetStdHandle;
static PFN_WRITEFILE      p_WriteFile;
static PFN_EXITPROCESS    p_ExitProcess;

// Buffer to display to the console
static const char m_output[] = "hello, world\n";

//
// Compares two strings for equality, case-sensitive.
//
static BOOL stringEqualA(const char *string1, const char *string2)
{
    unsigned char c1;
    unsigned char c2;

    do {
        c1 = (unsigned char)*string1++;
        c2 = (unsigned char)*string2++;
    } while (c1 != '\0' && c1 == c2);

    return (c1 == c2);
}

//
// Compares two strings for equality, case-insensitive.
//
static BOOL stringEqualNoCaseA(const char *string1, const char *string2)
{
    unsigned char c1;
    unsigned char c2;

    do {
        c1 = (unsigned char)*string1++;
        c2 = (unsigned char)*string2++;

        // Convert to lower case
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 -= (unsigned char)('A' - 'a');
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 -= (unsigned char)('A' - 'a');
        }
    } while (c1 != '\0' && c1 == c2);

    return (c1 == c2);
}

//
// Locates kernel32.dll in the current processes module list using
// EnumProcessModules().
//
static HMODULE locateKernel32Module(VOID)
{
    CHAR    name[MAX_PATH];
    DWORD   i;
    DWORD   countBytes;
    HANDLE  currProcess;
    HMODULE modules[128];

    currProcess = GetCurrentProcess();
    countBytes = 0;

    //
    // Enumerate module list
    //

    if (!EnumProcessModules(currProcess, modules, sizeof(modules), &countBytes)) {
        return NULL;
    }

    for (i = 0; i < (countBytes / sizeof(HMODULE)); i++) {

        // Retrieve file name of module (e.g. foo.dll)
        if (!GetModuleBaseNameA(currProcess, modules[i], name, sizeof(name))) {
            continue;
        }

        if (stringEqualNoCaseA(name, "kernel32.dll")) {
            // Found kernel32! We're done...
            return modules[i];
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
// exported functions by name. Note, there is very limited validation of PE
// structures and no support for forwarded functions.
//
// Returns NULL on failure, or a pointer to the function on success.
//
static VOID *getProcByName(HMODULE base, const char *procName)
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
        if (!stringEqualA(name, procName)) {
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
// Dynamically resolves functions from the kernel32.dll library on runtime
// using LoadLibrary() and GetProcAddress().
//
// Returns 0 (FALSE) on failure, or non-zero (TRUE) on success.
//
static BOOL resolveFuncs(VOID)
{
    HMODULE module;

    // Locate the kernel32.dll module in this process
    module = locateKernel32Module();
    if (module == NULL) {
        return FALSE;
    }

    // Locate GetProcAddress in kernel32.dll's export address table (EAT)
    p_GetProcAddress = (PFN_GETPROCADDRESS)getProcByName(module, "GetProcAddress");
    if (p_GetProcAddress == NULL) {
        return FALSE;
    }

    //
    // We could just use getProcByName()...but it may be useful to set a
    // breakpoint on GetProcAddress during the demo.
    //

    // Now use GetProcAddress to look-up the remaining WinAPI functions
    p_GetStdHandle = (PFN_GETSTDHANDLE)p_GetProcAddress(module, "GetStdHandle");
    if (p_GetStdHandle == NULL) {
        return FALSE;
    }

    p_WriteFile = (PFN_WRITEFILE)p_GetProcAddress(module, "WriteFile");
    if (p_WriteFile == NULL) {
        return FALSE;
    }

    p_ExitProcess = (PFN_EXITPROCESS)p_GetProcAddress(module, "ExitProcess");
    if (p_ExitProcess == NULL) {
        return FALSE;
    }

    return TRUE;
}

//
// Entry point (EP) for our executable.
//
void __stdcall EntryPoint(void)
{
    HANDLE stdOutput;
    UINT   result;

    if (!resolveFuncs()) {
        return;
    }

    stdOutput = p_GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdOutput == INVALID_HANDLE_VALUE) {
        result = 1;
    } else if (!p_WriteFile(stdOutput, m_output, sizeof(m_output) - 1, NULL, NULL)) {
        result = 2;
    } else {
        // Success
        result = 0;
    }

    p_ExitProcess(result);

    // Unreachable
    __assume(0);
}
