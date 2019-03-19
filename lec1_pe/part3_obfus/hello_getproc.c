//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 2, Example 1 - GetProcAddress to Resolve WinAPIs
//
// To further obscure the nature of our application purpose, we will resolve
// (almost) all of our imports dynamically at runtime using the LoadLibrary and
// GetProcAddress functions. Thus, removing those function names from our PE's
// import address table (IAT).
//
// GetModuleHandle, LoadLibrary and GetProcAddress:
// https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-getmodulehandlea
// https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-loadlibrarya
// https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-getprocaddress
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "hello.h"

// Buffer to display to the console
static const char m_output[] = "hello, world\n";

// Pointers to our resolved kernel32.dll functions
static PFN_GETSTDHANDLE  p_GetStdHandle;
static PFN_WRITEFILE     p_WriteFile;
static PFN_EXITPROCESS   p_ExitProcess;

//
// Dynamically resolves functions from the kernel32.dll library on runtime
// using LoadLibrary() and GetProcAddress().
//
// Returns 0 (FALSE) on failure, or non-zero (TRUE) on success.
//
static BOOL resolveFuncs(VOID)
{
    HMODULE module;

    // kernel32 should be mapped into our address space
    module = GetModuleHandleA("kernel32");
    if (module == NULL) {
        // Load if not
        module = LoadLibraryA("kernel32.dll");
        if (module == NULL) {
            return FALSE;
        }
    }

    // Locates the given function names in the library's export directory
    // and returns a pointer to the address of the function. GetProcAddress
    // returns NULL on failure (i.e. could not locate the given function name).

    p_GetStdHandle = (PFN_GETSTDHANDLE)GetProcAddress(module, "GetStdHandle");
    if (p_GetStdHandle == NULL) {
        return FALSE;
    }

    p_WriteFile = (PFN_WRITEFILE)GetProcAddress(module, "WriteFile");
    if (p_WriteFile == NULL) {
        return FALSE;
    }

    p_ExitProcess = (PFN_EXITPROCESS)GetProcAddress(module, "ExitProcess");
    if (p_ExitProcess == NULL) {
        return FALSE;
    }

    // Normally, FreeLibrary() should be called when finished with a given
    // library because libraries are reference counted by the Loader. However,
    // we will require access to these functions for the entirety of this
    // application's execution.

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

    // Call the 'p_' pointers to our dynamically resolved WinAPI functions
    stdOutput = p_GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdOutput == INVALID_HANDLE_VALUE) {
        result = 1;
    } else if (!p_WriteFile(stdOutput, m_output, sizeof(m_output) - 1, NULL, NULL)) {
        result = 2;
    } else {
        // All good!
        result = 0;
    }

    p_ExitProcess(result);

    // Unreachable
    __assume(0);
}
