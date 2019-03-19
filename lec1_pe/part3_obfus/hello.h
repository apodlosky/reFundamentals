//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Fuction prototypes for hello world demo.
//

#pragma once

// Returns the base pointer adjusted to the specified offset
#define RVA_TO_PTR(base, offset) ((VOID *)(((BYTE *)base) + offset))

//
// Type definitions for Windows API function pointers. It is critical
// that these definitions replicate the original function signature
// (return type, calling conventions, number of parameters and their types)
// in order for the compiler to generate proper code for calling them.
//
// Note: WinAPI functions use __stdcall calling conventions on X86 (32bit),
// which the WINAPI macro will appropriately expand to.
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
