//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// When compiling the DLL, BUILD_DLL must be defined before including
// this header.
//
// When linking against this DLL, simply include this header file.
//

#pragma once

#ifdef BUILD_DLL
#define IMPEXP __declspec(dllexport) // mark function for export
#else
#define IMPEXP __declspec(dllimport) // mark function for import
#endif

IMPEXP VOID __stdcall SayHello(VOID);

IMPEXP VOID __stdcall SayHelloMultiple(DWORD count, DWORD delay);

IMPEXP BOOL __stdcall SayHelloEx(DWORD count, DWORD delay, BOOL blocking, HANDLE *threadPtr);
