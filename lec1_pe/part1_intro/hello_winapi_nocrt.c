//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 1, Example 4 - Windows API without CRT
//
// Write to standard output using only the Windows API. Previous example used
// C Runtime Library (CRT) functions (printf, implemented with open, write, close).
//
// Since we are using the WinAPI exclusively, we will define our own entry
// function and instruct the linker using /ENTRY to set this function as the
// PE's entry point.
//
// Note: this is NOT typical when developing a application because several
// features of the MSVC compiler will not be available: floating point math,
// stack security checks, and others.
//
// GetStdHandle and WriteFile:
// https://docs.microsoft.com/en-us/windows/console/getstdhandle
// https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-writefile
//
// Linker options, /ENTRY:
// https://docs.microsoft.com/en-us/cpp/build/reference/linker-options
// https://docs.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char m_output[] = "hello, world\n";

//
// Application entry function (PE entry point).
//
void __stdcall EntryPoint(void)
{
    HANDLE stdOutput;
    UINT   result;

    stdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdOutput == INVALID_HANDLE_VALUE) {
        result = 1;
    } else if (!WriteFile(stdOutput, m_output, sizeof(m_output) - 1, NULL, NULL)) {
        result = 2;
    } else {
        // All good!
        result = 0;
    }

    ExitProcess(result);

    // Inform compiler this code is unreachable
    __assume(0);
}
