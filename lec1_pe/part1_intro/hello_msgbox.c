//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 1, Example 3 - MessageBox from WinMain
//
// As previously stated, WinMain does not create the usual console handles -
// so we will use MessageBox() to greet the user, graphically.
//
// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-messagebox
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning(disable: 4100) // C4100: unreferenced formal parameter

//
// Entry point for a graphical Windows-based application.
//
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PTSTR pCmdLine, int nCmdShow)
{
    MessageBox(NULL, "Hello", "World!", MB_OK);

    return 0;
}
