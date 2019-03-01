//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 2, Example 2 - DLL without CRT, Ordinals Defined in .DEF
//
// Since this DLL does not make use of the C Runtime Library we will define
// our own entry point and avoid linking against the CRT.
//
// Note: this is NOT typical when developing a library because several
// features of the MSVC compiler will not be available: floating point math,
// stack security checks, and others.
//

#define BUILD_DLL
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "greeting.h"

//
// Parameters passed from SayHelloEx() to the hello-thread.
//
typedef struct {
    DWORD count;    // Number of times to prompt the user.
    DWORD delay;    // Time to delay before prompts, in milliseconds.
} HELLO_PARAMS;

// Parameters for the annoying thread
#define ANNOY_COUNT     1000
#define ANNOY_DELAY     2000

// Handle to the annoying thread created during initialization.
#ifdef ANNOYING
static HANDLE m_annoyingThread;
#endif

// Global memory heap (w/serialized access enabled)
static HANDLE m_heap;

//
// Prompts the user with a MessageBox. This function will block execution until
// the user acknowledges/closes the MessageBox.
//
__declspec(dllexport)
VOID __stdcall SayHello(VOID)
{
    MessageBox(NULL, "Hello", "World!", MB_OK);
}

//
// Prompts the user with a MessageBox the specified number of times. This
// function will block execution until the user acknowledges/closes every
// MessageBox.
//
// Parameters:
//  count - The number of times to display the prompt.
//  delay - The time to delay before prompts, in milliseconds.
//
__declspec(dllexport)
VOID __stdcall SayHelloMultiple(DWORD count, DWORD delay)
{
    while (count-- > 0) {
        Sleep(delay);
        MessageBox(NULL, "Hello", "World!", MB_OK);
    }
}

//
// Thread callback procedure to display the MessageBox(s). The thread
// procedure's parameter is a pointer to a 'HELLO_PARAMS' structure that has
// been allocated on the heap.
//
static DWORD CALLBACK helloThreadProc(LPVOID value)
{
    HELLO_PARAMS *params = (HELLO_PARAMS *)value;

    SayHelloMultiple(params->count, params->delay);

    HeapFree(m_heap, 0, params);

    return 0;
}

//
// Prompts the user with a MessageBox the specified number of times. If blocking
// is FALSE, a background thread is created and the handle to thread is provided
// to the caller.
//
// Parameters:
//  blocking  - Determines if execution is blocked to display the prompts.
//  count     - The number of times to display the prompt.
//  delay     - The time to delay before prompts, in milliseconds.
//  threadPtr - Pointer to a HANDLE to receieve the thread's handle.
//              If blocking is TRUE, this parameter is ignored and can be NULL.
//              If blocking is FALSE, this parameter CANNOT be NULL.
//
// Returns:
//  If the function succeeds, the return value is non-zero.
//  If the function fails, the return value is zero. Call GetLastError for
//  extended error information.
//
__declspec(dllexport)
BOOL __stdcall SayHelloEx(DWORD count, DWORD delay, BOOL blocking, HANDLE *threadPtr)
{
    HELLO_PARAMS *params;

    if (blocking) {
        SayHelloMultiple(count, delay);
		return TRUE;
    }

    if (threadPtr == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Allocate structure to pass parameters to our hello-thread
    params = HeapAlloc(m_heap, 0, sizeof(HELLO_PARAMS));
    if (params == NULL) {
        SetLastError(STATUS_NO_MEMORY);
        return FALSE;
    }
    params->count = count;
    params->delay = delay;

    *threadPtr = CreateThread(NULL, 0, helloThreadProc, (LPVOID)params, 0, NULL);
    if (*threadPtr == INVALID_HANDLE_VALUE) {
        DWORD saveError = GetLastError();

        // HeapFree() may alter the error-code from CreateThread()
        HeapFree(m_heap, 0, params);

        SetLastError(saveError);
        return FALSE;
    }

    return TRUE;
}

//
// Initializes features used by the library. Creates a thread that prompts
// the user repeatedly when compiled with -DANNOYING.
//
// Returns zero on failure, or non-zero on success.
//
static BOOL initialize(VOID)
{
#ifdef ANNOYING
    m_annoyingThread = INVALID_HANDLE_VALUE;
#endif

    // Create heap: serialized, 1 page initial, and growable
    m_heap = HeapCreate(0, 0, 0);
    if (m_heap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

#ifdef ANNOYING
    // Start the annoying thread
    SayHelloEx(ANNOY_COUNT, ANNOY_DELAY, FALSE, &m_annoyingThread);
#endif

    return TRUE;
}

//
// Finalizes the library before unloading.
//
// Note: If initialization fails (i.e. if initialize() returns FALSE on
// DLL_PROCESS_ATTACH), the DLL_PROCESS_DETACH is still sent before unloading.
//
static VOID finalize(VOID)
{
#ifdef ANNOYING
    if (m_annoyingThread != INVALID_HANDLE_VALUE) {
        // This is a very heavy-handed approach to stopping a thread,
        // notifying the thread with an event would be much cleaner.
        // Avoid doing this in the real world.
        TerminateThread(m_annoyingThread, 1);
        CloseHandle(m_annoyingThread);
    }
#endif

    // Remove our heap before being unloaded
    if (m_heap != INVALID_HANDLE_VALUE) {
        HeapDestroy(m_heap);
    }
}

//
// Entry point for the library.
//
BOOL __stdcall EntryPoint(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // Disable thread attach/detatch notifications
            DisableThreadLibraryCalls(instance);

            return initialize();

        case DLL_PROCESS_DETACH:
            finalize();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Thread notifications are disabled
            break;
    }

    return TRUE;
}
