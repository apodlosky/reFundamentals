//
// Copyright (c) Alex Ionescu.  All rights reserved.
//
// Crudely copied from:
// https://doxygen.reactos.org/d2/d3d/peb__teb_8h_source.html
// https://doxygen.reactos.org/d1/d97/ldrtypes_8h_source.html
// https://doxygen.reactos.org/d5/df7/ndk_2rtltypes_8h_source.html
//
// Internal Windows Structures
//
// Version: should be XP and newer (untested)
//

#pragma once

#pragma warning(disable: 4201) // C4201: nonstandard extension

//
// Strings
//

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//
// Critical Sections
//

// defined in winnt.h
#if 0
typedef struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    PRTL_CRITICAL_SECTION CriticalSection;
    LIST_ENTRY ProcessLocksList;
    ULONG EntryCount;
    ULONG ContentionCount;
    ULONG Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    PVOID OwningThread;
    PVOID LockSemaphore;
    ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#endif

//
// Client ID
//

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//
// Current Dir
//

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//
// Exceptions
//

// defined in excpt.h
#if 0
typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION;
#endif

// defined in winnt.h
#if 0
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_DISPOSITION Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
#endif

//
// Loader Data
//

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

//
// Process Environment Block (PEB)
//

#ifdef _WIN64
#define GDI_HANDLE_BUFFER_SIZE 60
#else
#define GDI_HANDLE_BUFFER_SIZE 34
#endif

typedef struct _PEB_FREE_BLOCK {
    struct _PEB_FREE_BLOCK *Next;
    ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG SpareUlong; // AtlThunkSListPtr32
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG_PTR HeapSegmentReserve;
    ULONG_PTR HeapSegmentCommit;
    ULONG_PTR HeapDeCommitTotalFreeThreshold;
    ULONG_PTR HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    PVOID MinimumStackCommit;
 } PEB, *PPEB;

//
// Thread Information Block (TIB)
//

// defined in winnt.h
#if 0
typedef struct _NT_TIB {
    PEXCEPTION_REGISTRATION_RECORD ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        ULONG Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB, *PNT_TIB;
#endif

//
// Thread Environment Block (TEB)
//

// winternl.h version
#if 0
typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
    PVOID Reserved2[399];
    BYTE Reserved3[1952];
    PVOID TlsSlots[64];
    BYTE Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;  // Windows 2000 only
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} TEB, *PTEB;
#endif

 typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PVOID ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID Reserved2[399]; // very incomplete but TEB changes more often
    BYTE Reserved3[1944];
    PVOID TlsSlots[64];
    BYTE Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} TEB, *PTEB;

//
// Function: GetTIB
//
// Retrieves a pointer to the Thread Information Block (TIB).
//
__forceinline NT_TIB *GetTIB(VOID)
{
    //
    // Use compiler intrinsic functions to access FS/GS registers since the
    // MSVC X64 compiler removed support for inline assembly.
    //
#if defined(_M_IX86)
    // mov eax, fs:0x0
    return (NT_TIB *)__readfsdword(0x0);
#elif defined(_M_X64)
    // mov rax, gs:0x0
    return (NT_TIB *)__readgsqword(0x0);
#else
#error unsupported architecture
#endif
}

//
// Function: GetTEB
//
// Retrieves a pointer to the Thread Environment Block (TEB).
//
__forceinline TEB *GetTEB(VOID)
{
#if defined(_M_IX86)
    // mov eax, fs:0x18
    return (TEB *)__readfsdword(0x18);
#elif defined(_M_X64)
    // mov rax, gs:0x30
    return (TEB *)__readgsqword(0x30);
#else
#error unsupported architecture
#endif
}

//
// Function: GetPEB
//
// Retrieves a pointer to the Process Environment Block (PEB).
//
__forceinline PEB *GetPEB(VOID)
{
#if defined(_M_IX86)
    // mov eax, fs:0x30
    return (PEB *)__readfsdword(0x30);
#elif defined(_M_X64)
    // mov rax, gs:0x60
    return (PEB *)__readgsqword(0x60);
#else
#error unsupported architecture
#endif
}

//
// Offset verifcations
//

#ifdef _WIN64
C_ASSERT(FIELD_OFFSET(PEB, Mutant) == 0x08);
C_ASSERT(FIELD_OFFSET(PEB, Ldr) == 0x18);
C_ASSERT(FIELD_OFFSET(PEB, FastPebLock) == 0x038);
C_ASSERT(FIELD_OFFSET(PEB, TlsExpansionCounter) == 0x070);
C_ASSERT(FIELD_OFFSET(PEB, NtGlobalFlag) == 0x0BC);
C_ASSERT(FIELD_OFFSET(PEB, GdiSharedHandleTable) == 0x0F8);
C_ASSERT(FIELD_OFFSET(PEB, LoaderLock) == 0x110);
C_ASSERT(FIELD_OFFSET(PEB, ImageSubsystem) == 0x128);
C_ASSERT(FIELD_OFFSET(PEB, ImageProcessAffinityMask) == 0x138);
C_ASSERT(FIELD_OFFSET(PEB, PostProcessInitRoutine) == 0x230);
C_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x2C0);
#else
C_ASSERT(FIELD_OFFSET(PEB, Mutant) == 0x04);
C_ASSERT(FIELD_OFFSET(PEB, Ldr) == 0x0C);
C_ASSERT(FIELD_OFFSET(PEB, FastPebLock) == 0x01C);
C_ASSERT(FIELD_OFFSET(PEB, TlsExpansionCounter) == 0x03C);
C_ASSERT(FIELD_OFFSET(PEB, NtGlobalFlag) == 0x068);
C_ASSERT(FIELD_OFFSET(PEB, GdiSharedHandleTable) == 0x094);
C_ASSERT(FIELD_OFFSET(PEB, LoaderLock) == 0x0A0);
C_ASSERT(FIELD_OFFSET(PEB, ImageSubsystem) == 0x0B4);
C_ASSERT(FIELD_OFFSET(PEB, ImageProcessAffinityMask) == 0x0C0);
C_ASSERT(FIELD_OFFSET(PEB, PostProcessInitRoutine) == 0x14C);
C_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x1D4);
#endif

#ifdef _WIN64
C_ASSERT(FIELD_OFFSET(TEB, NtTib) == 0x000);
C_ASSERT(FIELD_OFFSET(TEB, EnvironmentPointer) == 0x038);
C_ASSERT(FIELD_OFFSET(TEB, ProcessEnvironmentBlock) == 0x60);
C_ASSERT(FIELD_OFFSET(TEB, TlsExpansionSlots) == 0x1780);
#else
C_ASSERT(FIELD_OFFSET(TEB, NtTib) == 0x000);
C_ASSERT(FIELD_OFFSET(TEB, EnvironmentPointer) == 0x01C);
C_ASSERT(FIELD_OFFSET(TEB, ProcessEnvironmentBlock) == 0x30);
C_ASSERT(FIELD_OFFSET(TEB, TlsExpansionSlots) == 0xF94);
#endif
