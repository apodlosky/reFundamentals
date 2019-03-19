//
// reFundamentals
// Copyright (c) 2019 Adam Podlosky
//
// Types for infector demo.
//

#pragma once

#pragma warning(disable: 4201) // C4201: nonstandard extension

#include "queue.h"

// Aligns the given value
#define ALIGN4(n) (((n) + 3) & ~3)
#define ALIGN8(n) (((n) + 7) & ~7)

// Dummy value for OEP place holder
#define OEP_DUMMY32     0xDDDDDDDD
#define OEP_DUMMY64     0xDDDDDDDDDDDDDDDD

#ifdef _WIN64
#define OEP_DUMMY       OEP_DUMMY64
#else
#define OEP_DUMMY       OEP_DUMMY32
#endif

// Marker offset (bytes) and value for infected executables
#define MARKER_OFFSET   0x30 // unused space
#define MARKER_VALUE    0xDEADDEAD

// Returns the base pointer adjusted to the specified offset
#define RVA_TO_PTR(base, offset) ((VOID *)(((BYTE *)base) + offset))

//
// Copy of code stub.
//
typedef struct {
    BOOL        is64;       // Flag indicates if stub is 64bit
    VOID        *code;      // Pointer to the code
    SIZE_T      length;     // Length of the code stub
    union {
        UINT32  *dummy32;   // Pointer to the OEP placeholder (32-bit)
        UINT64  *dummy64;   // Pointer to the OEP placeholder (64-bit)
    };
} INFECT_STUB;

//
// Mapped file data.
//
typedef struct {
    HANDLE      file;       // Handle to the file (read, write)
    HANDLE      map;        // File mapping handle (full access)
    VOID        *view;      // View of mapping (in process address space)
    SIZE_T      size;       // Size of the file mapping
} MAPPED_FILE;

//
// Pointers to PE headers in the mapped file.
//
typedef struct {
    BOOL                    is64;       // Flag indicates if PE is 64bit
    IMAGE_DOS_HEADER        *dos;       // Pointer to the DOS header
    union {
        IMAGE_NT_HEADERS32  *nt32;      // Pointer to the NT header (32-bit)
        IMAGE_NT_HEADERS64  *nt64;      // Pointer to the NT header (64-bit)
    };
    IMAGE_FILE_HEADER       *file;      // Pointer to the file header
    IMAGE_SECTION_HEADER    *section;   // Pointer to the first section header
} PE_HEADERS;

//
// Maximum number of sections allowed has varied between releases:
//  Windows XP and prior: 96
//  Windows Vista and up: 65535
//
#define PE_MAX_SECTIONS     96

//
// Code cave entry.
//
typedef struct _PE_CAVE_ENTRY {
    TAILQ_ENTRY(_PE_CAVE_ENTRY) link; // TailQ list structure
    SIZE_T               offset;    // File offset of start of the code cave
    SIZE_T               length;    // Length of code cave, in bytes
    IMAGE_SECTION_HEADER *section;  // Section the cave belongs to
    BOOL                 isData;    // Indicates if within a data section
    BOOL                 isExec;    // Indicates if within a executable section
} PE_CAVE_ENTRY;

//
// List of code cave entries.
//
typedef struct _PE_CAVE_LIST PE_CAVE_LIST;
TAILQ_HEAD(_PE_CAVE_LIST, _PE_CAVE_ENTRY);
