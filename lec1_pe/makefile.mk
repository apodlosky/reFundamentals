#
# reFundamentals
# Copyright (c) 2019 Adam Podlosky
#
# Makefile for Microsoft NMAKE
#
# Usage:
#   nmake -f makefile.mk all [options]
#
# Options:
#   DEBUG=0/1  - Toggle debug/release builds
#   STATIC=0/1 - Toggle static runtime
#

# Build directories
P1_DIR      = ./part1_intro
P2_DIR      = ./part2_dll
P3_DIR      = ./part3_obfus
P4_DIR      = ./part4_infect
OUT_DIR     = ./build

# Build tools
AS          = ml.exe
CC          = cl.exe
LD          = link.exe
RC          = rc.exe

# Build flags
AFLAGS      = /nologo /c /coff /W3
CFLAGS      = /nologo /c /W4
LFLAGS      = /nologo
RFLAGS      = /nologo /r

DEPENDS     = kernel32.lib user32.lib
ENTRY       = EntryPoint

!ifndef DEBUG
DEBUG  = 0
!endif

!ifndef STATIC
STATIC = 1
!endif

!message [*] reFundamentals

!if $(DEBUG)
!message [-]  Build Type: Debug
AFLAGS      = $(AFLAGS) /Zi
CFLAGS      = $(CFLAGS) /Zi
LFLAGS      = $(LFLAGS) /DEBUG
OUT_DIR     = $(OUT_DIR)-dbg
!else
!message [-]  Build Type: Release
AFLAGS      = $(AFLAGS)
CFLAGS      = $(CFLAGS) /Os
LFLAGS      = $(LFLAGS) /DEBUG:NONE /RELEASE
OUT_DIR     = $(OUT_DIR)-rls
!endif

LFLAGS       = $(LFLAGS) $(DEPENDS)
CFLAGS_NOCRT = $(CFLAGS) /GS-
LFLAGS_NOCRT = $(LFLAGS) /ENTRY:$(ENTRY) /INCREMENTAL:NO /NODEFAULTLIB $(DEPENDS)

!if $(STATIC)
!message [-] Runtime Lib: Static
!if $(DEBUG)
CFLAGS      = $(CFLAGS) /MTd
!else
CFLAGS      = $(CFLAGS) /MT
!endif
OUT_DIR     = $(OUT_DIR)-stc
!else
!message [-] Runtime Lib: Dynamic
!if $(DEBUG)
CFLAGS      = $(CFLAGS) /MDd
!else
CFLAGS      = $(CFLAGS) /MD
!endif
OUT_DIR     = $(OUT_DIR)-dyn
!endif

!message [-]  Output Dir: $(OUT_DIR)

default: all

all: part1 part2 part3 part4

setup:
    @IF NOT EXIST "$(OUT_DIR)" MKDIR "$(OUT_DIR)"

part1: setup \
        "$(OUT_DIR)/empty.exe" \
        "$(OUT_DIR)/hello.exe" \
        "$(OUT_DIR)/hello_msgbox.exe" \
        "$(OUT_DIR)/hello_winapi_nocrt.exe"
    @ECHO [-] Finished building part 1

part2: setup \
        "$(OUT_DIR)/annoying.dll" \
        "$(OUT_DIR)/greeting.dll" \
        "$(OUT_DIR)/nullpad.exe"
    @ECHO [-] Finished building part 2

part3: setup \
        "$(OUT_DIR)/hello_getproc.exe" \
        "$(OUT_DIR)/hello_modenum.exe" \
        "$(OUT_DIR)/hello_stealth.exe"
    @ECHO [-] Finished building part 3

part4: setup \
        "$(OUT_DIR)/infector.exe"
    @ECHO [-] Finished building part 4

distclean:
    @ECHO [-] Deleting intermediate files
    -@DEL /F "$(OUT_DIR)\*.exp" 2> nul
    -@DEL /F "$(OUT_DIR)\*.ilk" 2> nul
    -@DEL /F "$(OUT_DIR)\*.lib" 2> nul
    -@DEL /F "$(OUT_DIR)\*.map" 2> nul
    -@DEL /F "$(OUT_DIR)\*.obj" 2> nul
    -@DEL /F "$(OUT_DIR)\*.pdb" 2> nul
    -@DEL /F "$(OUT_DIR)\*.res" 2> nul

clean: distclean
    @ECHO [-] Deleting executable files
    -@DEL /F "$(OUT_DIR)\*.dll" 2> nul
    -@DEL /F "$(OUT_DIR)\*.exe" 2> nul
    -@DEL /F "$(OUT_DIR)\*.lib" 2> nul

#
# Part 1 build rules
#

"$(OUT_DIR)/empty.obj": "$(P1_DIR)/empty.c"
    @$(CC) $(CFLAGS) /Fo$@ $**

"$(OUT_DIR)/empty.exe": "$(OUT_DIR)/empty.obj"
    @$(LD) $(LFLAGS) /NODEFAULTLIB /ENTRY:empty /SUBSYSTEM:console /OUT:$@ $**

"$(OUT_DIR)/hello.obj": "$(P1_DIR)/hello.c"
    @$(CC) $(CFLAGS) /Fo$@ $**

"$(OUT_DIR)/hello.exe": "$(OUT_DIR)/hello.obj"
    @$(LD) $(LFLAGS) /OUT:$@ $**

"$(OUT_DIR)/hello_msgbox.obj": "$(P1_DIR)/hello_msgbox.c"
    @$(CC) $(CFLAGS) /Fo$@ $**

"$(OUT_DIR)/hello_msgbox.exe": "$(OUT_DIR)/hello_msgbox.obj"
    @$(LD) $(LFLAGS) /OUT:$@ $**

"$(OUT_DIR)/hello_winapi_nocrt.obj": "$(P1_DIR)/hello_winapi_nocrt.c"
    @$(CC) $(CFLAGS_NOCRT) /Fo$@ $**

"$(OUT_DIR)/hello_winapi_nocrt.exe": "$(OUT_DIR)/hello_winapi_nocrt.obj"
    @$(LD) $(LFLAGS_NOCRT) /SUBSYSTEM:console /OUT:$@ $**

#
# Part 2 build rules
#

"$(OUT_DIR)/annoying.obj": "$(P2_DIR)/greeting.c"
    @$(CC) $(CFLAGS_NOCRT) /DANNOYING=1 /Fo$@ $**

"$(OUT_DIR)/annoying.dll": "$(OUT_DIR)/annoying.obj"
    @$(LD) $(LFLAGS_NOCRT) /SUBSYSTEM:windows /DLL "/DEF:$(P2_DIR)/greeting.def" /OUT:$@ $**

"$(OUT_DIR)/greeting.obj": "$(P2_DIR)/greeting.c"
    @$(CC) $(CFLAGS_NOCRT) /Fo$@ $**

"$(OUT_DIR)/greeting.dll": "$(OUT_DIR)/greeting.obj"
    @$(LD) $(LFLAGS_NOCRT) /SUBSYSTEM:windows /DLL "/DEF:$(P2_DIR)/greeting.def" /OUT:$@ $**

"$(OUT_DIR)/nullpad.obj": "$(P2_DIR)/nullpad.c"
    @$(CC) $(CFLAGS) /Fo$@ $**

"$(OUT_DIR)/nullpad.res": "$(P2_DIR)/nullpad.rc"
    $(RC) $(RFLAGS) /fo$@ $**

"$(OUT_DIR)/nullpad.exe": "$(OUT_DIR)/nullpad.obj" "$(OUT_DIR)/nullpad.res"
    @$(LD) $(LFLAGS) /OUT:$@ $**

#
# Part 3 build rules
#

"$(OUT_DIR)/hello_getproc.obj": "$(P3_DIR)/hello_getproc.c"
    @$(CC) $(CFLAGS_NOCRT) /Fo$@ $**

"$(OUT_DIR)/hello_getproc.exe": "$(OUT_DIR)/hello_getproc.obj"
    @$(LD) $(LFLAGS_NOCRT) /SUBSYSTEM:console /OUT:$@ $**

"$(OUT_DIR)/hello_modenum.obj": "$(P3_DIR)/hello_modenum.c"
    @$(CC) $(CFLAGS_NOCRT) /Fo$@ $**

"$(OUT_DIR)/hello_modenum.exe": "$(OUT_DIR)/hello_modenum.obj"
    @$(LD) $(LFLAGS_NOCRT) psapi.lib /SUBSYSTEM:console /OUT:$@ $**

"$(OUT_DIR)/hello_stealth.obj": "$(P3_DIR)/hello_stealth.c"
    @$(CC) $(CFLAGS_NOCRT) /Fo$@ $**

"$(OUT_DIR)/hello_stealth.exe": "$(OUT_DIR)/hello_stealth.obj"
    @$(LD) $(LFLAGS_NOCRT) /SUBSYSTEM:console /FIXED /EMITPOGOPHASEINFO /OUT:$@ $**

#
# Part 4 build rules
#

"$(OUT_DIR)/infector.obj": "$(P4_DIR)/infector.c"
    @$(CC) $(CFLAGS) /Fo$@ $**

"$(OUT_DIR)/infector.exe": "$(OUT_DIR)/infector.obj"
    @$(LD) $(LFLAGS) /OUT:$@ $**
