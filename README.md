# reFundamentals

Lecture series on reverse engineering and malware analysis fundamentals.

## Directories

  * lec1_pe - Introduction to the Portable Executable (PE) format

  * lec2_win - Introduction to the Windows API, memory, and processes

  * lec3_???

## Binaries

Binaries are provided, they are stored in password-protected ZIP files to
avoid triggering false-positive warnings from anti-virus software.

Password for all ZIP files is the usual: **infected**

Even though these binaries are safe, please get in the habit of analyzing them
from a safe virtual environment.

## Resources

See **RESOURCES.md** for a list of articles, books, useful tools, and more.

## Building

Sources can be compiled using the provided makefile with Microsoft NMake. To
setup the build environment, use the *x86 Native Tools Command Prompt for VS*
shortcut provided with a Microsoft Visual Studio installation.

Requirements:
 * Microsoft Platform SDK v7 or newer
 * Microsoft Visual Studio C++ 2015 or 2017
 * Only tested on x86

## License

See **LICENSE** file for terms and conditions. Contents of this repository is
licensed under a simplified BSD (2-clause) license.
