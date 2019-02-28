
# Resources

## YegSec - Edmonton Security Meet-up

 - Monthly talks, hosted at *Start-up Edmonton*
 - Friendly and knowledgeable group of InfoSec professionals
 - Students with a passion for security are always welcome
 - https://www.yegsec.ca/

## Books and Guides

Selection of books and online resources that I have found useful.

### Where to Begin

 - @hasherezade's guide to getting started
  - https://hshrzd.wordpress.com/how-to-start/

 - @malwaretech's guide to setting up a VM
  - https://www.malwaretech.com/2017/11/creating-a-simple-free-malware-analysis-environment.html


## Demos and Practice Labs

- Reverse Engineering for Beginners by @ophirharpaz
 - https://www.begin.re/

 - Reverse Engineering Workshops by @malwareunicorn
    - http://malwareunicorn.org/

 - OpenAnalysis and OpenAnalysis Live by @herrcore and @seanmw
    - https://www.openanalysis.net/
    - https://www.youtube.com/channel/UC--DwaiMV-jtO-6EvmKOnqg


### Assembly

 - **Assembly Language for X86 Processor** by Kip Irvine ([Amazon.ca](https://www.amazon.ca/Assembly-Language-x86-Processors-7th/dp/0133769402/))

 > Great start for learning x86 assembly

 - **Professional Assembly Language** (2005) by Richard Blum ([Amazon.ca](https://www.amazon.ca/Professional-Assembly-Language-Richard-Blum/dp/0764579010/))

 > A little dated now

 - **Compiler Explorer** (https://godbolt.org/)

 > Online, real-time C compilers (clang, gcc, MSVC) to generate assembler output for x86, x64, and ARM

 - **x86 and amd64 instruction reference** (https://www.felixcloutier.com/x86/)

 > Easily accessible reference parsed from the Intel Software Development manuals

 - **Intel Software Developer Manuals** (https://software.intel.com/en-us/articles/intel-sdm)

 > Very lengthy but the definitive resource on Intel IA-32/64 architecture


### Reverse Engineering

 - **Reversing: Secrets of Reverse Engineering** (2005) by Eldad Eilam ([Amazon.ca](https://www.amazon.ca/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817/))

 > Introduction to reverse engineering, somewhat outdated now

 - **Practical Malware Analysis** (2012) by Michael Sikorski and Andrew Honig ([Amazon.ca](https://www.amazon.ca/Practical-Malware-Analysis-Hands-Dissecting/dp/1593272901/))

 > Excellent starting point for reverse engineering malware

 - **Practical Reverse Engineering** (2014) by Bruce Dang, et al. ([Amazon.ca](https://www.amazon.ca/Practical-Reverse-Engineering-Reversing-Obfuscation/dp/1118787315/))

 > More advanced, great follow-up after reading Practical Malware Analysis

 - **The IDA Pro Book** (2012, 2nd edition) by Chris Eagle ([Amazon.ca](https://www.amazon.ca/IDA-Pro-Book-Unofficial-Disassembler/dp/1593272898/))

 > Outstanding guide to learning IDA Pro


### Microsoft Windows

 - **Windows System Programming** (2010, 4th edition) by Johnson Hart ([Amazon.ca](https://www.amazon.ca/Windows-System-Programming-Johnson-Hart/dp/0321657748/))

 > Introduction to programming using the Windows API

 - **Windows Internals, Part 1** (7th edition) ([Amazon.ca](https://www.amazon.ca/Windows-Internals-Part-architecture-management/dp/0735684189/))

 > Architecture of the Microsoft Windows operating systems

 - **Windows Internals, Part 2** (6th edition) ([Amazon.ca](https://www.amazon.ca/Windows-Internals-Part-2-6th/dp/0735665877/))

 > Continued, more of a reference for developers

 - **Troubleshooting with the Windows Sysinternals Tools** (2nd edition) ([Amazon.ca](https://www.amazon.ca/Troubleshooting-Windows-Sysinternals-Tools-2nd/dp/0735684448/))

 > Using the Sysinternals tools suite for analyzing applications and the system

 - **NT Internals** (http://undocumented.ntinternals.net/)

 > Documented internal Windows functions and data structures, somewhat outdated

 - **ReactOS** (https://reactos.org/)

 > Open-souce, binary-compatible, reimplementation of the Microsoft Windows operating system
 > Reading the source code is an excellent insight in how Windows works


### Other

 - **The Art of Unpacking** (2007) by Mark Vincent Yason
    - Excellent resource for unpacking executables
    - https://www.blackhat.com/presentations/bh-usa-07/Yason/Whitepaper/bh-usa-07-yason-WP.pdf

 - **The Ultimate Anti-Debug Reference** (2011) by Peter Ferrie
    - Overview of techniques used to detect the presence a debugger
    - https://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf

 - **CyberChef** (https://gchq.github.io/CyberChef/)


## Virtual Environment

    It should go without saying, that analyzing malware on your computer's native
operating system could go terribly wrong. Instead, malware analysis is usually
done from an operating system running as a virtual machine. If the hypervisor
and virtual machine are configured properly (disabling sharing, etc.) you can
achieve a reasonable level of security and separation. However, software will
always have bugs...and with bugs often come vulnerablities.

Popular Hypervisors:

 - **Sun VirtualBox** (https://www.virtualbox.org/)
   - Freeware and multi-platform support
   - Very commonly used, lots of resources for locking down VMs

 - **Microsoft Hyper-V**
   - Included with the professional and server editions of Microsoft Windows

 - **VMware Fusion** (https://www.vmware.com/ca/products/fusion.html)
   - Commercial and MacOSX only

 - **VMware Workstation** (https://www.vmware.com/ca/products/workstation-pro.html)
   - Commercial and Windows/Linux only

Virtual Machine Images:

 - Microsoft provides several free, pre-installed virtual machine images
   (90 day trials) to web developers for testing.
 - Many malware analysis hobbyists use these images.
 - https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/


## Tools

    There are endless numbers of tools and scripts available to reverse
engineers, this is a selection of the more common ones that I use.

### Cutter / Radare2
 - Diassembler, debugger, and decompiler for many architectures
 - Open-source and multi-platform
 - https://github.com/radareorg/cutter

### HxD
 - Excellent hex editor
 - Freeware for Windows
 - https://mh-nexus.de/en/hxd/

### IDA
 - Diassembler, debugger, and decompiler for many architectures (licensing required)
 - Commercial ($$$$) and multi-platform
 - Free version available, but limited to x86 (32bit) PE, ELF, and Mach-O binaries
 - https://www.hex-rays.com/products/ida/

### PE-Bear
 - Excellent PE analysis tool by @hasherezade
 - Freeware (partially open-source) and multi-platform
 - https://hshrzd.wordpress.com/pe-bear/
 - https://github.com/hasherezade/ (check out her other projects as well)

### pd - Process Dump
 - Process dumping, works well with malware that often require more IAT rebuilding
 - http://split-code.com/processdump.html
 - https://github.com/glmcdona/Process-Dump

### Process Hacker
 - Powerful process monitor for Windows, useful for monitoring malware
 - https://processhacker.sourceforge.io/

### Scylla
 - Process dumping and import reconstruction
 - https://github.com/NtQuery/Scylla

### Sysinternals
 - Tools for troubleshooting and monitoring Windows sytems and applications
 - https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

### x64dbg
 - Excellent assembly-level debugger (an improved Olly :-))
 - https://x64dbg.com/
 - https://github.com/x64dbg/x64dbg/releases

### WinDbg
 - Microsoft Windows debugger, bit of steep learning curve but powerful
 - https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/
