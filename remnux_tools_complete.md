# REMnux Command-Line Tools — Complete Reference with Examples

> **Source**: [docs.remnux.org](https://docs.remnux.org) | Compiled June 2026  
> REMnux is a Linux toolkit for reverse-engineering and analyzing malicious software, based on Ubuntu.

---

## Table of Contents
1. [Examine Static Properties](#1-examine-static-properties)
2. [Statically Analyze Code](#2-statically-analyze-code)
3. [Dynamically Reverse-Engineer Code](#3-dynamically-reverse-engineer-code)
4. [Perform Memory Forensics](#4-perform-memory-forensics)
5. [Explore Network Interactions](#5-explore-network-interactions)
6. [Investigate System Interactions](#6-investigate-system-interactions)
7. [Analyze Documents](#7-analyze-documents)
8. [Gather and Analyze Data](#8-gather-and-analyze-data)
9. [General Utilities](#9-general-utilities)

---

## 1. Examine Static Properties

### 1.1 General File Analysis

---

#### `file`
Identify file type using "magic" numbers.

```bash
file malware.exe
file -i malware.bin           # Show MIME type
file *                        # Check all files in directory
file -k malware.exe           # Keep going (show all matches)
```

---

#### `trid` / `tridupdate`
Identify file type using a large database of file signatures.

```bash
trid malware.bin              # Identify file type
trid malware.bin -ce          # Show confidence values
tridupdate                    # Update signature database
```

---

#### `magika`
Google's AI-powered file type identification tool.

```bash
magika malware.bin            # Identify file type
magika --json malware.bin     # JSON output
magika -r /samples/           # Recursively scan directory
magika --no-dereference *.bin # Scan multiple files
```

---

#### `diec` (Detect-It-Easy CLI)
Detect file type, compiler, packer, and protections.

```bash
diec malware.exe              # Basic detection
diec -i malware.exe           # Show detailed info
diec -j malware.exe           # JSON output
diec -r /samples/             # Recursive directory scan
diec --all malware.exe        # Show all detections
```

---

#### `exiftool`
Read, write, and edit metadata across many file types.

```bash
exiftool malware.exe                  # Show all metadata
exiftool -j malware.exe               # JSON output
exiftool -csv *.exe                   # CSV output for multiple files
exiftool -FileType malware.exe        # Show just the file type
exiftool -CompileDate malware.exe     # Show compile date
exiftool -a malware.exe               # Show duplicate tags
exiftool -X malware.exe               # XML output
```

---

#### `ssdeep`
Compute fuzzy hashes (Context Triggered Piecewise Hashing) for similarity matching.

```bash
ssdeep malware.exe                        # Compute fuzzy hash
ssdeep -r /samples/                       # Hash all files recursively
ssdeep -m known_hashes.txt unknown.exe    # Match against known hashes
ssdeep -la /samples/                      # List and compare all in directory
ssdeep -t 30 -m hashes.txt sample.exe    # Match with threshold of 30%
```

---

#### `yara-rules`
Scan a file using the pre-installed community YARA rules (packer, anti-debug, networking detection).

```bash
yara-rules malware.exe        # Scan file with all bundled rules
yara-forge malware.exe        # Scan for malware family identification
```

---

#### `yara`
Run custom or built-in YARA rules against files.

```bash
yara rules.yar malware.exe            # Scan with a rule file
yara -r rules.yar /samples/           # Recursive scan
yara -s rules.yar malware.exe         # Show matching strings
yara -m rules.yar malware.exe         # Print module data
yara -g rules.yar malware.exe         # Print tags
yara rules/ malware.exe               # Use rules directory
```

---

#### `yr` (YARA-X)
Next-generation YARA written in Rust.

```bash
yr scan rules.yar malware.exe         # Scan with rule file
yr scan rules/ malware.exe            # Scan with rules directory
yr compile rules.yar -o rules.yarc    # Compile rules
yr scan rules.yarc malware.exe        # Scan with compiled rules
```

---

#### `bulk_extractor`
Extract strings, emails, URLs, credit card numbers, and other artifacts from binary files.

```bash
bulk_extractor -o output/ malware.exe         # Extract to output dir
bulk_extractor -o output/ disk.img            # Extract from disk image
bulk_extractor -e email -o out/ sample.exe    # Extract only emails
bulk_extractor -e net -o out/ capture.pcap    # Extract network artifacts
bulk_extractor -R /samples/ -o out/           # Recursive scan
```

---

#### `strings.py` (Didier Stevens)
Extract strings with more control than standard `strings`.

```bash
strings.py malware.exe                        # Extract ASCII & Unicode strings
strings.py -n 8 malware.exe                   # Minimum length 8
strings.py -u malware.exe                     # Unicode strings only
strings.py malware.exe | sort | uniq          # Deduplicate
```

---

#### `re-search.py`
Search file for common suspicious patterns using built-in regex library (IPs, URLs, registry keys, etc.).

```bash
re-search.py -n ipv4 malware.exe              # Search for IPv4 addresses
re-search.py -n url malware.exe               # Search for URLs
re-search.py -n email malware.exe             # Search for email addresses
re-search.py malware.exe                      # Run all built-in patterns
re-search.py -n domain malware.exe            # Search for domain names
```

---

#### `nth` (Name-That-Hash)
Identify the type of a hash value.

```bash
nth --text "5f4dcc3b5aa765d61d8327deb882cf99"    # Identify a hash
nth -f hashes.txt                                  # Identify from file
nth --text "hash" --json                           # JSON output
nth -a "5f4dcc3b5aa765d61d8327deb882cf99"         # Most likely matches
```

---

#### `hash-id.py`
Identify different types of hashes interactively.

```bash
hash-id.py                           # Interactive mode
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hash-id.py
```

---

#### `signsrch`
Find signatures of encryption, compression, or encoding algorithms within a binary.

```bash
signsrch malware.exe                  # Scan for algorithm signatures
signsrch -e malware.exe               # Show file offsets
signsrch -l malware.exe               # List all signatures found
```

---

#### `binwalk`
Extract and analyze firmware images and embedded files.

```bash
binwalk firmware.bin                  # Scan for embedded files
binwalk -e firmware.bin               # Extract embedded files
binwalk -M firmware.bin               # Recursive extraction (Matryoshka)
binwalk -E firmware.bin               # Entropy analysis (detect encryption)
binwalk -B firmware.bin               # Signature scan only
binwalk -D 'zip:zip' firmware.bin     # Extract only zip files
```

---

#### `hachoir-metadata`
Extract metadata from various file types.

```bash
hachoir-metadata malware.exe          # Show metadata
hachoir-metadata --raw malware.exe    # Raw output
hachoir-grep pattern malware.exe      # Search for patterns
```

---

#### `clamscan` / `freshclam`
Scan files for malware signatures using ClamAV.

```bash
clamscan malware.exe                          # Scan single file
clamscan -r /samples/                         # Recursive scan
clamscan --infected /samples/                 # Show only infected files
clamscan --log=scan.log -r /samples/          # Log results
freshclam                                     # Update virus database
clamscan --remove malware.exe                 # Scan and remove if detected
```

---

#### `file-magic.py`
Identify file types using the Python magic module.

```bash
file-magic.py malware.exe             # Identify file type
file-magic.py -r /samples/            # Recursive check
```

---

#### `numbers-to-string.py`
Convert sequences of decimal numbers to ASCII strings.

```bash
numbers-to-string.py "72 101 108 108 111"     # Decimal to ASCII
numbers-to-string.py -s "," "72,101,108"      # Comma-separated input
cat numbers.txt | numbers-to-string.py         # From file via pipe
```

---

#### `disitool.py`
Manipulate digital signatures in PE files.

```bash
disitool.py -m malware.exe            # Show signature info
disitool.py -e malware.exe sig.p7b    # Extract signature
disitool.py -r malware.exe            # Remove signature
disitool.py -c src.exe dst.exe        # Copy signature from src to dst
```

---

### 1.2 PE File Analysis

---

#### `manalyze`
Comprehensive static analysis of PE files including plugin-based checks.

```bash
manalyze malware.exe                          # Basic analysis
manalyze --plugins=all malware.exe            # Run all plugins
manalyze --plugins=packer malware.exe         # Packer detection only
manalyze --plugins=virustotal malware.exe     # Check VirusTotal
manalyze -o json malware.exe                  # JSON output
manalyze -r /samples/                         # Scan directory
```

---

#### `peframe`
Static analysis of PE files and Office documents.

```bash
peframe malware.exe               # Full analysis
peframe --json malware.exe        # JSON output
peframe --strings malware.exe     # Extract strings
peframe --import malware.exe      # Show imports
```

---

#### `pecheck.py`
Didier Stevens' PE file analysis tool.

```bash
pecheck.py malware.exe                # Full PE analysis
pecheck.py -s malware.exe            # Show sections
pecheck.py -l malware.exe            # Show libraries/imports
pecheck.py -j malware.exe            # JSON output
pecheck.py -A malware.exe            # Anomaly detection
```

---

#### `readpe` / `pedis` / `pestr` / `pehash` / `pescan` / `pesec` / `peldd` / `peres`
The `pev` / `readpe` toolkit — comprehensive PE analysis suite.

```bash
readpe malware.exe                    # Show PE headers
pestr malware.exe                     # Extract strings from PE
pedis malware.exe                     # Disassemble PE entry point
pedis -s .text malware.exe            # Disassemble .text section
pehash malware.exe                    # Compute various PE hashes
pescan malware.exe                    # Scan for suspicious characteristics
pesec malware.exe                     # Show security features (ASLR, DEP, etc.)
peldd malware.exe                     # Show DLL dependencies
peres malware.exe                     # Show resources
peres -x malware.exe                  # Extract resources
```

---

#### `pedump`
Analyze and dump PE file components.

```bash
pedump malware.exe                    # Full PE dump
pedump --imports malware.exe          # Show imports
pedump --exports malware.exe          # Show exports
pedump --resources malware.exe        # Show resources
pedump --headers malware.exe          # Show headers only
```

---

#### `portex`
Statically analyze PE files, detect anomalies and anti-analysis tricks.

```bash
portex -f malware.exe                 # Full analysis
portex -f malware.exe --visualize     # Generate PE visualization
portex -f malware.exe --json          # JSON output
```

---

#### `pe-tree`
Browse PE file structure interactively.

```bash
pe-tree malware.exe                   # Open GUI tree view
pe-tree --output-dir out/ malware.exe # Dump to directory
```

---

#### `bearcommander`
Parse and view PE file structure.

```bash
bearcommander malware.exe             # Open interactive PE viewer
```

---

#### `debloat`
Strip junk/padding content from bloated executables.

```bash
debloat -f malware.exe -o cleaned.exe   # Debloat and save output
debloat -f malware.exe --safe           # Only remove clearly junk data
debloat-gui                             # Launch GUI version
```

---

#### `dllcharacteristics.py`
Read and set DLL characteristics flags in a PE file.

```bash
dllcharacteristics.py malware.exe                         # Read characteristics
dllcharacteristics.py malware.exe DYNAMIC_BASE            # Enable ASLR
dllcharacteristics.py malware.exe NO_SEH                  # Set NO_SEH flag
```

---

#### `disitool.py` (PE-specific use)
Extract, delete, and inject digital signatures in PE files.

```bash
disitool.py -e malware.exe extracted.p7b  # Extract signature
disitool.py -r malware.exe                # Remove signature
disitool.py -i malware.exe sig.p7b        # Inject signature
```

---

### 1.3 ELF File Analysis

---

#### `readelf.py` (pyelftools)
Parse and analyze ELF files and DWARF debug information.

```bash
readelf.py -h malware.elf             # Show ELF header
readelf.py -S malware.elf             # Show sections
readelf.py -l malware.elf             # Show program headers
readelf.py -s malware.elf             # Show symbol table
readelf.py -d malware.elf             # Show dynamic section
readelf.py -r malware.elf             # Show relocations
readelf.py -a malware.elf             # Show all information
```

---

### 1.4 .NET File Analysis

---

#### `dotnetfile_dump.py`
Analyze static properties of .NET files.

```bash
dotnetfile_dump.py malware.exe        # Dump .NET metadata
dotnetfile_dump.py -p malware.exe     # Show PE headers too
```

---

### 1.5 Deobfuscation Tools

---

#### `xorsearch`
Search for XOR-, ROL-, ROT-, and SHIFT-encoded strings.

```bash
xorsearch malware.exe "This program"          # Search for known plaintext
xorsearch -l 6 malware.exe "kernel32"         # Search with min length
xorsearch malware.exe MZ                      # Search for MZ header (PE inside)
xorsearch -s 8 malware.exe "http"             # Search with ROT of 8
```

---

#### `xorsearch.py` (Didier Stevens)
Extended XOR/ROL/ROT/SHIFT search with YARA and regex support.

```bash
xorsearch.py -k "http" malware.exe            # XOR key search for "http"
xorsearch.py -r "https?://" malware.exe       # Regex pattern search
xorsearch.py -y "rule.yar" malware.exe        # YARA-based search
```

---

#### `XORStrings`
Find XOR-encoded strings in a binary.

```bash
xorstrings malware.exe                        # Scan all XOR keys
xorstrings -l 8 malware.exe                   # Minimum string length 8
xorstrings -x 0x41 malware.exe                # Test specific XOR key
```

---

#### `xortool`
Analyze XOR-encoded data and guess key parameters.

```bash
xortool malware.bin                           # Auto-detect XOR key length
xortool -x 0d malware.bin                     # Specify key length as 13
xortool -c 00 malware.bin                     # Most common char is null
xortool -b malware.bin                        # Brute-force key
xortool-xor -f key -s malware.bin > out.bin  # XOR file with key file
```

---

#### `unxor`
Deobfuscate XOR-encoded files using known plaintext.

```bash
unxor -p "MZ" -k 4 malware.exe        # Use "MZ" as plaintext, key length 4
unxor -f malware.bin -o decoded.bin   # Decode to output file
```

---

#### `brxor.py`
Bruteforce XOR keys to find English-language strings.

```bash
brxor.py malware.exe                          # Bruteforce all single-byte XOR keys
brxor.py -b 2 malware.exe                     # Try 2-byte keys
```

---

#### `xorBruteForcer.py`
Brute-force XOR-encoded files.

```bash
xorBruteForcer.py malware.bin         # Bruteforce single-byte XOR
```

---

#### `FLOSS` (FLARE Obfuscated String Solver)
Extract and deobfuscate strings from PE files including stack strings and tight loops.

```bash
floss malware.exe                             # Extract all string types
floss --no-static-strings malware.exe         # Skip simple static strings
floss -n 5 malware.exe                        # Minimum string length 5
floss --json malware.exe                      # JSON output
floss -o results.txt malware.exe              # Save to file
floss --functions 0x401000,0x401200 malware.exe  # Specific functions only
```

---

#### `base64dump.py`
Locate and decode Base64 and other common encodings from files.

```bash
base64dump.py malware.exe                     # Find and decode Base64
base64dump.py -e b64 malware.exe              # Base64 encoding only
base64dump.py -e uu malware.exe               # UUencoding
base64dump.py -s malware.exe                  # Show stats
base64dump.py malware.exe | strings           # Pipe decoded output
```

---

#### `translate.py`
Apply Python expressions to transform/translate bytes in a file.

```bash
translate.py "byte ^ 0x41" malware.bin > out.bin    # XOR with 0x41
translate.py "byte + 1" malware.bin > out.bin        # ROT by 1
translate.py "(byte - 0x61) % 26 + 0x61" malware.bin > out.bin  # Caesar cipher
```

---

#### `cut-bytes.py`
Extract a byte range from a file or data stream.

```bash
cut-bytes.py 100:200 malware.bin > extracted.bin      # Bytes 100–200
cut-bytes.py 0x100:0x200 malware.bin > extracted.bin  # Hex offset range
cut-bytes.py :500 malware.bin > first500.bin           # First 500 bytes
cut-bytes.py 1000: malware.bin > after1k.bin           # From offset 1000 to end
```

---

#### `format-bytes.py`
Decompose structured binary data using format strings (struct-style parsing).

```bash
format-bytes.py ">HH" header.bin              # Parse 2 big-endian uint16s
format-bytes.py "<IIH" data.bin               # Little-endian uint32, uint32, uint16
```

---

#### `hex-to-bin.py`
Convert hexadecimal text dumps back to binary data.

```bash
hex-to-bin.py hexdump.txt > output.bin        # Convert hex text to binary
echo "4d5a9000" | hex-to-bin.py > pe.bin      # From echo
```

---

#### `sets.py`
Perform set operations (union, intersection, difference) on lines or bytes.

```bash
sets.py intersection file1.txt file2.txt      # Lines in both files
sets.py difference file1.txt file2.txt        # Lines only in file1
sets.py union file1.txt file2.txt             # All unique lines combined
```

---

#### `chepy`
CyberChef-like CLI tool and Python library for data transformations.

```bash
chepy malware.bin --from-base64               # Decode from Base64
chepy malware.bin --xor "41" --to-hex         # XOR with 0x41 then show hex
chepy "aGVsbG8=" --from-base64 --to-str       # Decode Base64 string
chepy malware.bin --entropy                   # Calculate entropy
chepy input.txt --rot13                       # ROT13 decode
```

---

#### `mwcp` (DC3-MWCP)
Parse malware configuration information.

```bash
mwcp parse --parser Emotet malware.exe        # Parse with specific parser
mwcp parse --parser-dir parsers/ malware.exe  # Use custom parsers directory
mwcp list                                     # List available parsers
mwcp parse --json malware.exe                 # JSON output
```

---

#### `csce` / `list-cs-settings` (Cobalt Strike Config Extractor)
Extract and parse Cobalt Strike beacon configurations.

```bash
csce malware.exe                              # Extract CS beacon config
csce -p malware.exe                           # Pretty-print output
list-cs-settings                              # List all known CS settings
```

---

#### `1768.py`
Analyze Cobalt Strike beacon payloads.

```bash
1768.py malware.bin                           # Analyze beacon
1768.py -j malware.bin                        # JSON output
1768.py malware.bin -x                        # Extract embedded PE
```

---

#### `cs-decrypt-metadata.py`
Decrypt Cobalt Strike metadata from network captures.

```bash
cs-decrypt-metadata.py -k privatekey.pem metadata.bin  # Decrypt with RSA key
```

---

#### `cs-extract-key.py`
Extract AES and HMAC keys from a Cobalt Strike beacon process memory dump.

```bash
cs-extract-key.py memdump.bin                 # Extract keys from memory dump
```

---

#### `cs-analyze-processdump.py`
Detect sleep mask encoding in Cobalt Strike beacon process dumps.

```bash
cs-analyze-processdump.py memdump.bin         # Analyze for sleep masking
```

---

#### `xor-kpa.py`
Known plaintext attack against XOR-encoded data.

```bash
xor-kpa.py -p "MZ" malware.bin               # Known plaintext "MZ"
xor-kpa.py -p "This program" malware.bin     # Longer known plaintext
```

---

#### `strdeob.pl`
Locate and decode stack strings in executable files.

```bash
strdeob.pl malware.exe                        # Decode stack strings
```

---

#### `unicode`
Display Unicode character properties for analysis/investigation.

```bash
unicode U+0041                                # Show info for character A
unicode "suspicious_char"                     # Analyze a string's characters
unicode --category Lu                         # Show uppercase letters
```

---

#### `Malchive` (`malutil-*`)
MITRE's suite for static analysis of malicious code. All tools prefixed with `malutil-`.

```bash
malutil-xordecode malware.bin                 # XOR decode
malutil-findxor malware.bin                   # Find XOR key
malutil-debase64 malware.txt                  # Decode Base64
malutil-pecheck malware.exe                   # PE file check
malutil-superstrings malware.exe              # Extract strings (enhanced)
# See full list: https://github.com/MITRECND/malchive/wiki/Utilities
```

---

## 2. Statically Analyze Code

### 2.1 General

---

#### `ghidra`
NSA's software reverse engineering suite.

```bash
ghidra                                        # Launch GUI
ghidraRun                                     # Alternative launch command
analyzeHeadless /project proj -import malware.exe -postScript PrintAST.java  # Headless analysis
# Inside Ghidra: File > Import File > Analyze > Browse functions in Code Browser
```

---

#### `objdump`
Disassemble and inspect binary files.

```bash
objdump -d malware.exe                        # Disassemble executable sections
objdump -D malware.exe                        # Disassemble all sections
objdump -f malware.exe                        # File headers
objdump -x malware.exe                        # All headers
objdump -t malware.exe                        # Symbol table
objdump -p malware.exe                        # Private headers (imports/exports)
objdump -S malware.exe                        # Mix source and disassembly
objdump -M intel -d malware.exe              # Intel syntax disassembly
objdump --disassemble=main malware.elf        # Disassemble specific function
```

---

#### `qltool` (Qiling)
Emulate execution of PE files, shellcode, and more across multiple OS platforms.

```bash
qltool run -f malware.exe --os windows --arch x86    # Run Windows x86 PE
qltool run -f shellcode.bin --os windows --arch x86  # Run shellcode
qltool run -f malware.exe --rootfs ~/rootfs/win/     # With rootfs
qltool disasm -f malware.exe --os windows --arch x86 # Disassemble
qltool code -f malware.exe --os linux --arch x86     # Code analysis
```

---

#### `vivbin` / `vdbbin` (Vivisect)
Static analysis and emulation of binary files.

```bash
vivbin malware.exe                            # Open in Vivisect GUI
vdbbin malware.exe                            # Open in Vdb debugger
# Python scripting:
python3 -c "import vivisect; vw = vivisect.VivWorkspace(); vw.loadFromFile('malware.exe'); vw.analyze()"
```

---

### 2.2 .NET Analysis

---

#### `de4dot`
Deobfuscate and unpack .NET programs.

```bash
de4dot malware.exe                            # Auto-detect and deobfuscate
de4dot malware.exe -o cleaned.exe             # Save output
de4dot --detect malware.exe                   # Detect obfuscator only
de4dot --all-flows malware.exe                # Full deobfuscation
```

---

#### `ilspycmd` (ILSpy CLI)
Decompile .NET assemblies to C# source code.

```bash
ilspycmd malware.exe                          # Decompile to stdout
ilspycmd malware.exe -o ./output/             # Output to directory
ilspycmd malware.exe -t "Namespace.ClassName" # Decompile specific type
ilspycmd malware.exe --list-types             # List all types
ilspycmd malware.exe -il                      # Show IL (intermediate language)
```

---

### 2.3 PE File Static Analysis (Code)

---

#### `speakeasy` / `emu_exe.py` / `emu_dll.py`
Emulate Windows PE execution in a sandbox to extract behavior.

```bash
speakeasy -t malware.exe -o report.json              # Emulate and report
speakeasy -t malware.exe --raw --arch x86            # Raw shellcode mode
speakeasy -t malware.dll --no-report                 # No output report
emu_exe.py -f malware.exe                            # Emulate EXE
emu_dll.py -f malware.dll -e DllMain                 # Emulate DLL entry point
```

---

### 2.4 Python File Analysis

---

#### PyInstaller Extractor (`pyinstxtractor.py`)
Extract contents of PyInstaller-packaged executables.

```bash
pyinstxtractor.py malware.exe                 # Extract all components
# Then decompile the .pyc files:
uncompyle6 output_dir/malware.pyc             # Decompile .pyc to source
pycdc output_dir/malware.pyc                  # Alternative decompiler
```

---

### 2.5 Android Analysis

---

#### `apktool`
Reverse engineer Android APK files.

```bash
apktool d malware.apk                         # Decompile APK
apktool d malware.apk -o output/              # Decompile to directory
apktool b output/ -o rebuilt.apk              # Rebuild APK from source
apktool d malware.apk --no-src               # Decode resources only
apktool d malware.apk --force                # Force overwrite
```

---

#### `droidlysis`
Static analysis of Android APK files.

```bash
droidlysis --input malware.apk                # Analyze APK
droidlysis --input malware.apk --output out/  # With output directory
droidlysis --input malware.apk --json         # JSON output
droidlysis --input malware.apk --all          # Full analysis
```

---

#### Androguard suite
Comprehensive Android analysis tools.

```bash
androguard analyze malware.apk                     # Full analysis
androguard analyze malware.apk -o report.json      # JSON report
androdis malware.apk                               # Disassemble Dalvik bytecode
androlyze.py -s malware.apk                        # Interactive analysis
androaxml.py -i malware.apk -o manifest.xml        # Extract AndroidManifest.xml
androcg.py -i malware.apk -o callgraph.gml         # Generate call graph
```

---

## 3. Dynamically Reverse-Engineer Code

### 3.1 General

---

#### `radare2` (r2)
Powerful reverse engineering framework for binary analysis, disassembly, and debugging.

```bash
r2 malware.exe                                # Open in interactive mode
r2 -A malware.exe                             # Open and auto-analyze
r2 -d malware.exe                             # Open in debug mode
r2 -w malware.exe                             # Open in write mode

# Common r2 commands (inside the r2 shell):
# aaa          - Analyze all (functions, xrefs)
# afl          - List all functions
# pdf @ main   - Disassemble main function
# px 64 @ 0x401000  - Print hex at address
# iz           - List strings in data sections
# ii           - Show imports
# iE           - Show exports
# VV           - Visual graph mode
# q            - Quit

rasm2 -a x86 -b 32 "nop; nop; ret"           # Assemble instructions
rabin2 -i malware.exe                         # Show imports
rabin2 -E malware.exe                         # Show exports
rabin2 -S malware.exe                         # Show sections
rabin2 -s malware.exe                         # Show symbols
rabin2 -z malware.exe                         # Show strings
rahash2 -a md5 malware.exe                    # Hash file
rafind2 -s "http" malware.exe                 # Search for string
```

---

#### `frida` suite
Dynamic instrumentation toolkit for tracing processes.

```bash
frida-ps -a                                   # List all running processes
frida-ps -ai                                  # List with PIDs
frida-ls-devices                              # List available devices
frida -p 1234 -l trace.js                     # Inject script into PID 1234
frida -n notepad.exe -l trace.js              # Inject by process name
frida-trace -p 1234 -i "recv*"               # Trace recv functions in PID
frida-trace -n malware.exe -i "CreateFile*"  # Trace CreateFile calls
frida-trace -n malware.exe -m "*!*open*"      # Trace all open methods
frida-kill 1234                               # Kill process by PID
frida-discover -n malware.exe                 # Discover exported functions
```

---

#### `wine`
Run Windows binaries on Linux.

```bash
wine malware.exe                              # Run Windows executable
wine malware.exe arg1 arg2                    # With arguments
WINEDEBUG=+all wine malware.exe 2>&1 | tee wine.log  # Full debug output
WINEDLLOVERRIDES="ntdll=b" wine malware.exe   # Override DLL
winedbg malware.exe                           # Debug with Wine debugger
```

---

### 3.2 Shellcode Analysis

---

#### `scdbgc`
Emulate and analyze shellcode execution.

```bash
scdbgc /f shellcode.bin                       # Emulate shellcode
scdbgc /f shellcode.bin /r                    # Report mode
scdbgc /f shellcode.bin /findsc               # Find shellcode offset
scdbgc /f shellcode.bin /max 1000            # Limit to 1000 instructions
scdbgc /f shellcode.bin /d                   # Dump output
```

---

#### `shcode2exe`
Convert shellcode to a Windows executable for easier analysis.

```bash
shcode2exe -f shellcode.bin -o shellcode.exe           # Convert to EXE
shcode2exe -f shellcode.bin -o shellcode.exe -p x64    # 64-bit shellcode
```

---

### 3.3 JavaScript / Script Deobfuscation

---

#### `js` (SpiderMonkey)
Execute JavaScript using Mozilla's standalone engine.

```bash
js malicious.js                               # Execute JavaScript file
js -e "print('test')"                         # Execute inline JS
js -f malicious.js -i                         # Interactive after executing
```

---

#### `js-ascii` / `js-file` (Patched SpiderMonkey)
Didier Stevens' patched SpiderMonkey — prints ASCII output and non-executing JS.

```bash
js-ascii malicious.js                         # Execute and show ASCII output
js-file malicious.js                          # Execute and dump to file
```

---

#### `box-js`
Analyze and deobfuscate suspicious JavaScript.

```bash
box-js malicious.js                           # Run and capture behavior
box-js malicious.js --no-shell-error         # Suppress shell errors
box-js malicious.js --timeout 30             # 30-second timeout
box-export results/                           # Export analysis results
```

---

#### `jstillery`
Deobfuscate JavaScript using AST and partial evaluation.

```bash
jstillery malicious.js                        # Deobfuscate JavaScript
jstillery -o clean.js malicious.js            # Save output
```

---

#### `pwsh` (PowerShell Core)
Execute and analyze PowerShell scripts.

```bash
pwsh                                          # Interactive PS shell
pwsh -File malware.ps1                        # Execute script
pwsh -Command "Get-Content malware.ps1 | Out-String"  # Read script
pwsh -NoProfile -File malware.ps1             # No profile
# Useful for deobfuscation:
pwsh -Command "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('base64here'))"
```

---

### 3.4 ELF Debugging

---

#### `gdb`
GNU Project Debugger — multi-language debugger.

```bash
gdb malware.elf                               # Start debugger
gdb -p 1234                                   # Attach to process

# Common GDB commands:
# run                 - Start program
# break main          - Set breakpoint at main
# break *0x401000     - Set breakpoint at address
# continue            - Continue execution
# next                - Step over
# step                - Step into
# info registers      - Show registers
# x/10x $rsp          - Examine 10 hex words at stack pointer
# disassemble main    - Disassemble main function
# bt                  - Backtrace
# info proc map       - Show memory mappings
```

---

#### `edb`
AArch32/x86/x86-64 debugger well-suited for Linux ELF files.

```bash
edb --run malware.elf                         # Launch and run binary
edb --attach 1234                             # Attach to PID
# Use GUI for breakpoints, memory inspection, register view
```

---

#### `ltrace`
Trace library (shared library) calls made by a process.

```bash
ltrace ./malware.elf                          # Trace all library calls
ltrace -S ./malware.elf                       # Also trace system calls
ltrace -e "malloc+free" ./malware.elf         # Trace specific calls
ltrace -f ./malware.elf                       # Follow child processes
ltrace -o output.txt ./malware.elf            # Log to file
ltrace -l /lib/libc.so.6 ./malware.elf        # Trace specific library
```

---

#### `strace`
Trace system calls and signals.

```bash
strace ./malware.elf                          # Trace all syscalls
strace -e trace=network ./malware.elf         # Network syscalls only
strace -e trace=file ./malware.elf            # File-related syscalls only
strace -e trace=open,read,write ./malware.elf # Specific syscalls
strace -p 1234                                # Attach to running process
strace -f ./malware.elf                       # Follow forks
strace -o strace.log ./malware.elf            # Log to file
strace -c ./malware.elf                       # Summary count
strace -T ./malware.elf                       # Show time spent in each call
```

---

## 4. Perform Memory Forensics

---

#### `vol3` / `volshell3` (Volatility 3)
Memory forensics framework for analyzing memory images.

```bash
# First, place symbol tables in the correct location:
# /opt/volatility3/lib/python3.*/site-packages/volatility3/symbols

vol3 -f memory.dmp windows.info              # Basic image info
vol3 -f memory.dmp windows.pslist            # List processes
vol3 -f memory.dmp windows.pstree           # Process tree
vol3 -f memory.dmp windows.cmdline          # Command-line arguments
vol3 -f memory.dmp windows.dlllist          # DLLs per process
vol3 -f memory.dmp windows.malfind          # Find injected code/shellcode
vol3 -f memory.dmp windows.netscan          # Network connections
vol3 -f memory.dmp windows.netstat          # Network stats
vol3 -f memory.dmp windows.filescan         # Scan for file objects
vol3 -f memory.dmp windows.dumpfiles --pid 1234   # Dump files for process
vol3 -f memory.dmp windows.handles --pid 1234     # Open handles
vol3 -f memory.dmp windows.memmap --pid 1234      # Memory map for PID
vol3 -f memory.dmp windows.vadinfo --pid 1234     # VAD info
vol3 -f memory.dmp windows.registry.hivelist      # Registry hive list
vol3 -f memory.dmp windows.registry.printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
vol3 -f memory.dmp linux.pslist              # Linux process list
vol3 -f memory.dmp linux.bash               # Bash history from memory

volshell3 -f memory.dmp                      # Interactive memory shell
```

---

#### `aeskeyfind`
Find AES keys in a memory image.

```bash
aeskeyfind memory.dmp                         # Scan for 128/256-bit AES keys
aeskeyfind -v memory.dmp                      # Verbose output
```

---

#### `rsakeyfind`
Find RSA private keys in a memory image.

```bash
rsakeyfind memory.dmp                         # Scan for RSA private keys
```

---

#### `bulk_extractor` (memory forensics use)
Extract artifacts from memory images.

```bash
bulk_extractor -o output/ memory.dmp              # Full extraction
bulk_extractor -e email -o out/ memory.dmp        # Extract emails
bulk_extractor -e net -o out/ memory.dmp          # Extract network artifacts
bulk_extractor -e url -o out/ memory.dmp          # Extract URLs
```

---

## 5. Explore Network Interactions

### 5.1 Traffic Capture and Analysis

---

#### `tcpdump`
Command-line packet capture and analysis.

```bash
tcpdump -i eth0                               # Capture on interface eth0
tcpdump -i eth0 -w capture.pcap              # Write to pcap file
tcpdump -r capture.pcap                      # Read pcap file
tcpdump -i eth0 port 80                      # Filter HTTP traffic
tcpdump -i eth0 host 192.168.1.100           # Filter by host
tcpdump -i eth0 'tcp port 443'               # HTTPS traffic
tcpdump -i eth0 -n -X                        # No DNS lookup, hex+ASCII output
tcpdump -i eth0 -A port 80                   # ASCII output for HTTP
tcpdump -i eth0 -c 100                       # Capture 100 packets then stop
```

---

#### `tshark`
Wireshark's command-line interface for capture and analysis.

```bash
tshark -i eth0                                        # Capture on interface
tshark -r capture.pcap                                # Read pcap
tshark -r capture.pcap -T fields -e ip.src -e ip.dst # Extract fields
tshark -r capture.pcap -Y "http"                      # Apply display filter
tshark -r capture.pcap -Y "dns"                       # DNS traffic only
tshark -r capture.pcap -Y "tcp.port==4444"            # Specific port
tshark -r capture.pcap -z io,phs                      # Protocol hierarchy
tshark -r capture.pcap --export-objects http,./output # Export HTTP objects
tshark -r capture.pcap -T json                        # JSON output
tshark -r capture.pcap -z conv,tcp                    # TCP conversations
tshark -r capture.pcap -z follow,tcp,ascii,0          # Follow TCP stream 0
```

---

#### `ngrep`
Network grep — search for patterns in packet data.

```bash
ngrep -i "password" port 80                   # Search for "password" on HTTP
ngrep -d eth0 "GET|POST"                      # Match HTTP verbs
ngrep -q "command" host 192.168.1.1           # Quiet mode, filter by host
ngrep -W byline port 25                       # SMTP traffic, line-by-line
ngrep -t "." -d eth0                          # Timestamp all traffic
```

---

#### `tcpflow`
Reconstruct TCP streams from captures.

```bash
tcpflow -r capture.pcap                       # Extract TCP flows from pcap
tcpflow -c -r capture.pcap                    # Print to console
tcpflow -r capture.pcap -o output/            # Save flows to directory
tcpflow -i eth0 -o output/                    # Live capture and flow extraction
```

---

#### `tcpxtract`
Extract files transferred over network from pcap files.

```bash
tcpxtract -f capture.pcap                     # Extract files from pcap
tcpxtract -f capture.pcap -o output/          # Save to directory
tcpxtract -d eth0                             # Live capture and extraction
```

---

#### `tcpick`
Command-line TCP stream sniffer and reassembler.

```bash
tcpick -C -r capture.pcap                     # Reconstruct streams
tcpick -r capture.pcap -wR                    # Write each stream to a file
tcpick -i eth0 -C "port 80"                   # Live capture, show streams
```

---

#### `mitmproxy` / `mitmdump` / `mitmweb`
Intercept and inspect HTTP/HTTPS traffic.

```bash
mitmproxy -p 8080                             # Start interactive proxy on 8080
mitmweb -p 8080                               # Start with web UI
mitmdump -p 8080                              # Non-interactive dump mode
mitmdump -w capture.pcap                      # Write to pcap
mitmdump -r capture.pcap                      # Replay from pcap
mitmdump -s script.py                         # Use Python addon script
mitmproxy --mode transparent                  # Transparent proxy mode
```

---

#### `polarproxy`
Intercept and decrypt TLS traffic.

```bash
polarproxy -p 10443 -o pcap/ --pcapoveripport 57012   # Listen and save pcap
polarproxy -v -p 443                                   # Verbose mode
polarproxy --insecure -p 10443                         # Accept invalid certs
```

---

#### `cs-parse-traffic.py`
Decrypt and parse Cobalt Strike beacon C2 traffic.

```bash
cs-parse-traffic.py -k privatekey.pem capture.pcap    # Decrypt with RSA key
cs-parse-traffic.py -a 192.168.1.100 capture.pcap     # Filter by C2 IP
```

---

### 5.2 Network Connectivity Tools

---

#### `curl`
Transfer data to/from servers via many protocols.

```bash
curl http://malware-c2.example.com/            # Simple GET request
curl -v http://c2.example.com/                 # Verbose (show headers)
curl -A "Mozilla/5.0" http://c2.example.com/   # Custom User-Agent
curl -H "X-Custom: header" http://c2.example.com/  # Custom header
curl -d "data=value" http://c2.example.com/    # POST request
curl -o response.bin http://c2.example.com/payload  # Save response
curl --proxy socks5://127.0.0.1:9050 http://c2.example.com/  # Via SOCKS proxy
curl -k https://c2.example.com/                # Ignore TLS errors
curl -x http://127.0.0.1:8080 http://c2.example.com/  # Via HTTP proxy
```

---

#### `nc` (netcat)
Read and write data across network connections.

```bash
nc -lvp 4444                                  # Listen on port 4444
nc 192.168.1.100 4444                         # Connect to host:port
nc -lvp 4444 > received_file.exe              # Receive file
nc 192.168.1.100 4444 < malware.exe           # Send file
nc -z -v 192.168.1.100 1-1024                # Port scan
nc -u 192.168.1.100 53                        # UDP mode
```

---

#### `thug`
Honeyclient for analyzing malicious web pages (JavaScript, PDF, Flash).

```bash
thug -F http://malicious-site.example.com/     # Analyze with logging
thug -u win7ie11 http://malicious-site.com/    # Emulate Windows 7 IE 11
thug -F -p 3 http://malicious-site.com/       # Enable PDF plugin
```

---

### 5.3 Network Services

---

#### `inetsim`
Emulate common internet services (DNS, HTTP, SMTP, FTP, etc.) for malware analysis.

```bash
inetsim                                        # Start with default config
inetsim --config /etc/inetsim/inetsim.conf     # Specify config file
# Config at /etc/inetsim/inetsim.conf — enable/disable services,
# set IPs and ports, configure response files
# Log files: /var/log/inetsim/
```

---

#### `fakenet` (FakeNet-NG)
Dynamic network analysis tool — intercepts and redirects all network traffic.

```bash
sudo fakenet                                   # Start FakeNet-NG
sudo fakenet -c /opt/fakenet-ng/.../default.ini  # With config
# Edit config first: set LinuxRestrictInterface to your NIC (e.g., ens33)
```

---

#### `fakedns`
Respond to all DNS queries with a specified IP address.

```bash
fakedns -h                                     # Show help
sudo fakedns 192.168.1.1                       # Respond with this IP for all queries
sudo fakedns -p 5353 192.168.1.1              # Use port 5353
```

---

#### `dnsresolver.py`
Flexible DNS resolver for dynamic analysis with wildcard and tracking support.

```bash
dnsresolver.py                                 # Interactive mode
dnsresolver.py -a 192.168.1.100               # Answer all queries with IP
dnsresolver.py -f domains.txt                  # Use domain file for routing
```

---

#### `fakemail`
Fake SMTP server to capture outbound emails from malware.

```bash
fakemail --host 127.0.0.1 --port 25 --path /tmp/mail/  # Start on port 25
fakemail --background                                   # Run as daemon
```

---

#### `accept-all-ips`
Redirect all incoming connections to local ports (used with INetSim).

```bash
sudo accept-all-ips start                      # Start redirection
sudo accept-all-ips stop                       # Stop redirection
sudo accept-all-ips status                     # Check status
```

---

## 6. Investigate System Interactions

---

#### `strace` (see also section 3.4)
Trace system calls for behavioral analysis.

```bash
strace -f -e trace=all -o strace_output.txt ./malware.elf
strace -f -e trace=network,file ./malware.elf
```

---

#### `ltrace` (see also section 3.4)
Trace library calls for behavioral analysis.

```bash
ltrace -f -S -o ltrace_output.txt ./malware.elf
```

---

#### `sandfly-processdecloak`
Find hidden processes using multiple detection methods.

```bash
sudo sandfly-processdecloak                    # Scan for hidden processes
```

---

#### `unhide`
Find hidden processes, TCP/UDP ports, and network connections.

```bash
sudo unhide proc                               # Find hidden processes
sudo unhide sys                                # Kernel-level hiding
sudo unhide brute                              # Brute-force PID scan
sudo unhide-tcp                                # Find hidden TCP ports
```

---

#### `procdot`
Visualize Process Monitor (ProcMon) CSV output as a graph.

```bash
procdot                                        # Launch GUI
# In GUI: File > Load ProcMon CSV, set filter options, render graph
procdot /proc procmon_log.csv /dot output.dot  # Command-line mode
```

---

## 7. Analyze Documents

### 7.1 General Document Analysis

---

#### `tesseract`
OCR text extraction from images.

```bash
tesseract image.png output                     # Extract text to output.txt
tesseract screenshot.png output pdf            # Output as PDF
tesseract image.png stdout                     # Print to console
tesseract image.png output -l eng+deu          # Multi-language
tesseract image.png output --psm 6             # Page segmentation mode 6
```

---

### 7.2 PDF Analysis

---

#### `pdfid.py`
Quickly scan a PDF for suspicious elements.

```bash
pdfid.py malware.pdf                           # Quick scan for JS, /OpenAction, etc.
pdfid.py -e malware.pdf                        # Show entropy of streams
pdfid.py -f malware.pdf                        # Follow object references
pdfid.py -d malware.pdf                        # Disarm dangerous elements
```

---

#### `pdf-parser.py`
Deep inspection of PDF structure and objects.

```bash
pdf-parser.py malware.pdf                      # List all objects
pdf-parser.py --stats malware.pdf             # Summary statistics
pdf-parser.py -o 10 malware.pdf               # Inspect object 10
pdf-parser.py -f malware.pdf                  # Follow object references
pdf-parser.py --filter malware.pdf            # Show filtered stream data
pdf-parser.py -c malware.pdf                  # Show content
pdf-parser.py --search /JS malware.pdf        # Search for JavaScript
pdf-parser.py -d dump.bin -o 10 malware.pdf  # Dump object 10 to file
```

---

#### `peepdf` (peepdf-3)
Interactive PDF analysis tool.

```bash
peepdf malware.pdf                             # Interactive shell
peepdf -f malware.pdf                          # Force parsing (broken PDFs)
peepdf -s commands.txt malware.pdf            # Batch commands from script

# Common peepdf shell commands:
# info            - File information
# tree            - Object tree
# js_analyse      - Analyze JavaScript
# js_beautify 5   - Beautify JS in object 5
# stream 5        - Show stream of object 5
# rawstream 5     - Raw stream data
```

---

#### `pdftool.py`
Analyze incremental updates in PDF documents.

```bash
pdftool.py malware.pdf                         # List incremental updates
pdftool.py -v malware.pdf                      # Verbose output
pdftool.py -e malware.pdf                      # Extract each version
```

---

#### `pdftk`
Manipulate PDF files.

```bash
pdftk malware.pdf dump_data                    # Show PDF metadata
pdftk malware.pdf dump_data_fields             # Show form fields
pdftk malware.pdf burst                        # Split into individual pages
pdftk in1.pdf in2.pdf cat output merged.pdf   # Merge PDFs
pdftk malware.pdf output decrypted.pdf allow AllFeatures owner_pw ""  # Decrypt
pdftk malware.pdf output decompressed.pdf uncompress  # Decompress streams
```

---

#### `qpdf`
Inspect and transform PDF structure.

```bash
qpdf --check malware.pdf                       # Check PDF integrity
qpdf malware.pdf --json                        # Dump structure as JSON
qpdf malware.pdf --qdf output.pdf             # Human-readable debug format
qpdf --decrypt malware.pdf output.pdf         # Remove encryption
qpdf malware.pdf --json-output=out.json       # Full JSON output
```

---

#### `pdfresurrect`
Extract earlier versions of content from incrementally updated PDFs.

```bash
pdfresurrect malware.pdf                       # List versions
pdfresurrect -w malware.pdf                   # Write out all versions
pdfresurrect -s malware.pdf                   # Show summary
```

---

#### Origamindee (`pdfcop`, `pdfdecompress`, `pdfextract`, etc.)
Ruby-based PDF library with CLI tools.

```bash
pdfcop malware.pdf                             # Validate and sanitize PDF
pdfdecompress malware.pdf > decompressed.pdf   # Decompress all streams
pdfextract malware.pdf                         # Extract streams/objects
pdfdecrypt malware.pdf output.pdf              # Decrypt PDF
```

---

### 7.3 Microsoft Office Analysis

---

#### `oledump.py`
Analyze OLE2 files (DOC, XLS, PPT, etc.) for macros and embedded objects.

```bash
oledump.py malware.doc                         # List all streams
oledump.py -s 7 malware.doc                   # Show stream 7
oledump.py -s 7 -d malware.doc                # Dump stream 7 (raw)
oledump.py -s 7 -v malware.doc                # Decompress/decrypt stream 7
oledump.py -p plugin_biff.py malware.xls      # Use plugin
oledump.py --vbadecompress -s 7 malware.doc   # Decompress VBA stream
oledump.py -s 7 malware.doc | base64dump.py   # Pipe to base64dump
```

---

#### oletools suite
Comprehensive OLE and VBA analysis tools.

```bash
# olevba — Extract and analyze VBA macros
olevba malware.doc                             # Full VBA analysis
olevba --decode malware.doc                   # Decode obfuscated strings
olevba --deobf malware.doc                    # Deobfuscate VBA
olevba -j malware.doc                         # JSON output

# oleid — Identify OLE characteristics
oleid malware.doc                              # Check for indicators

# olebrowse — Browse OLE structure
olebrowse malware.doc                          # GUI browser

# mraptor — Detect malicious macros
mraptor malware.doc                            # Check for auto-exec macros
mraptor -r /samples/                           # Recursive scan

# msodde — Extract DDE fields
msodde malware.doc                             # Find DDE links
msodde -r /samples/                            # Recursive

# rtfobj — Analyze embedded objects in RTF
rtfobj malware.rtf                             # List embedded objects
rtfobj -d output/ malware.rtf                 # Extract objects

# pyxswf — Extract Flash objects from Office files
pyxswf malware.doc                             # Extract SWF objects
```

---

#### `rtfdump.py`
Analyze RTF files for embedded objects and exploits.

```bash
rtfdump.py malware.rtf                         # List all RTF objects
rtfdump.py -s 5 malware.rtf                   # Show element 5
rtfdump.py -s 5 -H malware.rtf               # Show as hex
rtfdump.py -s 5 -d malware.rtf               # Dump element 5
rtfdump.py --objects malware.rtf              # Show embedded objects only
```

---

#### `zipdump.py`
Analyze zip files (and OOXML Office documents, which are ZIP-based).

```bash
zipdump.py malware.docx                        # List all files in zip/OOXML
zipdump.py -s 3 malware.docx                  # Show file 3 content
zipdump.py -s 3 -d malware.docx              # Dump file 3 raw
zipdump.py malware.docx | oledump.py -         # Pipe to oledump
```

---

#### `xmldump.py`
Extract and analyze XML content from OOXML Office documents.

```bash
xmldump.py malware.docx                        # Extract XML from OOXML
xmldump.py -s 3 malware.docx                  # Show specific XML file
xmldump.py malware.docx | grep -i "vba"       # Search XML for VBA references
```

---

#### `onedump.py`
Analyze and extract embedded files from OneNote documents.

```bash
onedump.py malware.one                         # List embedded files
onedump.py -s 2 malware.one                   # Show embedded file 2
onedump.py -s 2 -d malware.one               # Dump embedded file 2
```

---

#### `xlmdeobfuscator`
Deobfuscate Excel 4.0 (XLM) macros.

```bash
xlmdeobfuscator -f malware.xls                # Deobfuscate XLM macros
xlmdeobfuscator -f malware.xls --export-json  # JSON output
xlmdeobfuscator -f malware.xlsb               # Binary Excel format
xlmdeobfuscator -f malware.xls --start-point "Sheet1!A1"  # Specific start
```

---

#### `pcodedmp`
Disassemble VBA p-code from Office documents.

```bash
pcodedmp malware.doc                           # Disassemble all VBA p-code
pcodedmp -d malware.xls                        # More detailed output
```

---

#### `pcode2code`
Decompile VBA p-code back to readable source code.

```bash
pcode2code malware.doc                         # Decompile to VBA source
pcode2code -o output/ malware.doc             # Save to directory
```

---

#### `msoffcrypto-tool`
Decrypt encrypted Microsoft Office documents.

```bash
msoffcrypto-tool malware.docx -d -p password  # Decrypt with password
msoffcrypto-tool malware.docx -t              # Test if encrypted
msoffcrypto-tool malware.docx -d -o decrypted.docx -p ""  # Empty password
```

---

#### `msoffcrypto-crack.py`
Recover the password of an encrypted Office document (wordlist attack).

```bash
msoffcrypto-crack.py malware.docx                       # Try default passwords
msoffcrypto-crack.py -w wordlist.txt malware.docx       # Wordlist attack
```

---

#### `msoffice-crypt`
Encrypt and decrypt OOXML Office documents.

```bash
msoffice-crypt -d -p password malware.xlsx output.xlsx  # Decrypt
msoffice-crypt -e -p password clean.xlsx encrypted.xlsx # Encrypt
```

---

#### `evilclippy`
Modify VBA project properties and stomp macros for analysis.

```bash
evilclippy -uu malware.doc                     # Remove VBA password protection
evilclippy -s fake_macro.vba malware.doc       # Stomp macro (hide real code)
evilclippy -g malware.doc                      # GUI version check
```

---

#### `olecfexport` / `olecfinfo` (libolecf)
Low-level access to OLE2 Compound Document file structure.

```bash
olecfinfo malware.doc                          # Show OLE structure info
olecfexport -t malware.doc -d output/          # Export all streams
olecfexport -s "Macros/VBA/Module1" malware.doc # Export specific stream
```

---

### 7.4 Email Analysis

---

#### `extract_msg`
Extract content and attachments from Outlook MSG files.

```bash
extract_msg malware.msg                        # Extract to current directory
extract_msg --out output/ malware.msg          # Extract to specific directory
extract_msg --json malware.msg                 # JSON output
extract_msg --attachments-only malware.msg    # Attachments only
```

---

#### `msgconvert`
Convert Outlook MSG files to MBOX/EML format.

```bash
msgconvert malware.msg                         # Convert to .eml
msgconvert malware.msg > malware.eml          # Save as .eml
```

---

#### `mailparser`
Parse raw SMTP and MSG email messages.

```bash
mailparser -f malware.eml                      # Parse email file
mailparser -f malware.eml --json              # JSON output
mailparser --smtp malware.txt                  # Parse raw SMTP
```

---

#### `emldump.py`
Parse and analyze EML email files.

```bash
emldump.py malware.eml                         # List all parts
emldump.py -s 2 malware.eml                   # Show part 2
emldump.py -s 2 -d malware.eml               # Dump part 2 (attachment)
emldump.py -j malware.eml                     # JSON output
```

---

## 8. Gather and Analyze Data

---

#### `yara`
Scan files for malware using rules (see also section 1.1).

```bash
yara rules.yar malware.exe                    # Scan with rule file
yara -r rules/ /samples/                      # Recursive scan with rules dir
yara -s rules.yar malware.exe                 # Show matching strings
yara -n rules.yar malware.exe                 # Show non-matching rules
```

---

#### `yr` (YARA-X)

```bash
yr scan rules.yar malware.exe                 # Scan file
yr scan -r rules/ /samples/                   # Recursive
yr compile rules.yar -o compiled.yarc         # Compile rules
```

---

#### `ioc_parser`
Extract indicators of compromise from PDF security reports.

```bash
ioc_parser report.pdf                          # Extract IOCs from PDF
ioc_parser -o json report.pdf                 # JSON output
ioc_parser -d -o json report.pdf             # Include defanged IOCs
ioc_parser report.pdf -p -o csv              # CSV output
```

---

#### `malwoverview`
Query multiple threat intelligence platforms (VirusTotal, HybridAnalysis, etc.).

```bash
# First add API keys to ~/.malwapi.conf
malwoverview -f malware.exe                    # Query all platforms
malwoverview -f malware.exe -V                 # VirusTotal only
malwoverview -f malware.exe -H                 # HybridAnalysis only
malwoverview -u http://malicious-url.com       # URL lookup
malwoverview -i 192.168.1.100                 # IP lookup
malwoverview -d malicious-domain.com          # Domain lookup
malwoverview -F /samples/                      # Scan directory
```

---

#### `virustotal-search.py`
Search VirusTotal for file hashes.

```bash
virustotal-search.py -k <api_key> -f malware.exe          # Search by file
virustotal-search.py -k <api_key> hashlist.txt            # Search hash list
virustotal-search.py -k <api_key> -h 5f4dcc3b5aa765d6...  # Search by hash
```

---

#### `virustotal-submit.py`
Submit files to VirusTotal.

```bash
virustotal-submit.py -k <api_key> malware.exe             # Submit single file
virustotal-submit.py -k <api_key> -r /samples/            # Submit directory
```

---

#### `dissect` suite
Fox-IT's DFIR framework — comprehensive forensics toolset.

```bash
target-query -t malware.vmdk -f hostname         # Query hostname from image
target-query -t malware.vmdk -f ps               # Process list
target-query -t malware.vmdk -f netstat          # Network connections
target-query -t malware.vmdk -f browsers.history  # Browser history
target-query -t malware.vmdk -f runkeys           # Run registry keys
target-fs -t malware.vmdk /Windows/System32/     # Browse filesystem
target-shell -t malware.vmdk                     # Interactive shell
acquire                                           # Acquire a live system
rdump artifacts.rec                              # Dump records
target-reg -t malware.vmdk                       # Registry access
```

---

#### `time-decode`
Decode and encode timestamps in various formats.

```bash
time-decode --unix 1672531200                    # Unix timestamp
time-decode --windows 133170432000000000         # Windows FILETIME
time-decode --chrome 13300000000000000           # Chrome timestamp
time-decode --epoch-be "00 00 00 00 63 B4 30 00" # Big-endian epoch
time-decode --guess 1672531200                   # Guess format
time-decode --now                                # Current time in all formats
```

---

#### `ipwhois_cli.py`
Retrieve WHOIS data for IP addresses.

```bash
ipwhois_cli.py 8.8.8.8                           # WHOIS for IP
ipwhois_cli.py --json 192.168.1.100             # JSON output
ipwhois_cli.py --inc 8.8.8.8                    # ARIN WHOIS
```

---

#### `pdnstool`
Query passive DNS databases.

```bash
pdnstool malicious-domain.com                    # Query passive DNS
pdnstool -t A malicious-domain.com              # Query A records only
pdnstool -r 192.168.1.100                        # Reverse lookup
```

---

#### `dexray`
Extract and decode files from antivirus quarantine archives.

```bash
dexray quarantine.vbn                            # Extract from Symantec quarantine
dexray MfeDeepRem.qua                            # McAfee quarantine
dexray -d output/ quarantine.vbn                # Extract to directory
# Supports: Symantec, McAfee, Kaspersky, Trend Micro, and more
```

---

#### `nsrllookup`
Look up file hashes in the NIST National Software Reference Library (NSRL).

```bash
nsrllookup md5hash                              # Single hash lookup
echo "5f4dcc3b5aa765d61d8327deb882cf99" | nsrllookup  # Via pipe
nsrllookup -f hashes.txt                        # Batch lookup from file
```

---

#### `Scalpel`
File carving from disk images and binary files.

```bash
scalpel disk.img -o output/                     # Carve from disk image
scalpel -c /etc/scalpel/scalpel.conf disk.img -o out/  # Custom config
scalpel -b memory.dmp -o output/                # Carve from memory dump
scalpel -q disk.img -o output/                  # Quick mode (no audit log)
```

---

## 9. General Utilities

---

#### `remnux` (REMnux Installer)
Install and update the REMnux distribution.

```bash
remnux update                                   # Update all tools
remnux upgrade                                  # Upgrade to new version
remnux install                                  # Fresh install
remnux status                                   # Check current status
```

---

#### `myip`
Quickly get the IP address of the default network interface.

```bash
myip                                            # Show current IP address
```

---

#### `7z` / `7za` / `7zr`
Compress and decompress files.

```bash
7z x archive.7z                                 # Extract archive
7z x malware.zip -o output/                    # Extract zip to directory
7z l archive.7z                                 # List archive contents
7z e archive.7z -p"password"                   # Extract with password
7z a output.7z /samples/                        # Create archive
7z t archive.7z                                 # Test archive integrity
7zz x archive.7z                                # Use newer 7zz binary
```

---

#### `zip` / `unzip`
Standard zip compression.

```bash
unzip malware.zip                               # Extract zip
unzip -l malware.zip                            # List contents
unzip -p malware.zip file.exe > extracted.exe  # Extract specific file to stdout
unzip malware.zip -d output/                   # Extract to directory
zip -r archive.zip /samples/                    # Create zip
```

---

#### `unrar` / `rar`
Decompress and create RAR archives.

```bash
unrar x malware.rar                             # Extract RAR
unrar l malware.rar                             # List contents
unrar p malware.rar file.exe > extracted.exe   # Extract file to stdout
rar x -p"password" protected.rar               # Extract with password
```

---

#### `cabextract`
Extract files from Microsoft Cabinet (.cab) archives.

```bash
cabextract malware.cab                          # Extract cab file
cabextract -l malware.cab                       # List cab contents
cabextract -d output/ malware.cab              # Extract to directory
```

---

#### `sqlite3`
Interact with SQLite database files (browser history, malware databases, etc.).

```bash
sqlite3 database.db                             # Open interactive mode
sqlite3 database.db ".tables"                  # List all tables
sqlite3 database.db "SELECT * FROM urls LIMIT 10;"  # Query table
sqlite3 database.db ".schema urls"             # Show table schema
sqlite3 database.db ".dump" > export.sql       # Dump entire database
sqlite3 database.db ".mode csv" ".output out.csv" "SELECT * FROM urls;"  # CSV export
```

---

#### `nasm`
x86-64 assembler for creating or reassembling code.

```bash
nasm -f bin shellcode.asm -o shellcode.bin      # Assemble to binary
nasm -f elf64 code.asm -o code.o                # Assemble to ELF object
nasm -l listing.txt -f bin shellcode.asm -o shellcode.bin  # With listing
```

---

#### `ssh` / `sshd` / `sftp`
Secure shell for remote connections.

```bash
ssh user@192.168.1.100                          # Connect to remote host
ssh -p 2222 user@192.168.1.100                 # Custom port
sftp user@192.168.1.100                         # SFTP connection
sftp -P 2222 user@192.168.1.100                # SFTP with custom port
sshd start                                      # Start SSH daemon
```

---

#### `pwsh` (PowerShell Core)
Run PowerShell scripts and commands cross-platform.

```bash
pwsh                                            # Interactive shell
pwsh -File malware.ps1                          # Execute script
pwsh -NoProfile -NonInteractive -File malware.ps1  # Clean execution
pwsh -Command "IEX (Get-Content malware.ps1 | Out-String)"  # Inline exec
# Decode common PowerShell obfuscation:
pwsh -Command "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('encoded_string_here'))"
```

---

#### `docker`
Run and manage analysis tool containers.

```bash
docker run --rm -it remnux/remnux-distro       # Run REMnux as container
docker run --rm -v $(pwd):/malware remnux/floss /malware/sample.exe  # Run FLOSS container
docker ps                                        # List running containers
docker images                                    # List images
docker pull remnux/capa                          # Pull a REMnux tool image
```

---

#### `wine`
Run Windows executables on Linux.

```bash
wine malware.exe                                # Execute Windows binary
wine malware.exe arg1 arg2                      # With arguments
WINEPREFIX=~/.wine32 WINEARCH=win32 wine malware.exe  # 32-bit prefix
wine reg add "HKLM\SOFTWARE\..." /v name /t REG_SZ /d value  # Edit registry
winecfg                                         # Configure Wine
```

---

#### `cast`
Manage SaltStack-based Linux distributions (used internally by REMnux).

```bash
cast apply                                      # Apply all states
cast apply remnux.tools.volatility3            # Install specific tool
cast list                                       # List states
```

---

#### `texteditor.py` (Didier Stevens)
Edit text files using search-and-replace from the command line.

```bash
texteditor.py -s "find_string" -r "replace_string" input.txt  # Find and replace
texteditor.py -r malware.ps1 "output.ps1"     # Regex replace
```

---

#### `sortcanon.py` (Didier Stevens)
Sort text files using canonicalization.

```bash
sortcanon.py input.txt                          # Sort with default canonicalization
sortcanon.py -c ip input.txt                   # Sort by IP address order
```

---

#### `myjson-filter.py` (Didier Stevens)
Filter JSON-formatted output from Didier Stevens' tools.

```bash
tool.py ... | myjson-filter.py -k "key"        # Filter by key
myjson-filter.py -k "type" -v "PE" input.json  # Filter by key=value
```

---

*Data sourced from the official REMnux documentation at https://docs.remnux.org*  
*Examples are based on standard tool usage and REMnux-specific notes from the documentation.*
