# SIFT Workstation — Complete Command-Line Tools Reference with Examples

> **Source**: [sans.org/tools/sift-workstation](https://www.sans.org/tools/sift-workstation) | [github.com/teamdfir/sift-saltstack](https://github.com/teamdfir/sift-saltstack) | Compiled June 2026  
> SIFT (SANS Investigative Forensic Toolkit) is a free, open-source DFIR workstation built on Ubuntu 22.04 (Jammy).  
> Default credentials: user `sansforensics` / password `forensics`

---

## Table of Contents
1. [Disk Imaging & Acquisition](#1-disk-imaging--acquisition)
2. [Evidence Mounting & File System Access](#2-evidence-mounting--file-system-access)
3. [Timeline Analysis](#3-timeline-analysis)
4. [Memory Forensics](#4-memory-forensics)
5. [Registry Analysis](#5-registry-analysis)
6. [Windows Artifact Analysis](#6-windows-artifact-analysis)
7. [Log & Event Analysis](#7-log--event-analysis)
8. [File Carving & Recovery](#8-file-carving--recovery)
9. [Hashing & Integrity](#9-hashing--integrity)
10. [Network Forensics](#10-network-forensics)
11. [Email & Browser Forensics](#11-email--browser-forensics)
12. [Password Recovery](#12-password-recovery)
13. [Encryption & Disk Decryption](#13-encryption--disk-decryption)
14. [String & Binary Analysis](#14-string--binary-analysis)
15. [Malware & Code Analysis](#15-malware--code-analysis)
16. [Threat Intelligence & Data Gathering](#16-threat-intelligence--data-gathering)
17. [General Utilities & Infrastructure](#17-general-utilities--infrastructure)

---

## 1. Disk Imaging & Acquisition

---

### `dc3dd`
Enhanced version of `dd` with hashing, logging, and forensic features built in.

```bash
# Basic image of a drive
dc3dd if=/dev/sdb of=/cases/image.dd

# Image with MD5 and SHA256 hashing and a log
dc3dd if=/dev/sdb of=/cases/image.dd hof=/cases/image.dd.log hash=md5 hash=sha256

# Image to multiple segments (split at 2GB)
dc3dd if=/dev/sdb ofs=/cases/image.dd.000 ofsz=2G

# Image to an E01/AFF via pipe (common SIFT workflow)
dc3dd if=/dev/sdb | ewfacquire -

# Wipe a drive securely
dc3dd if=/dev/zero of=/dev/sdb
```

---

### `dcfldd`
Another forensic `dd` variant from DoD Cyber Crime Lab with hashing and wiping.

```bash
dcfldd if=/dev/sdb of=/cases/image.dd hash=md5,sha256 hashlog=/cases/hash.log

# Split image
dcfldd if=/dev/sdb of=/cases/image.dd bs=512 split=2G splitformat=000

# Progress display
dcfldd if=/dev/sdb of=/cases/image.dd statusinterval=256
```

---

### `ewfacquire` / `ewfexport` / `ewfinfo` / `ewfmount` (libewf-tools)
Expert Witness Format (E01/EWF) acquisition and manipulation tools.

```bash
# Acquire evidence to E01
ewfacquire /dev/sdb
ewfacquire -t /cases/evidence /dev/sdb   # Specify output target

# Get image info / metadata
ewfinfo /cases/evidence.E01

# Export E01 to raw dd image
ewfexport -t /cases/evidence_raw /cases/evidence.E01

# Mount E01 read-only for examination
mkdir /mnt/ewf
ewfmount /cases/evidence.E01 /mnt/ewf

# Then mount the filesystem inside it
mount -o ro,loop,noatime /mnt/ewf/ewf1 /mnt/evidence
```

---

### `afflib-tools` (affinfo, affconvert, affcrypto, affsign, affcat)
Advanced Forensic Format (AFF) tools.

```bash
# Get image metadata
affinfo image.aff

# Convert dd to AFF
affconvert -o image.aff image.dd

# Convert AFF back to raw
affconvert -r -o image.dd image.aff

# Sign an AFF image
affsign image.aff

# Dump AFF to stdout
affcat image.aff > raw.dd
```

---

### `safecopy`
Data recovery tool that skips bad sectors and attempts to recover as much as possible.

```bash
safecopy /dev/sdb /cases/recovered.dd          # Full drive recovery
safecopy --stage1 /dev/sdb /cases/stage1.dd    # Stage 1: bulk copy
safecopy --stage2 /dev/sdb /cases/stage2.dd    # Stage 2: retry bad blocks
safecopy --stage3 /dev/sdb /cases/stage3.dd    # Stage 3: aggressive retry
```

---

### `gddrescue` (GNU ddrescue)
Data recovery copying tool that handles read errors gracefully.

```bash
ddrescue /dev/sdb /cases/image.dd /cases/image.log    # Basic with log
ddrescue -d -r3 /dev/sdb /cases/image.dd /cases/image.log  # Direct access, 3 retries
ddrescue -m /cases/image.log /dev/sdb /cases/image.dd      # Resume from log
```

---

### `xmount`
Convert between disk image formats on-the-fly, including E01, AFF, VMDK, VHD.

```bash
# Mount E01 as raw image
xmount --in ewf /cases/evidence.E01 /mnt/xmount/

# Mount as VHD
xmount --in ewf --out vhd /cases/evidence.E01 /mnt/xmount/

# With cache file for write operations (keeps source read-only)
xmount --in ewf --out raw --cache /tmp/cache.xmount /cases/evidence.E01 /mnt/xmount/
```

---

## 2. Evidence Mounting & File System Access

---

### `ewfmount` + `mount` (standard workflow)
The standard SIFT workflow for mounting disk images.

```bash
# Step 1: Mount the E01
mkdir /mnt/ewf /mnt/windows
ewfmount /cases/evidence.E01 /mnt/ewf

# Step 2: Check partition layout
mmls /mnt/ewf/ewf1
# or:
fdisk -l /mnt/ewf/ewf1

# Step 3: Mount the Windows partition (offset in 512-byte sectors × 512)
# e.g., if mmls shows partition starting at sector 2048:
mount -o ro,loop,noatime,offset=$((2048*512)) /mnt/ewf/ewf1 /mnt/windows

# Step 4: Unmount
umount /mnt/windows
umount /mnt/ewf
fusermount -u /mnt/ewf
```

---

### `kpartx`
Create device maps from partition tables in disk images.

```bash
kpartx -a -v image.dd                  # Add partition maps from image
kpartx -l image.dd                     # List partitions
ls /dev/mapper/                        # View created mappings (e.g., loop0p1)
mount -o ro /dev/mapper/loop0p1 /mnt/windows
kpartx -d image.dd                     # Remove mappings
```

---

### `mmls` (Sleuth Kit)
Display partition layout of a disk image.

```bash
mmls image.dd                          # List partitions
mmls -t dos image.dd                   # Force DOS partition table
mmls -o 0 image.dd                     # Specify offset
```

---

### `fsstat` (Sleuth Kit)
Show file system details (type, block size, timestamps, etc.).

```bash
fsstat image.dd                        # Analyze file system
fsstat -o 2048 image.dd               # With offset in sectors
fsstat -f ntfs image.dd               # Force NTFS analysis
```

---

### `fls` (Sleuth Kit)
List files and directories in a forensic image, including deleted entries.

```bash
fls image.dd                           # List root directory
fls -r image.dd                        # Recursive list
fls -d image.dd                        # Deleted files only
fls -u image.dd                        # Unallocated entries only
fls -o 2048 image.dd                   # With partition offset
fls -r -m / image.dd > bodyfile.txt    # Create bodyfile for timeline
```

---

### `istat` (Sleuth Kit)
Display details about a specific inode/file system entry.

```bash
istat image.dd 128                     # Show inode 128
istat -o 2048 image.dd 128            # With partition offset
```

---

### `icat` (Sleuth Kit)
Extract the contents of a file by inode number.

```bash
icat image.dd 128 > recovered_file    # Extract file by inode
icat -o 2048 image.dd 128 > file      # With partition offset
```

---

### `ifind` (Sleuth Kit)
Find the meta-data structure for a given file name or allocated block.

```bash
ifind -n "Windows/System32/ntdll.dll" image.dd  # Find inode by filename
ifind -d 12345 image.dd                           # Find inode owning data block
```

---

### `ffind` (Sleuth Kit)
Find file names given an inode number.

```bash
ffind image.dd 128                     # Find filename for inode 128
ffind -a image.dd 128                 # Include deleted filenames
```

---

### `blkls` / `blkcat` / `blkstat` (Sleuth Kit)
Work with raw data blocks in a file system.

```bash
blkls image.dd > unallocated.bin       # Extract unallocated space
blkls -A image.dd > allocated.bin      # Extract allocated space
blkcat image.dd 1234 > block.bin       # Extract specific block
blkstat image.dd 1234                  # Show block status
```

---

### `sorter` (Sleuth Kit)
Sort files in a forensic image by file type (using magic signatures).

```bash
sorter -d /cases/sorted/ image.dd      # Sort all files
sorter -s /cases/sorted/ -m /cases/mnt/ image.dd  # With mounted path
sorter -l /cases/sorted/ image.dd      # List files by category
```

---

### `tsk_recover` (Sleuth Kit)
Recover files from a forensic image to a directory.

```bash
tsk_recover image.dd /cases/recovered/          # Recover all files
tsk_recover -e image.dd /cases/recovered/       # Include deleted files
tsk_recover -t ntfs image.dd /cases/recovered/  # Force NTFS
```

---

### `tsk_gettimes` (Sleuth Kit)
Extract MAC times from a forensic image into a bodyfile.

```bash
tsk_gettimes image.dd > bodyfile.txt
tsk_gettimes -o 2048 image.dd > bodyfile.txt
```

---

### `disktype`
Detect file system and partition types in a disk image.

```bash
disktype image.dd                      # Auto-detect filesystem types
disktype /dev/sdb                      # On a live device
```

---

### `ntfs-3g`
Mount NTFS file systems with full read/write access.

```bash
ntfs-3g -o ro /dev/sdb1 /mnt/windows  # Mount NTFS read-only
ntfs-3g /dev/sdb1 /mnt/windows         # Mount read-write (NOT for forensics)
```

---

### `vmfs-tools`
Access VMware VMFS file systems from forensic images.

```bash
vmfs-fuse /dev/sdb1 /mnt/vmfs          # Mount VMFS filesystem
vmfs-tools /dev/sdb1 ls /             # List root directory
```

---

### `libvshadow-tools` (vshadowinfo, vshadowmount)
Access Windows Volume Shadow Copies from forensic images.

```bash
# List available shadow copies
vshadowinfo /mnt/ewf/ewf1

# Mount all shadow copies
mkdir /mnt/vss
vshadowmount /mnt/ewf/ewf1 /mnt/vss

# Access individual shadow copies
ls /mnt/vss/
mount -o ro,loop /mnt/vss/vss1 /mnt/shadow1
```

---

### `libfvde-tools` (fvdeinfo, fvdemount)
Access FileVault 2 encrypted volumes.

```bash
fvdeinfo /dev/sdb1                     # Show FileVault 2 info
fvdemount -p "password" /dev/sdb1 /mnt/fvde/  # Mount with password
fvdemount -r recovery_key /dev/sdb1 /mnt/fvde/ # Mount with recovery key
```

---

### `libfsapfs-tools` (fsapfsinfo, fsapfsmount)
Access Apple File System (APFS) volumes.

```bash
fsapfsinfo image.dd                    # Show APFS volume info
fsapfsmount image.dd /mnt/apfs/        # Mount APFS volume
```

---

### `avfs`
Virtual filesystem providing read-only access to archives (zip, tar, gz, etc.) as directories.

```bash
mountavfs                              # Mount AVFS virtual filesystem
ls ~/.avfs/path/to/archive.zip#/       # Browse inside archive
fusermount -u ~/.avfs                  # Unmount
```

---

### `xfsprogs` (xfs_db, xfs_repair, xfs_info)
Tools for XFS file system analysis.

```bash
xfs_info /dev/sdb1                     # Show XFS volume info
xfs_db -r /dev/sdb1                    # Open XFS debugger (read-only)
xfs_db -r -c "sb 0" -c "print" /dev/sdb1  # Show superblock
```

---

### `dislocker`
Access BitLocker-encrypted volumes.

```bash
dislocker -V /dev/sdb1 -u"password" -- /mnt/dislocker/  # Unlock with password
dislocker -V /dev/sdb1 -r recovery_key.txt -- /mnt/dislocker/ # With recovery key
mount -o ro /mnt/dislocker/dislocker-file /mnt/windows/  # Mount unlocked volume
```

---

## 3. Timeline Analysis

---

### `log2timeline.py` / `plog2timeline.py` (Plaso)
Extract timestamps from hundreds of artifact types and aggregate into a supertimeline.

```bash
# Basic timeline from a disk image
log2timeline.py /cases/timeline.plaso /cases/image.dd

# From a mounted directory
log2timeline.py /cases/timeline.plaso /mnt/windows/

# Specify timezone
log2timeline.py --timezone Australia/Sydney /cases/timeline.plaso image.dd

# Only run specific parsers
log2timeline.py --parsers "winreg,winevt,prefetch" timeline.plaso image.dd

# Analyze a memory image
log2timeline.py timeline.plaso memory.dmp

# Include Volume Shadow Copies
log2timeline.py --vss-stores all timeline.plaso image.dd

# Parse from a specific partition offset
log2timeline.py -o 2048 timeline.plaso image.dd
```

---

### `psort.py` (Plaso)
Sort and filter Plaso output, export to various formats (CSV, timeline, JSON).

```bash
# Export to CSV (human-readable)
psort.py -o l2tcsv /cases/timeline.plaso /cases/timeline.csv

# Export with time filter
psort.py -o l2tcsv -q "date > '2024-01-01 00:00:00'" timeline.plaso filtered.csv

# Export to JSON
psort.py -o json timeline.plaso timeline.json

# Export to Excel
psort.py -o xlsx timeline.plaso timeline.xlsx

# Filter by hostname
psort.py -o l2tcsv --filter "hostname contains 'DESKTOP-ABC'" timeline.plaso out.csv

# Show statistics
psort.py --analysis statistics timeline.plaso /dev/null
```

---

### `pinfo.py` (Plaso)
Show information and statistics about a Plaso storage file.

```bash
pinfo.py timeline.plaso               # Summary info
pinfo.py -v timeline.plaso            # Verbose (all parsers used)
```

---

### `mactime` (Sleuth Kit / Perl)
Create a human-readable timeline from a bodyfile.

```bash
# Create bodyfile first
fls -r -m / image.dd > bodyfile.txt

# Generate timeline for a date range
mactime -b bodyfile.txt -d -z UTC "2024-01-01" "2024-12-31" > timeline.csv

# Timeline without date filter
mactime -b bodyfile.txt -d > timeline.csv

# With timezone offset
mactime -b bodyfile.txt -d -z "US/Eastern" > timeline.csv
```

---

### `tln.pl` (Harlan Carvey / keydet89 tools)
Timeline analysis tool — combines bodyfile and event log entries.

```bash
tln.pl -b bodyfile.txt > timeline.tln   # From bodyfile
tln.pl -e events.txt > timeline.tln     # From event logs
```

---

## 4. Memory Forensics

---

### `vol3` / `vol.py` (Volatility 3)
The primary memory forensics framework on SIFT.

```bash
# Windows memory analysis
vol3 -f memory.dmp windows.info              # Basic image info
vol3 -f memory.dmp windows.pslist            # Process list
vol3 -f memory.dmp windows.pstree           # Process tree (parent-child)
vol3 -f memory.dmp windows.cmdline          # Command-line args per process
vol3 -f memory.dmp windows.dlllist          # DLLs per process
vol3 -f memory.dmp windows.handles          # Open handles per process
vol3 -f memory.dmp windows.handles --pid 1234  # Handles for specific PID
vol3 -f memory.dmp windows.malfind          # Find injected code / shellcode
vol3 -f memory.dmp windows.netscan          # Network connections (current + recent)
vol3 -f memory.dmp windows.netstat          # Active network connections
vol3 -f memory.dmp windows.filescan         # Scan for FILE_OBJECT structs
vol3 -f memory.dmp windows.dumpfiles        # Dump cached files
vol3 -f memory.dmp windows.dumpfiles --pid 1234  # Dump files for PID
vol3 -f memory.dmp windows.memmap           # Memory map per process
vol3 -f memory.dmp windows.vadinfo          # Virtual Address Descriptor info
vol3 -f memory.dmp windows.vadwalk          # Walk VAD tree
vol3 -f memory.dmp windows.procdump         # Dump process executable
vol3 -f memory.dmp windows.procdump --pid 1234 --dump-dir /output/
vol3 -f memory.dmp windows.modscan          # Scan for kernel modules
vol3 -f memory.dmp windows.driverscan       # Scan for driver objects
vol3 -f memory.dmp windows.svcscan          # Scan for services
vol3 -f memory.dmp windows.callbacks        # Kernel callbacks (rootkit detection)
vol3 -f memory.dmp windows.ssdt            # System Service Descriptor Table
vol3 -f memory.dmp windows.mutantscan       # Scan for mutex objects
vol3 -f memory.dmp windows.envars           # Environment variables
vol3 -f memory.dmp windows.registry.hivelist  # List registry hives
vol3 -f memory.dmp windows.registry.printkey -K "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
vol3 -f memory.dmp windows.registry.userassist  # UserAssist keys
vol3 -f memory.dmp windows.hashdump         # Dump password hashes (SAM)

# Linux memory analysis
vol3 -f memory.dmp linux.pslist            # Process list
vol3 -f memory.dmp linux.bash             # Bash history from memory
vol3 -f memory.dmp linux.netstat          # Network connections
vol3 -f memory.dmp linux.malfind          # Find injected code

# macOS memory analysis
vol3 -f memory.dmp mac.pslist
vol3 -f memory.dmp mac.netstat
```

---

### `aeskeyfind`
Find AES keys in a memory dump.

```bash
aeskeyfind memory.dmp                  # Find all AES keys (128 and 256-bit)
aeskeyfind -v memory.dmp              # Verbose output
```

---

### `rsakeyfind`
Find RSA private keys in a memory dump.

```bash
rsakeyfind memory.dmp                  # Scan for RSA private keys
```

---

### `bulk_extractor`
Extract artifacts from memory images (emails, URLs, credit cards, etc.).

```bash
bulk_extractor -o /cases/output/ memory.dmp         # Full extraction
bulk_extractor -e email -o /cases/ memory.dmp        # Email only
bulk_extractor -e net -o /cases/ memory.dmp          # Network artifacts
bulk_extractor -e url -o /cases/ memory.dmp          # URLs
bulk_extractor -e ccn -o /cases/ memory.dmp          # Credit card numbers
bulk_extractor -r /cases/output/ memory.dmp          # Recursive (all features)
```

---

## 5. Registry Analysis

---

### `regripper` / `rip.pl`
Extract and decode Windows registry data using plugins.

```bash
# List available plugins
rip.pl -l

# Run a specific plugin against a hive
rip.pl -r /mnt/windows/Windows/System32/config/SYSTEM -p system

# Run all plugins against a hive
rip.pl -r NTUSER.DAT -f ntuser

# Common hive / plugin combinations:
rip.pl -r SAM -p samparse            # User accounts from SAM
rip.pl -r SYSTEM -p sysinfo          # System info (timezone, computer name)
rip.pl -r SYSTEM -p usbstor          # USB devices connected
rip.pl -r SYSTEM -p services         # Installed services
rip.pl -r SOFTWARE -p uninstall      # Installed programs
rip.pl -r SOFTWARE -p mru            # Most Recently Used lists
rip.pl -r NTUSER.DAT -p userassist   # UserAssist (program execution)
rip.pl -r NTUSER.DAT -p recentdocs   # Recent documents
rip.pl -r NTUSER.DAT -p runkeys      # Run keys (persistence)
rip.pl -r NTUSER.DAT -p shellbags    # ShellBags (folder access)
rip.pl -r NTUSER.DAT -p muicache     # MUICache (program execution)
rip.pl -r USRCLASS.DAT -p shellbags  # ShellBags (user class hive)
rip.pl -r SECURITY -p secrets        # LSA secrets

# Redirect output to file
rip.pl -r NTUSER.DAT -f ntuser > ntuser_output.txt
```

---

### `libregf-tools` (regfinfo, regfexport)
Low-level access to Windows Registry hive files.

```bash
regfinfo NTUSER.DAT                    # Show hive metadata
regfexport NTUSER.DAT output/          # Export all keys as text files
```

---

### `libevt-tools` (evtinfo, evtexport)
Parse legacy Windows EVT event log files.

```bash
evtinfo Security.evt                   # Show event log metadata
evtexport Security.evt                 # Export all events
evtexport -o text Security.evt         # Text output
```

---

### `libevtx-tools` (evtxinfo, evtxexport)
Parse Windows EVTX (Vista+) event log files.

```bash
evtxinfo Security.evtx                  # Show event log metadata
evtxexport Security.evtx                # Export all events to stdout
evtxexport -o xml Security.evtx         # XML output
evtxexport -o text Security.evtx        # Text output
evtxexport -o csv Security.evtx > events.csv  # CSV output
```

---

### `evtxparse.pl` / `evtparse.pl` (keydet89 tools)
Parse Windows event logs with context-aware output.

```bash
evtxparse.pl Security.evtx > events.txt   # Parse EVTX
evtparse.pl Security.evt > events.txt     # Parse legacy EVT
```

---

### `parse.pl` (keydet89)
Parse various Windows artifacts (Prefetch, LNK, etc.).

```bash
parse.pl -m d -d /cases/evidence/   # Parse all supported files in directory
```

---

### `samdump2`
Dump password hashes from the Windows SAM database.

```bash
samdump2 SYSTEM SAM                    # Dump hashes (requires both hives)
samdump2 -o hashes.txt SYSTEM SAM     # Save to file
```

---

## 6. Windows Artifact Analysis

---

### `pref.pl` / `prefetch` analysis (keydet89 tools)
Parse Windows Prefetch files (evidence of execution).

```bash
pref.pl -d /mnt/windows/Windows/Prefetch/   # Parse all prefetch files
pref.pl -f /mnt/windows/Windows/Prefetch/NOTEPAD.EXE-12345678.pf  # Single file
```

---

### `lnk.pl` (keydet89)
Parse Windows LNK (shortcut) files.

```bash
lnk.pl file.lnk                        # Parse LNK file
lnk.pl -d /mnt/windows/Users/user/Recent/  # Parse all LNK files in directory
```

---

### `jl.pl` (keydet89 — Jump List parser)
Parse Windows Jump Lists.

```bash
jl.pl jumplist.automaticDestinations    # Parse a jump list file
jl.pl -d /mnt/windows/Users/user/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/
```

---

### `mft.pl` (keydet89)
Parse the NTFS Master File Table ($MFT).

```bash
mft.pl -f /cases/MFT > mft_output.txt   # Parse MFT file
mft.pl -f /cases/MFT -b > bodyfile.txt  # Output as bodyfile
```

---

### `usnj.pl` (keydet89)
Parse the NTFS USN Journal ($UsnJrnl).

```bash
usnj.pl -f /cases/UsnJrnl > usnjrnl.txt  # Parse USN journal
```

---

### `recbin.pl` (keydet89)
Parse the Windows Recycle Bin ($Recycle.Bin / INFO2).

```bash
recbin.pl -f /cases/$Recycle.Bin/         # Parse Recycle Bin folder
recbin.pl -f /mnt/windows/\$Recycle.Bin/
```

---

### `regtime.pl` (keydet89)
Parse registry hive timestamps for timeline.

```bash
regtime.pl -r NTUSER.DAT > regtime.txt   # Extract registry key timestamps
regtime.pl -r SYSTEM >> regtime.txt
```

---

### `regslack.pl` (keydet89)
Extract slack space from Windows Registry hives.

```bash
regslack.pl NTUSER.DAT                   # Dump registry slack space
```

---

### `jobparse.pl` (keydet89)
Parse Windows Scheduled Tasks (.job files).

```bash
jobparse.pl file.job                     # Parse .job file
jobparse.pl -d /mnt/windows/Windows/System32/Tasks/  # Parse all
```

---

### `parseie.pl` (keydet89)
Parse Internet Explorer browsing history.

```bash
parseie.pl -f index.dat                  # Parse IE index.dat
parseie.pl -d /mnt/windows/Users/user/AppData/Local/Microsoft/Windows/History/
```

---

### `ff.pl` / `ff_signons.pl` (keydet89)
Parse Firefox history and saved passwords.

```bash
ff.pl -d /mnt/windows/Users/user/AppData/Roaming/Mozilla/Firefox/Profiles/  # History
ff_signons.pl -f signons.sqlite          # Saved passwords
```

---

### `bodyfile.pl` (keydet89)
Create bodyfile format from various Windows artifacts.

```bash
bodyfile.pl -d /mnt/windows/ > bodyfile.txt  # Create bodyfile from directory
```

---

### `idx.pl` / `idxparse.pl` (keydet89)
Parse Java IDX (cache) files.

```bash
idx.pl -f file.idx                       # Parse IDX file
idxparse.pl -d /mnt/windows/Users/user/AppData/LocalLow/Sun/Java/Deployment/cache/
```

---

### `pff-tools` / `libpff` (pffexport, pffinfo)
Parse Personal Folder File (PST/OST) Outlook data files.

```bash
pffinfo email.pst                        # Show PST file info
pffexport email.pst                      # Export all emails and attachments
pffexport -t all email.pst -o output/    # Export to directory
```

---

### `libmsiecf` (msiecfinfo, msiecfexport)
Parse Microsoft Internet Explorer Cache File (index.dat).

```bash
msiecfinfo index.dat                     # Show index.dat metadata
msiecfexport index.dat                   # Export all cache entries
msiecfexport -o csv index.dat > ie_history.csv  # CSV output
```

---

### `libesedb-tools` (esedbinfo, esedbexport)
Parse Extensible Storage Engine (ESE/JET) databases (used by IE, Exchange, AD, Windows Search).

```bash
esedbinfo WebCacheV01.dat                # Show ESE database info
esedbexport WebCacheV01.dat              # Export all tables
esedbexport -t Containers WebCacheV01.dat  # Export specific table

# Common ESE databases:
# C:\Windows\System32\sru\SRUDB.dat     (System Resource Usage)
# C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb  (Windows Search)
# C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat (IE/Edge history)
```

---

### `libplist-utils`
Parse Apple property list (plist) files.

```bash
plistutil -i file.plist                  # Parse binary or XML plist
plistutil -i file.plist -o text.plist -f xml  # Convert binary to XML
```

---

### `upx-ucl`
Unpack UPX-packed executables.

```bash
upx -d packed.exe -o unpacked.exe        # Decompress packed binary
upx -l packed.exe                        # Show packing info
upx -t packed.exe                        # Test if valid UPX
```

---

## 7. Log & Event Analysis

---

### `evtxexport` + `grep`
Most common pattern for searching event logs.

```bash
evtxexport Security.evtx | grep "EventID>4624"  # Successful logons
evtxexport Security.evtx | grep "EventID>4625"  # Failed logons
evtxexport System.evtx   | grep "EventID>7045"  # New service installed
evtxexport Security.evtx | grep "EventID>4720"  # New user created
evtxexport Security.evtx | grep "EventID>4776"  # Credential validation
evtxexport System.evtx   | grep "EventID>104"   # Event log cleared
```

---

### `plaso-tools` (psort.py timeline with event log filter)
Timeline filtering for event log investigation.

```bash
psort.py -o l2tcsv -q "source_short eq 'EVT'" timeline.plaso evt_only.csv
psort.py -o l2tcsv -q "data_type eq 'windows:evtx:record'" timeline.plaso evtx.csv
```

---

### `nfdump` / `nfcapd`
Read and analyze NetFlow capture data.

```bash
nfcapd -l /var/flows/ -p 9995           # Collect NetFlow data on port 9995
nfdump -r /var/flows/nfcapd.202401010000 # Read flow file
nfdump -r /var/flows/ -s ip/bytes       # Top IPs by bytes
nfdump -r /var/flows/ -f 'host 10.0.0.1' # Filter by host
nfdump -r /var/flows/ -t 2024/01/01.00:00:00-2024/01/01.23:59:59  # Time filter
nfdump -r /var/flows/ -o extended       # Extended output format
nfdump -r /var/flows/ 'proto tcp and port 80'  # TCP port 80 only
```

---

## 8. File Carving & Recovery

---

### `foremost`
Carve files from disk images based on file headers, footers, and internal structures.

```bash
foremost -i image.dd -o /cases/foremost_out/      # Carve from image
foremost -t jpeg,pdf,doc -i image.dd -o output/   # Carve specific types
foremost -v -i image.dd -o output/                # Verbose mode
foremost -i unallocated.bin -o output/            # From extracted unallocated space
foremost -c /etc/foremost.conf -i image.dd -o out/ # Custom config
```

---

### `scalpel`
Fast file carver using configurable header/footer definitions.

```bash
scalpel image.dd -o /cases/scalpel_out/           # Basic carving
scalpel -c /etc/scalpel/scalpel.conf image.dd -o out/  # Custom config
scalpel -b image.dd -o output/                    # No audit log
```

---

### `testdisk`
Recover lost partitions and repair partition tables.

```bash
testdisk image.dd                      # Interactive partition recovery
testdisk /list image.dd                # List partitions without interaction
```

---

### `photorec` (part of testdisk)
Recover deleted photos and files from disk images.

```bash
photorec image.dd                      # Interactive file recovery
photorec /d /cases/recovered/ image.dd # Specify output directory
```

---

### `extundelete`
Recover deleted files from ext3/ext4 file systems.

```bash
extundelete image.dd --restore-all     # Restore all deleted files
extundelete image.dd --restore-file path/to/file.txt  # Specific file
extundelete image.dd --restore-directory /home/user/  # Restore directory
extundelete image.dd --after 1704067200  # Files deleted after Unix timestamp
```

---

### `gzrt`
Recover data from damaged or incomplete gzip files.

```bash
gzrt damaged.gz > recovered.dat        # Attempt recovery
```

---

## 9. Hashing & Integrity

---

### `hashdeep` / `md5deep` / `sha256deep`
Hash files and verify integrity, with recursive support and audit mode.

```bash
# Compute hashes
hashdeep -r /mnt/evidence/             # Recursive SHA256+MD5+SHA1
md5deep -r /mnt/evidence/             # MD5 only, recursive
sha256deep -r /mnt/evidence/          # SHA256 only, recursive

# Create a hash manifest
hashdeep -r /mnt/evidence/ > hashes.txt

# Verify against baseline
hashdeep -r -a -k hashes.txt /mnt/evidence/   # Audit mode
hashdeep -r -m -k hashes.txt /mnt/evidence/   # Match mode (known files)

# Negative matching (find files NOT in baseline)
hashdeep -r -X -k baseline.txt /mnt/evidence/

# md5deep with specific format
md5deep -rl /mnt/evidence/ > md5_hashes.txt    # Relative paths
```

---

### `ssdeep`
Fuzzy hashing for similarity comparison.

```bash
ssdeep malware.exe                            # Compute fuzzy hash
ssdeep -r /mnt/evidence/                     # Recursive
ssdeep -m known_hashes.txt unknown.exe        # Match against known
ssdeep -la /samples/                          # Compare all files in dir
```

---

### `dc3dd` (with hashing)
Forensic imaging with integrated hashing (see section 1).

```bash
dc3dd if=/dev/sdb of=image.dd hash=sha256 hlog=hashes.log
```

---

## 10. Network Forensics

---

### `wireshark`
GUI network traffic analysis.

```bash
wireshark                              # Launch GUI
wireshark capture.pcap                 # Open pcap in GUI
```

---

### `tshark`
Wireshark command-line interface.

```bash
tshark -r capture.pcap                                    # Read pcap
tshark -r capture.pcap -Y "http"                          # HTTP only
tshark -r capture.pcap -Y "dns"                           # DNS only
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport  # Extract fields
tshark -r capture.pcap -z conv,tcp                        # TCP conversations
tshark -r capture.pcap -z follow,tcp,ascii,0              # Follow stream 0
tshark -r capture.pcap --export-objects http,./extracted/ # Export HTTP objects
tshark -r capture.pcap -R "frame.time >= '2024-01-01'"   # Time filter
tshark -r capture.pcap -z io,phs                          # Protocol stats
tshark -r capture.pcap -2 -R "http.request" -T fields -e http.host -e http.request.uri
```

---

### `tcpdump`
Command-line packet capture and analysis.

```bash
tcpdump -i eth0                               # Capture live
tcpdump -i eth0 -w capture.pcap              # Write to file
tcpdump -r capture.pcap                      # Read from file
tcpdump -r capture.pcap host 192.168.1.100   # Filter by host
tcpdump -r capture.pcap port 443             # HTTPS traffic
tcpdump -r capture.pcap -A                   # ASCII output
tcpdump -r capture.pcap -X                   # Hex + ASCII output
tcpdump -r capture.pcap -n                   # No DNS resolution
```

---

### `tcpflow`
Reconstruct and reassemble TCP streams from pcap files.

```bash
tcpflow -r capture.pcap                      # Extract flows
tcpflow -r capture.pcap -o /cases/flows/     # Save to directory
tcpflow -c -r capture.pcap                   # Console mode
tcpflow -r capture.pcap -e http              # HTTP extraction mode
```

---

### `tcpxtract`
Extract files from network traffic captures.

```bash
tcpxtract -f capture.pcap                    # Extract files
tcpxtract -f capture.pcap -o /cases/files/   # Save to directory
```

---

### `tcptrace`
Analyze TCP connections in pcap files.

```bash
tcptrace capture.pcap                        # Basic analysis
tcptrace -l capture.pcap                     # Long output
tcptrace -n capture.pcap                     # No DNS resolution
tcptrace -r capture.pcap                     # Print RTT info
tcptrace -G capture.pcap                     # Generate graphs
```

---

### `tcpreplay`
Replay pcap files back onto the network.

```bash
tcpreplay -i eth0 capture.pcap               # Replay at original speed
tcpreplay -x 10 -i eth0 capture.pcap        # Replay at 10× speed
tcpreplay --mbps=100 -i eth0 capture.pcap   # Replay at 100 Mbps
tcpreplay -t -i eth0 capture.pcap            # Replay as fast as possible
```

---

### `tcpick`
TCP stream sniffer and follower.

```bash
tcpick -C -r capture.pcap                    # Reconstruct streams
tcpick -r capture.pcap -wR                   # Write each stream to file
```

---

### `tcpslice`
Extract time slices from pcap files.

```bash
tcpslice 2024-01-01 2024-01-02 big.pcap > slice.pcap  # 24-hour slice
```

---

### `tcpstat`
Show network statistics from pcap files.

```bash
tcpstat -r capture.pcap -f "port 80" -o "%R\n" 10   # HTTP stats every 10s
tcpstat -r capture.pcap -o "%T %N\n" 1               # Packet count per second
```

---

### `tcptrack`
Monitor TCP connections live.

```bash
tcptrack -i eth0                             # Monitor all TCP connections
tcptrack -i eth0 -f capture.pcap            # From pcap
```

---

### `ngrep`
Network grep — pattern match in packet payloads.

```bash
ngrep -i "password" port 80                  # HTTP passwords
ngrep "GET|POST" port 80                     # HTTP methods
ngrep -d eth0 "cmd.exe" port 4444            # C2 shell commands
ngrep -q "." host 192.168.1.100              # All traffic to/from host
```

---

### `ssldump`
Decode and dump SSL/TLS traffic (requires private key or session key log).

```bash
ssldump -r capture.pcap                      # Decode SSL
ssldump -r capture.pcap -k server.key        # With private key
ssldump -r capture.pcap -k server.key -d     # Also dump data
ssldump -i eth0                              # Live capture
```

---

### `nfdump`
Read and analyze NetFlow/IPFIX data (see section 7).

---

### `nbtscan`
Scan network for NetBIOS names.

```bash
nbtscan 192.168.1.0/24                       # Scan subnet
nbtscan -v 192.168.1.100                     # Verbose single host
nbtscan -r 192.168.1.0/24                    # Reverse DNS
```

---

### `arp-scan`
Discover hosts on a local network using ARP.

```bash
sudo arp-scan -l                             # Scan local network
sudo arp-scan 192.168.1.0/24                # Scan subnet
sudo arp-scan --interface=eth0 192.168.1.0/24
```

---

### `p0f`
Passive OS fingerprinting from network traffic.

```bash
p0f -r capture.pcap                          # Fingerprint from pcap
p0f -i eth0                                  # Live passive fingerprinting
p0f -r capture.pcap -o /tmp/p0f.log          # Log results
```

---

### `dsniff`
Passive protocol analysis and credential sniffing toolkit.

```bash
dsniff -p capture.pcap                       # Analyze from pcap
dsniff -i eth0                               # Live sniffing
urlsnarf -p capture.pcap                     # Extract URLs
msgsnarf -p capture.pcap                     # Extract messages
```

---

### `socat`
Multipurpose relay — connect two data streams.

```bash
socat TCP-LISTEN:4444,fork STDOUT            # TCP listener to stdout
socat - TCP:192.168.1.100:4444               # Connect and interact
socat TCP-LISTEN:8080,fork TCP:10.0.0.1:80  # TCP proxy
socat OPENSSL-LISTEN:443,fork STDOUT         # TLS listener
socat UDP-LISTEN:5353 -                      # UDP listener
```

---

### `netcat` (nc)
Network utility for reading/writing over TCP/UDP.

```bash
nc -lvp 4444                                  # Listen on port 4444
nc 192.168.1.100 4444                         # Connect
nc -lvp 4444 > received_file                  # Receive file
nc 192.168.1.100 4444 < file_to_send          # Send file
nc -z -v 192.168.1.100 1-1024                # Port scan
```

---

### `cryptcat`
Netcat with Twofish encryption.

```bash
cryptcat -lvp 4444 -k "secret"               # Encrypted listener
cryptcat 192.168.1.100 4444 -k "secret"      # Encrypted connection
```

---

## 11. Email & Browser Forensics

---

### `pffexport` / `pffinfo` (libpff)
Parse PST and OST Outlook data files.

```bash
pffinfo email.pst                            # File metadata
pffexport email.pst                          # Export all to current dir
pffexport -t all -o /cases/pst_export/ email.pst  # Full export
```

---

### `readpst` (pst-utils)
Convert Outlook PST files to mbox/vcard format.

```bash
readpst email.pst                            # Convert to mbox
readpst -o /cases/pst_out/ email.pst         # Output to directory
readpst -S /cases/pst_out/ email.pst         # Separate files per folder
readpst -b email.pst                         # Include deleted items
```

---

### `msiecfexport` (libmsiecf)
Export Internet Explorer cache/history records.

```bash
msiecfexport index.dat                       # Export to stdout
msiecfexport -o csv index.dat > ie_cache.csv # CSV format
```

---

### `parseie.pl` (keydet89)
Parse IE history records.

```bash
parseie.pl -f index.dat > ie_history.txt
```

---

### `ff.pl` (keydet89 — Firefox parser)
Parse Firefox browser artifacts.

```bash
ff.pl -d /mnt/windows/Users/user/AppData/Roaming/Mozilla/Firefox/Profiles/
```

---

## 12. Password Recovery

---

### `samdump2`
Dump NTLM password hashes from Windows SAM database.

```bash
samdump2 SYSTEM SAM                          # Dump hashes
samdump2 -o hashes.txt SYSTEM SAM           # Save to file
```

---

### `ophcrack-cli`
Crack Windows password hashes using rainbow tables.

```bash
ophcrack -g -d /usr/share/ophcrack/tables/ -f hashes.txt  # Crack from file
ophcrack -t /path/to/tables/ -f hashes.txt  # Custom table location
```

---

### `hydra` / `hydra-gtk`
Fast network login cracker (use in lab only).

```bash
hydra -l admin -P wordlist.txt ssh://192.168.1.100     # SSH brute-force
hydra -L users.txt -P passwords.txt ftp://192.168.1.100  # FTP
hydra -l admin -P wordlist.txt http-get://192.168.1.100/admin  # HTTP Basic Auth
hydra -l admin -P wordlist.txt 192.168.1.100 smb       # SMB
hydra -t 4 -l admin -P wordlist.txt rdp://192.168.1.100  # RDP (4 threads)
hydra-gtk                                               # GUI version
```

---

### `cmospwd`
Decrypt CMOS/BIOS passwords.

```bash
cmospwd                                      # Read current CMOS password
cmospwd /k                                   # Kill CMOS password
```

---

### `ccrypt`
Encrypt and decrypt files using Rijndael cipher.

```bash
ccrypt -e file.txt                           # Encrypt file
ccrypt -d file.txt.cpt                       # Decrypt file
ccencrypt -k "passphrase" -e file.txt        # Encrypt with passphrase
```

---

## 13. Encryption & Disk Decryption

---

### `dislocker`
Access BitLocker-encrypted partitions.

```bash
dislocker -V /dev/sdb1 -u"password" -- /mnt/dislocker/
dislocker -V /dev/sdb1 -r recovery_key.txt -- /mnt/dislocker/
mount -o ro /mnt/dislocker/dislocker-file /mnt/windows/
```

---

### `libfvde-tools` (fvdemount)
Access FileVault 2 encrypted macOS volumes.

```bash
fvdemount -p "password" /dev/sdb1 /mnt/fvde/
fvdemount -r recovery_key /dev/sdb1 /mnt/fvde/
mount -o ro /mnt/fvde/fvde1 /mnt/mac/
```

---

### `cryptsetup`
Access LUKS-encrypted Linux partitions.

```bash
cryptsetup luksOpen /dev/sdb1 decrypted      # Unlock partition
mount -o ro /dev/mapper/decrypted /mnt/linux/
cryptsetup luksClose decrypted               # Close
cryptsetup luksDump /dev/sdb1                # Show LUKS header info
```

---

## 14. String & Binary Analysis

---

### `strings`
Extract printable strings from binary files.

```bash
strings malware.exe                          # ASCII strings
strings -a malware.exe                       # All sections
strings -n 6 malware.exe                     # Minimum length 6
strings -e l malware.exe                     # Unicode (UTF-16LE)
strings malware.exe | grep -i "http"         # Search results
strings malware.exe | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"  # Find IPs
```

---

### `hexedit`
Interactive hex editor for binary files.

```bash
hexedit file.bin                             # Open for editing
# Ctrl+C to save, Ctrl+X to exit without save
```

---

### `vbindiff`
Visual binary diff — compare two binary files side by side.

```bash
vbindiff file1.bin file2.bin                 # Compare files visually
```

---

### `ent`
Measure entropy of a file (high entropy = encrypted/compressed/packed).

```bash
ent malware.exe                              # Show entropy stats
ent -b malware.exe                           # Binary mode
```

---

### `radare2`
Reverse engineering framework (see also section 15).

```bash
r2 -A malware.exe                            # Analyze automatically
r2 malware.exe                               # Interactive session
rabin2 -i malware.exe                        # Show imports
rabin2 -E malware.exe                        # Show exports
rabin2 -S malware.exe                        # Show sections
rabin2 -z malware.exe                        # Show strings
rasm2 -a x86 -b 32 "nop"                     # Assemble instruction
```

---

### `gdb`
GNU debugger.

```bash
gdb malware.elf                              # Start debugging
gdb -p 1234                                  # Attach to PID
# Inside gdb:
# run         - Start execution
# break main  - Breakpoint at main
# continue    - Continue execution
# next        - Step over
# step        - Step into
# info regs   - Show registers
# x/10x $rsp  - Examine stack
# disassemble - Disassemble function
# bt          - Backtrace
```

---

### `jq`
Parse and query JSON data from command line.

```bash
jq '.' data.json                             # Pretty-print JSON
jq '.events[]' timeline.json                 # Extract events array
jq '.[] | .timestamp' data.json             # Extract all timestamps
jq 'select(.type == "logon")' events.json   # Filter by field value
jq -r '.[] | [.time,.src,.dst] | @csv' events.json  # CSV output
```

---

### `ag` (silversearcher-ag)
Ultra-fast code/text search tool.

```bash
ag "password" /mnt/evidence/                 # Search for "password"
ag -r "192\.168\." /mnt/evidence/           # Regex search
ag -l "http://" /mnt/evidence/              # List files only
ag --txt "malware" /mnt/evidence/           # Text files only
ag -i "administrator" /mnt/windows/         # Case-insensitive
```

---

### `grepcidr`
Filter output by CIDR IP ranges.

```bash
cat ips.txt | grepcidr 192.168.0.0/16        # Filter IPs in subnet
cat access.log | grepcidr -f internal_ranges.txt  # From CIDR file
grepcidr -v 10.0.0.0/8 ips.txt              # Inverse match (NOT in range)
```

---

## 15. Malware & Code Analysis

---

### `clamav` (clamscan / freshclam)
Scan files for malware signatures.

```bash
clamscan malware.exe                         # Scan single file
clamscan -r /mnt/evidence/                   # Recursive scan
clamscan --infected -r /mnt/evidence/        # Show infected only
freshclam                                    # Update signatures
clamscan --log=/cases/scan.log -r /mnt/evidence/  # Log results
```

---

### `pev` / `readpe` suite
PE file analysis tools (same as in REMnux).

```bash
readpe malware.exe                           # Show PE headers
pestr malware.exe                            # Extract strings
pedis malware.exe                            # Disassemble entry point
pehash malware.exe                           # Compute hashes
pescan malware.exe                           # Scan for anomalies
pesec malware.exe                            # Security features
peldd malware.exe                            # DLL dependencies
peres malware.exe                            # Resources
```

---

### `pdftk` (pdftk-java)
Manipulate and inspect PDF files.

```bash
pdftk malware.pdf dump_data                  # Metadata
pdftk malware.pdf burst                      # Split pages
pdftk malware.pdf output decrypted.pdf allow AllFeatures owner_pw ""  # Decrypt
pdftk malware.pdf output uncomp.pdf uncompress  # Decompress streams
```

---

### `upx-ucl`
Unpack UPX-packed binaries.

```bash
upx -d packed.exe -o unpacked.exe            # Decompress
upx -l packed.exe                            # Check packing info
upx -t packed.exe                            # Test integrity
```

---

### `python3-yara`
Scan files with YARA rules from Python or CLI.

```bash
# Python usage:
python3 -c "import yara; rules = yara.compile('rules.yar'); matches = rules.match('malware.exe'); print(matches)"

# Or with the yara CLI (if installed separately):
yara rules.yar malware.exe
yara -r rules/ /mnt/evidence/
```

---

### `wine`
Run Windows executables on Linux.

```bash
wine malware.exe                             # Execute
WINEDEBUG=+all wine malware.exe 2>&1 | tee wine.log  # Debug output
winedbg malware.exe                          # Debug with Wine debugger
```

---

## 16. Threat Intelligence & Data Gathering

---

### `aws-cli`
Amazon Web Services command-line interface for cloud forensics.

```bash
aws s3 ls s3://bucket-name/                  # List S3 bucket
aws s3 cp s3://bucket/file.log ./            # Download file
aws ec2 describe-instances                   # List EC2 instances
aws cloudtrail lookup-events --start-time 2024-01-01  # CloudTrail logs
aws logs get-log-events --log-group-name /aws/vpc/flowlogs --log-stream-name stream  # VPC flow logs
aws configure                                # Set up credentials
```

---

### `nikto`
Web server vulnerability scanner.

```bash
nikto -host http://192.168.1.100             # Scan web server
nikto -host https://192.168.1.100 -ssl       # HTTPS scan
nikto -host http://192.168.1.100 -output /cases/nikto.html -Format htm
nikto -host http://192.168.1.100 -Tuning 9   # SQL injection tests
```

---

### `aircrack-ng`
Wireless network security auditing suite.

```bash
aircrack-ng -w wordlist.txt capture.cap      # Crack WPA/WEP key
airmon-ng start wlan0                        # Enable monitor mode
airodump-ng wlan0mon                         # Capture wireless traffic
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon  # Target network
```

---

## 17. General Utilities & Infrastructure

---

### `pwsh` (PowerShell Core)
Run PowerShell scripts for incident response and forensic tasks.

```bash
pwsh                                         # Interactive shell
pwsh -File script.ps1                        # Execute script
pwsh -Command "Get-Content artifact.ps1 | Out-String"  # Display script
# Decode common base64 encoded PowerShell:
pwsh -Command "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('encoded_here'))"
# Parse Windows XML event logs:
pwsh -Command "Get-WinEvent -Path Security.evtx | Select-Object TimeCreated,Id,Message | Export-Csv events.csv"
```

---

### `docker`
Run containerized forensic tools.

```bash
docker pull teamdfir/sift                    # Pull SIFT image
docker run --rm -it teamdfir/sift            # Run SIFT in container
docker run --rm -v $(pwd):/data teamdfir/sift vol3 -f /data/memory.dmp windows.pslist
docker ps                                    # List running containers
docker images                                # List images
```

---

### `p7zip-full` (7z)
Compress and decompress archives.

```bash
7z x archive.zip                             # Extract
7z x archive.zip -o /cases/output/          # Extract to directory
7z l archive.zip                             # List contents
7z x archive.zip -p"password"               # Extract with password
7z a output.7z /cases/                       # Create archive
```

---

### `cabextract`
Extract Microsoft Cabinet files.

```bash
cabextract setup.cab                         # Extract
cabextract -d /cases/output/ setup.cab       # Extract to directory
cabextract -l setup.cab                      # List contents
```

---

### `unrar` / `rar`
Work with RAR archives.

```bash
unrar x archive.rar                          # Extract
unrar l archive.rar                          # List
rar x -p"password" protected.rar            # Extract with password
```

---

### `ccrypt`
Encrypt and decrypt files.

```bash
ccrypt -e file.txt                           # Encrypt
ccrypt -d file.txt.cpt                       # Decrypt
```

---

### `sqlite3`
Query SQLite databases found in forensic artifacts (browsers, apps, etc.).

```bash
sqlite3 places.sqlite ".tables"              # List tables (Firefox history)
sqlite3 places.sqlite "SELECT url, visit_date FROM moz_places ORDER BY visit_date DESC LIMIT 20;"
sqlite3 History ".tables"                    # Chrome history tables
sqlite3 History "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20;"
sqlite3 database.db ".dump" > export.sql    # Full dump
sqlite3 database.db ".mode csv" ".output out.csv" "SELECT * FROM table;" && cat out.csv
```

---

### `curl`
Interact with web services.

```bash
curl -v http://192.168.1.100/               # Verbose HTTP request
curl -k https://192.168.1.100/             # Ignore TLS errors
curl -o file.bin http://192.168.1.100/payload  # Download file
curl -A "Mozilla/5.0" http://192.168.1.100/  # Custom User-Agent
curl -x http://127.0.0.1:8080 http://target/ # Via proxy
```

---

### `nc` (netcat)
Network utility.

```bash
nc -lvp 4444                                 # Listen
nc 192.168.1.100 4444                        # Connect
nc -lvp 4444 > recv.exe                     # Receive file
```

---

### `tofrodos` (todos / fromdos)
Convert Windows (CRLF) and Unix (LF) line endings.

```bash
fromdos file.txt                             # Windows → Unix (in-place)
todos file.txt                               # Unix → Windows
fromdos < windows.txt > unix.txt             # From stdin
```

---

### `pv`
Monitor progress of data through a pipe.

```bash
pv image.dd | gzip > image.dd.gz            # Compress with progress
dd if=/dev/sdb | pv | dd of=image.dd        # Image with progress
```

---

### `fdupes`
Find duplicate files in a directory.

```bash
fdupes -r /mnt/evidence/                     # Find duplicates recursively
fdupes -r -d /mnt/evidence/                  # Delete duplicates interactively
fdupes -r -S /mnt/evidence/                  # Show sizes
fdupes -r -n /mnt/evidence/                  # Omit first of each group
```

---

### `kdiff3`
Three-way diff and merge tool for files and directories.

```bash
kdiff3 file1.txt file2.txt                   # Diff two files
kdiff3 dir1/ dir2/                           # Diff two directories
```

---

### `graphviz` (dot, neato, etc.)
Generate graph visualizations (used with Plaso, Volatility, etc.).

```bash
dot -Tpng process_tree.dot -o process_tree.png   # Render DOT graph to PNG
dot -Tsvg callgraph.dot -o callgraph.svg          # SVG output
xdot process_tree.dot                             # Interactive viewer
```

---

### `qemu` / `qemu-utils`
Emulate virtual machines and convert disk images.

```bash
qemu-img info image.vmdk                     # Show image info
qemu-img convert -f vmdk -O raw image.vmdk image.raw  # Convert to raw
qemu-img convert -f raw -O qcow2 image.raw image.qcow2  # To QCOW2
qemu-system-x86_64 -hda image.raw -m 2048   # Boot image in QEMU
```

---

### `libvmdk` (vmdkinfo, vmdkmount)
Access VMware VMDK disk images.

```bash
vmdkinfo image.vmdk                          # Show VMDK metadata
vmdkmount image.vmdk /mnt/vmdk/              # Mount VMDK
mount -o ro /mnt/vmdk/vmdk1 /mnt/windows/   # Mount filesystem inside
```

---

### `open-iscsi`
Connect to iSCSI targets (for SAN-based evidence acquisition).

```bash
iscsiadm -m discovery -t st -p 192.168.1.100  # Discover targets
iscsiadm -m node -T iqn.target -l             # Connect to target
iscsiadm -m node -T iqn.target -u             # Disconnect
```

---

### `samba` / `cifs-utils`
Mount Windows file shares for evidence collection.

```bash
mount -t cifs //192.168.1.100/C$ /mnt/share -o user=admin,password=pass,ro
mount -t cifs //192.168.1.100/C$ /mnt/share -o credentials=/etc/samba/creds,ro
smbclient //192.168.1.100/C$ -U admin        # Interactive SMB access
smbclient //192.168.1.100/C$ -U admin -c "ls"  # Run single command
```

---

### `android-sdk-platform-tools` (adb, fastboot)
Acquire data from Android devices.

```bash
adb devices                                  # List connected Android devices
adb pull /data/data/ /cases/android/         # Pull app data
adb pull /sdcard/ /cases/android_sdcard/     # Pull SD card
adb backup -all -apk -shared -f backup.ab    # Full backup
adb shell dumpsys                            # System dump
adb shell pm list packages                   # List installed apps
adb logcat > /cases/android_logs.txt        # Capture device logs
```

---

### `vim`
Text editor — common in SIFT for reviewing text-based artifacts.

```bash
vim artifact.txt                             # Open file
# Useful vim commands for forensics:
# /search_term    - Search forward
# n               - Next match
# :set number     - Show line numbers
# :%s/old/new/g   - Replace all
# :q!             - Quit without saving
```

---

*Sources: [github.com/teamdfir/sift-saltstack](https://github.com/teamdfir/sift-saltstack), [sans.org/tools/sift-workstation](https://www.sans.org/tools/sift-workstation), [github.com/keydet89/Tools](https://github.com/keydet89/Tools), and official tool documentation.*  
*Compiled June 2026.*
