# USB Write Blocker + Imager - Technical Reference

**Version:** 2.2.0  
**Status:** Production Ready (Wipe Feature Experimental)  
**Platform:** Windows 10/11 (x64)  
**Last Updated:** 2026-01-22

---

## Overview

Professional forensic tool providing USB write protection, forensic disk imaging, E01 archiving, and image verification for digital forensics and incident response.

### Core Features
- **USB Write Protection** - Registry-based write blocking
- **Forensic Disk Imaging** - Bit-by-bit copies with MD5/SHA-1
- **E01 Archiving** - Expert Witness Format conversion
- **Image Verification** - Independent hash checking
- **Secure Disk Wipe** - ⚠️ Experimental (non-functional on Windows)
- **Chain of Custody** - Automated forensic reports
- **Modern UI** - Professional dark theme with scrolling

### Technology
- Python 3.8+ with PySide6 (Qt6)
- dd.exe (disk imaging)
- ewfacquire.exe (E01 conversion)
- PyInstaller (single .exe deployment)

---

## Project Structure

```
USB_Write_Protect_Gui/
│
├── usb_write_blocker_imager.py     ← Main app (~676 lines)
│
├── forensic_tools/                 ← Package
│   ├── __init__.py                 (45 lines)
│   ├── utils.py                    (224 lines) - Utilities
│   ├── usb_blocker.py              (189 lines) - Write protection
│   ├── disk_imaging.py             (944 lines) - Disk imaging
│   ├── e01_converter.py            (869 lines) - E01 archiving
│   ├── image_verification.py       (622 lines) - Image verification
│   ├── wipe_disk.py                (753 lines) - Secure wipe
│   └── gui_components.py           (322 lines) - Shared UI
│
├── tsk_bin/                        ← External tools
│   ├── dd.exe
│   └── ewfacquire.exe
│
└── USB_Write_Blocker_Imager.spec   ← PyInstaller config
```

**Total:** ~4,644 lines organized into modules

---

## Architecture

### Refactoring Approach

**This is a REFACTORING, not a rewrite:**
- ✅ **Extracted** existing working code into modules
- ✅ **Organized** into logical components
- ✅ **Kept** all functionality identical
- ✅ **Added** new features (E01, verification, wipe)

**Before:** 1,763 lines in single file  
**After:** ~4,644 lines across modules

### Data Flow

```
User Action
    ↓
Main Window (with scrolling)
    ↓
┌───────┬───────┬───────┬───────┐
│       │       │       │       │
Write  Disk   E01    Secure
Block  Image  Archive  Wipe*
│       │       │       │
└───────┴───────┴───────┴───────┘
            ↓
    Reports & Logs
```

*Secure Wipe currently non-functional due to Windows restrictions

---

## Module Documentation

### forensic_tools/__init__.py
Package initialization and public API

```python
from .utils import (APP_TITLE, APP_VERSION, find_dd_executable, 
                    find_ewfacquire_executable, write_report)
from .usb_blocker import USBWriteBlocker
from .disk_imaging import ImageWorker, ImagingDialog
from .e01_converter import E01Worker, E01ArchiveDialog
from .image_verification import ImageVerificationDialog
from .wipe_disk import WipeDialog
from .gui_components import HelpDialog, QtLogHandler
```

### forensic_tools/utils.py
Shared utilities, constants, cleanup handlers

**Key Functions:**
- `find_dd_executable()` - Locate dd.exe
- `find_ewfacquire_executable()` - Locate ewfacquire.exe
- `write_report()` - Generate forensic reports
- `_cleanup_write_block()` - atexit cleanup

**Constants:**
- `APP_TITLE`, `APP_VERSION`, `IS_WINDOWS`

### forensic_tools/usb_blocker.py
USB write protection via registry

**Registry Key:**
```
HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies
WriteProtect = 1 (DWORD)
```

**Class: USBWriteBlocker**
- `enable()` - Enable write protection
- `disable()` - Disable write protection
- `verify()` - Check status
- `list_physical()` - List removable USB drives (IOCTL)

### forensic_tools/disk_imaging.py
Forensic disk imaging with dd

**Classes:**
- `ImageWorker(QThread)` - Background worker
- `ImagingDialog` - User interface

**Process:**
1. Select removable USB device
2. Choose output location
3. Execute: `dd if=\\.\PhysicalDrive{N} of=output.img bs=4M`
4. Monitor progress (file size polling)
5. Calculate MD5 + SHA-1
6. Generate forensic report

**Output:**
```
YYYYMMDD_ImageName/
├── ImageName.img  # Disk image
└── ImageName.txt  # Forensic report
```

### forensic_tools/e01_converter.py
Expert Witness Format (E01) conversion

**Classes:**
- `E01Worker(QThread)` - Background worker
- `E01ArchiveDialog` - User interface

**Process:**
1. Select source image (.img, .dd, .raw)
2. Choose output location
3. Fill case metadata (optional)
4. Select compression level
5. Execute: `ewfacquire -t output.E01 -C case -D description -c {compression} input.img`
6. Monitor progress
7. Generate report

**Compression Options:**
- `best` - Maximum compression (recommended)
- `fast` - Faster conversion, less compression
- `none` - No compression
- `empty-block` - Only compress empty blocks

**Output:**
```
output.E01        # Expert Witness Format file
output.E01.txt    # Conversion report
```

### forensic_tools/image_verification.py
Independent image verification

**Class: ImageVerificationDialog**

**Process:**
1. Select image file
2. Calculate MD5 and SHA-1 hashes
3. Display results
4. Compare with expected hashes

**Use Cases:**
- Verify integrity before analysis
- Court evidence verification
- Chain of custody validation

### forensic_tools/wipe_disk.py
Secure disk wipe (⚠️ Experimental)

**Classes:**
- `WipeWorker(QThread)` - Background worker
- `WipeDialog` - User interface

**⚠️ IMPORTANT WARNING:**
This feature is **currently non-functional** on Windows due to OS security restrictions. Windows blocks all write attempts to physical drives, even with:
- Administrator privileges
- Volume dismounting
- Direct device access
- Windows API calls
- dd.exe external tool

**Status:** Error 5 (Access Denied)

**Alternatives:**
- Boot from Linux USB (e.g., DBAN, Parted Magic)
- Use hardware-based wipers
- Professional forensic tools with signed drivers

### forensic_tools/gui_components.py
Shared GUI components

**Classes:**
- `HelpDialog` - User documentation
- `QtLogHandler` - Thread-safe logging

---

## Feature Details

### 1. USB Write Protection

**How It Works:**
- Modifies Windows registry
- Creates `StorageDevicePolicies` key
- Sets `WriteProtect=1` (DWORD)
- Applies to all USB devices
- Auto-disables on exit

**Limitations:**
- Registry-based (not hardware)
- Requires Administrator
- Windows-only
- System-wide (not per-device)

### 2. Forensic Disk Imaging

**Command:**
```bash
dd if=\\.\PhysicalDrive2 of=output.img bs=4M conv=noerror,sync
```

**Progress Monitoring:**
- Poll output file size every 300ms
- Calculate: `(file_size / expected) * 100`
- Display: MB/s speed, ETA

**Hash Verification:**
- MD5 (128-bit)
- SHA-1 (160-bit)
- Calculated after imaging
- Included in report

**Speeds:**
- USB 2.0: 20-35 MB/s
- USB 3.0: 80-150 MB/s
- USB 3.1: 150-300 MB/s

### 3. E01 Archiving

**Why E01 Format?**
- **Industry Standard:** Recognized in legal proceedings
- **Compression:** Reduces storage by 40-60%
- **Metadata:** Embedded case information
- **Integrity:** Built-in hash verification
- **Compatibility:** Supported by all forensic tools

**Command:**
```bash
ewfacquire -t output.E01 -C case -D description -c best input.img
```

**Features:**
- Real-time progress monitoring
- Configurable compression
- Case metadata embedding
- Hash verification
- Multi-segment support (for large files)

### 4. Image Verification

**Independent Verification:**
- Calculates hashes from any image file
- Compares against known-good values
- Court-admissible verification
- No modification to original

**Supported Formats:**
- Raw images (.img, .dd, .raw)
- E01 files (reads embedded hashes)
- Any binary file

### 5. Secure Disk Wipe ⚠️

**Status:** Non-functional on Windows

**Attempted Solutions:**
1. ❌ Windows API (CreateFileW + WriteFile)
2. ❌ Volume locking (FSCTL_LOCK_VOLUME)
3. ❌ Volume dismount (FSCTL_DISMOUNT_VOLUME)
4. ❌ Extended disk access (FSCTL_ALLOW_EXTENDED_DASD_IO)
5. ❌ dd.exe with temp zero file
6. ❌ All return Error 5 (Access Denied)

**Root Cause:**
Windows 10/11 security actively blocks all userspace programs from writing to physical drives when volumes are present, even with maximum privileges.

**Workaround:**
Boot from Linux USB and use:
- `shred` command
- `dd` command
- DBAN (Darik's Boot and Nuke)
- Parted Magic

---

## Technical Implementation

### Threading

```
Main Thread (GUI)
├─► ImageWorker (QThread) → dd.exe
├─► E01Worker (QThread) → ewfacquire.exe
├─► WipeWorker (QThread) → dd.exe (blocked)
└─► Qt Signals (thread-safe)
```

**Thread Safety:**
```python
self._cancel_lock = QtCore.QMutex()

# Writing
self._cancel_lock.lock()
self._cancel = True
self._cancel_lock.unlock()

# Reading
self._cancel_lock.lock()
should_cancel = self._cancel
self._cancel_lock.unlock()
```

### Path Sanitization

```python
def _sanitize_filename(name: str) -> str:
    # Remove invalid chars: < > : " / \ | ? *
    # Strip dots/spaces
    # Block reserved: CON, PRN, AUX, NUL, COM1-9, LPT1-9
    # Prevent empty or ".."
    # Limit to 200 chars
```

### Error Handling

**Critical** → User notification + halt
- dd.exe not found
- ewfacquire.exe not found
- Admin missing
- Device access denied

**Major** → Logged + partial completion
- Hash failures
- Report write errors

**Minor** → Silent retry
- Device enum errors
- File check race conditions

---

## Security & Forensics

### Forensic Soundness

**Chain of Custody:**
- Timestamp (UTC)
- Operator (username)
- System name
- Device info
- Hash verification
- Notes section

**Write Protection:**
- Prevents modification
- Verification before imaging
- Auto-cleanup on exit

**Hash Verification:**
- Industry standards
- Court admissible
- Tamper-evident reports

### Security

**Admin Privileges:**
- ✅ Registry modification
- ✅ Physical drive access
- ✅ E01 conversion
- ❌ NO file operations outside designated folders
- ❌ NO network access
- ❌ NO system modifications beyond write-block

**Input Validation:**
- ✅ Filename sanitization
- ✅ Path traversal prevention
- ✅ Reserved name blocking
- ✅ Drive index validation

---

## Build & Deployment

### Dependencies

```bash
pip install PySide6
```

**Tools:**
```
tsk_bin/dd.exe        # GNU dd for Windows
tsk_bin/ewfacquire.exe   # libewf EWF acquisition tool
```

### Build

**Command:**
```bash
pyinstaller USB_Write_Blocker_Imager.spec
```

**Output:**
```
dist/USB_Write_Blocker_Imager.exe  # Single file
```

**Spec File:**
```python
datas=[
    ('tsk_bin', 'tsk_bin'),
    ('forensic_tools', 'forensic_tools')
],
uac_admin=True  # Request admin
```

### Deployment

**Requirements:**
- Windows 10/11 x64
- Administrator privileges
- No Python needed
- No dependencies

**Portable:**
- ✅ Single .exe
- ✅ No installation
- ✅ No DLLs

---

## API Reference

### write_report()
```python
write_report(
    output_file: Path,
    device_info: Dict,
    start_ts: float,
    end_ts: float,
    expected: int,
    copied: int,
    md5: str,
    sha1: str,
    status: str,
    method: str = "dd",
    report_type: str = "imaging"
) -> str
```

### USBWriteBlocker.list_physical()
```python
list_physical() -> List[tuple]
# Returns: [(drive_index, size_bytes), ...]
# Example: [(2, 31457280000), (5, 128849018880)]
```

---

## Troubleshooting

### dd.exe Not Found
- Verify `tsk_bin/dd.exe` exists
- Check build includes tsk_bin/
- Recompile if needed

### ewfacquire.exe Not Found
- Download libewf from [GitHub](https://github.com/libyal/libewf/releases)
- Place ewfacquire.exe in tsk_bin/
- Ensure all DLL dependencies are included

### Write Protection Fails
- Run as Administrator
- Check registry permissions
- Verify no Group Policy blocking

### Device Not Detected
- Device must be removable (USB)
- Click "Refresh" button
- Check Device Manager
- Reconnect device

### Imaging Fails
- Check destination space
- Verify source device health
- Run as Administrator
- Check dd.exe is valid

### E01 Conversion Fails
- Verify ewfacquire.exe exists
- Check source file is accessible
- Ensure sufficient disk space
- Verify libewf DLL dependencies

### Secure Wipe Fails ⚠️
**Expected:** This feature is currently non-functional on Windows
- Error 5 (Access Denied) is normal
- Windows security blocks all write attempts
- **Solution:** Boot from Linux USB for wipe operations

---

## Performance

### Disk Imaging
- USB 2.0: 20-35 MB/s
- USB 3.0: 80-150 MB/s
- USB 3.1: 150-300 MB/s

### E01 Conversion
- Compression: ~50-100 MB/s
- Size reduction: 40-60% typical
- Time: Varies by compression level

### Hashing
- MD5: ~400-600 MB/s
- SHA-1: ~350-500 MB/s
- 100 GB @ 450 MB/s = ~4 min

---

## Version History

### v2.2.0 (Current - 2026-01-22)
- Code cleanup and optimization
- Removed orphaned PDF generator
- Added E01 archiving feature
- Added image verification
- Added secure wipe (experimental)
- Updated UI with scrolling
- Version bump and documentation updates

### v2.1.0 (2025-12-23)
- Modular architecture
- E01 support added
- Thread safety improvements
- Security fixes
- Professional UI

### v1.0.0
- USB write protection
- dd-based imaging
- MD5/SHA-1 hashing
- Basic GUI

---

## License & Legal

**License:** MIT / GPL-3.0

**For Legitimate Use Only:**
- ✅ Law enforcement
- ✅ Incident response
- ✅ Authorized testing
- ✅ Personal recovery
- ✅ Educational purposes

**Prohibited:**
- ❌ Unauthorized access
- ❌ Privacy violations
- ❌ Data theft
- ❌ Evidence tampering

Always obtain proper authorization.

---

## Quick Reference

### File Locations
```
Main:    usb_write_blocker_imager.py
Package: forensic_tools/
Tools:   tsk_bin/
Build:   USB_Write_Blocker_Imager.spec
Output:  dist/USB_Write_Blocker_Imager.exe
```

### Registry Key
```
HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies
WriteProtect (DWORD) = 1
```

### Key Classes
```
USBWriteBlocker
ImageWorker, ImagingDialog
E01Worker, E01ArchiveDialog
ImageVerificationDialog
WipeDialog (experimental)
HelpDialog, QtLogHandler
```

---

**End of Technical Reference**  
*Version 2.2.0 - 2026-01-22*  
*⚠️ Note: Secure Wipe feature experimental/non-functional on Windows*
