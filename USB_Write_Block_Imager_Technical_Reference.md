# USB Write Blocker + Imager - Technical Reference

**Version:** 2.3.0  
**Status:** Production Ready  
**Platform:** Windows 10/11 (x64)  
**Last Updated:** 2026-02-03

---

## Overview

Professional forensic tool providing USB write protection, forensic disk imaging, E01 archiving, and image verification for digital forensics and incident response.

### Core Features
- **USB Write Protection** - Triple-method registry-based write blocking
- **Forensic Disk Imaging** - Bit-by-bit copies with MD5/SHA-1/SHA-256 and case metadata
- **E01 Archiving** - Expert Witness Format conversion with compression
- **Image Verification** - Independent hash checking
- **Secure Disk Wipe** - Zero-fill wipe with verification
- **Chain of Custody** - Automated forensic reports with case information
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
├── usb_write_blocker_imager.py     ← Main app (~690 lines)
│
├── forensic_tools/                 ← Package
│   ├── __init__.py                 (45 lines)
│   ├── utils.py                    (290 lines) - Utilities
│   ├── usb_blocker.py              (467 lines) - Write protection
│   ├── disk_imaging.py             (1031 lines) - Disk imaging
│   ├── e01_converter.py            (896 lines) - E01 archiving
│   ├── image_verification.py       (876 lines) - Image verification
│   ├── wipe_disk.py                (1449 lines) - Secure wipe
│   └── gui_components.py           (322 lines) - Shared UI
│
├── tsk_bin/                        ← External tools
│   ├── dd.exe
│   └── ewfacquire.exe
│
└── USB_Write_Blocker_Imager.spec   ← PyInstaller config
```

**Total:** ~6,000+ lines organized into modules

---

## Architecture

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
- `write_report()` - Generate forensic reports with case metadata
- `_cleanup_write_block()` - atexit cleanup (unconditional)

**Constants:**
- `APP_TITLE`, `APP_VERSION`, `IS_WINDOWS`

### forensic_tools/usb_blocker.py
USB write protection via triple-method registry approach

**Registry Keys (All Three Methods):**
```
Method 1: HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies
          WriteProtect = 1 (DWORD)

Method 2: HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
          Deny_Write = 1 (DWORD)  [Disk Drives GUID - covers SD cards, USB hubs]

Method 3: HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
          Deny_Write = 1 (DWORD)  [Removable Storage GUID]
```

**Class: USBWriteBlocker**
- `enable()` - Enable write protection (all 3 methods)
- `disable()` - Disable write protection (all 3 methods)
- `verify()` - Check status (returns True if ANY method is enabled)
- `list_physical()` - List removable USB drives with device info (IOCTL)

**Startup Behavior:**
- Write protection is ALWAYS disabled on application startup
- Ensures clean state after crashes, force-closes, or unexpected termination
- All 3 registry methods are cleared before status check

### forensic_tools/disk_imaging.py
Forensic disk imaging with dd

**Classes:**
- `ImageWorker(QThread)` - Background worker with metadata support
- `ImagingDialog` - User interface with case information fields

**Case Information Fields:**
- Case Number
- Evidence Number
- Examiner (auto-filled with Windows username)
- Description
- Notes

**Process:**
1. Select removable USB device
2. Choose output location
3. Fill case information (optional)
4. Execute: `dd if=\\.\PhysicalDrive{N} of=output.img bs=4M`
5. Monitor progress (file size polling)
6. Calculate MD5 + SHA-1 (+ optional SHA-256)
7. Generate forensic report with case metadata

**Output:**
```
YYYYMMDD_ImageName/
├── ImageName.img  # Disk image
└── ImageName.txt  # Forensic report with case info
```

### forensic_tools/e01_converter.py
Expert Witness Format (E01) conversion

**Classes:**
- `E01Worker(QThread)` - Background worker
- `E01ArchiveDialog` - User interface

**Case Metadata Fields:**
- Case Number
- Evidence Number
- Examiner
- Description
- Notes
- Compression Level

**Process:**
1. Select source image (.img, .dd, .raw)
2. Choose output location
3. Fill case metadata (optional)
4. Select compression level
5. Execute: `ewfacquire -t output.E01 -C case -D description -c {compression} input.img`
6. Monitor progress
7. Generate report
8. Package E01 + report in ZIP archive

**Compression Options:**
- `best` - Maximum compression (recommended)
- `fast` - Faster conversion, less compression
- `none` - No compression
- `empty-block` - Only compress empty blocks

**Output:**
```
output_Archive.zip containing:
├── output_Archive.E01   # Expert Witness Format file
└── output_Archive.txt   # Conversion report
```

### forensic_tools/image_verification.py
Independent image verification

**Class: ImageVerificationDialog**

**Process:**
1. Select image file
2. Calculate MD5 and SHA-1 hashes (+ optional SHA-256)
3. Display results
4. Compare with expected hashes

**Use Cases:**
- Verify integrity before analysis
- Court evidence verification
- Chain of custody validation

### forensic_tools/wipe_disk.py
Secure disk wipe

**Classes:**
- `WipeWorker(QThread)` - Background worker
- `WipeDialog` - User interface

**Process:**
1. Select removable USB device
2. Confirm wipe operation (requires typing "WIPE")
3. Lock and dismount volumes
4. Write zeros to entire disk
5. Verify wipe completed
6. Optional: Format to ExFAT after wipe

**Features:**
- Zero-fill entire disk
- Volume locking and dismounting
- Progress monitoring
- Verification pass
- Optional post-wipe formatting

### forensic_tools/gui_components.py
Shared GUI components

**Classes:**
- `HelpDialog` - User documentation
- `QtLogHandler` - Thread-safe logging

---

## Feature Details

### 1. USB Write Protection

**How It Works:**
- Uses THREE registry methods for comprehensive coverage
- Method 1: StorageDevicePolicies (standard approach)
- Method 2: Group Policy Disk Drives GUID (covers SD cards, USB hubs)
- Method 3: Group Policy Removable Storage GUID
- All methods enabled/disabled together
- Forced disable on startup (crash recovery)
- Unconditional cleanup on exit

**Startup Sequence:**
1. Application starts
2. All 3 registry keys cleared (disable)
3. Status checked and displayed
4. User can then manually enable if needed

**Cleanup Handlers:**
- `atexit` handler clears all 3 keys
- Signal handlers (SIGINT, SIGTERM) clear all 3 keys
- Win32 console control handler clears all 3 keys
- Cleanup runs unconditionally (ignores tracked state)

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
- MD5 (128-bit) - Always calculated
- SHA-1 (160-bit) - Always calculated
- SHA-256 (256-bit) - Optional, adds ~15-25% time
- Calculated after imaging
- Included in report

**Device Information Captured:**
- Physical Drive index
- Vendor name
- Product name
- Serial number
- Device size

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
- ZIP packaging of E01 + report

### 4. Image Verification

**Independent Verification:**
- Calculates hashes from any image file
- Compares against known-good values
- Court-admissible verification
- No modification to original

**Supported Formats:**
- Raw images (.img, .dd, .raw)
- E01 files (reads embedded hashes via pyewf)
- Any binary file

### 5. Secure Disk Wipe

**Process:**
1. Select removable USB device
2. Double confirmation (button + type "WIPE")
3. Lock and dismount all volumes on disk
4. Write zeros to every sector
5. Verify wipe completed successfully
6. Optional: Format disk to ExFAT

**Safety Features:**
- Only targets removable USB devices
- Requires Administrator privileges
- Double confirmation prevents accidents
- Volume locking ensures exclusive access

---

## Technical Implementation

### Threading

```
Main Thread (GUI)
├─► ImageWorker (QThread) → dd.exe
├─► E01Worker (QThread) → ewfacquire.exe
├─► WipeWorker (QThread) → Native Windows I/O
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

**Chain of Custody Report Sections:**
- Operation Details (timestamp, operator, system, method, status)
- Case Information (case number, evidence number, examiner, description, notes)
- Device Information (physical drive, vendor, product, serial, size)
- Timing Information (start, end, duration, speed)
- Hash Verification (MD5, SHA-1, SHA-256)
- Chain of Custody Notes

**Write Protection:**
- Triple-method registry protection
- Forced disable on startup (crash recovery)
- Verification before imaging
- Unconditional cleanup on exit

**Hash Verification:**
- Industry standards (MD5, SHA-1, SHA-256)
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
tsk_bin/dd.exe           # GNU dd for Windows
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
    sha256: str = "",
    metadata: Dict = None  # Case information
) -> str
```

### USBWriteBlocker.list_physical()
```python
list_physical() -> List[dict]
# Returns: [{'index': int, 'size': int, 'vendor': str, 'product': str, 'serial': str}, ...]
# Example: [{'index': 2, 'size': 31457280000, 'vendor': 'SanDisk', 'product': 'Ultra USB 3.0', 'serial': 'ABC123'}]
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

### Write Protection Shows "ENABLED" on Startup
- This should not occur - application forces disable on startup
- If it persists, manually check all 3 registry keys
- Run `regedit` and verify keys are cleared

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

### Secure Wipe Fails
- Run as Administrator
- Ensure device is removable USB (not internal)
- Close all programs using the device
- Try disconnecting and reconnecting device
- Check Device Manager for device status

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
- SHA-256: ~250-400 MB/s
- 100 GB @ 450 MB/s = ~4 min

---

## Version History

### v2.3.0 (Current - 2026-02-03)
- Case information fields in forensic imaging dialog
- Forensic reports include case metadata section
- Triple-method write protection (StorageDevicePolicies + 2 Group Policy GUIDs)
- Forced write protection disable on startup
- Unconditional cleanup handler
- Device info (vendor/product/serial) in reports
- E01 path collision fix

### v2.2.0 (2026-01-22)
- Code cleanup and optimization
- Added E01 archiving feature
- Added image verification
- Added secure wipe feature
- Updated UI with scrolling

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

### Registry Keys (All 3 Methods)
```
HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies
    WriteProtect (DWORD) = 1

HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
    Deny_Write (DWORD) = 1

HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
    Deny_Write (DWORD) = 1
```

### Key Classes
```
USBWriteBlocker
ImageWorker, ImagingDialog
E01Worker, E01ArchiveDialog
ImageVerificationDialog
WipeDialog
HelpDialog, QtLogHandler
```

---

**End of Technical Reference**  
*Version 2.3.0 - 2026-02-03*
