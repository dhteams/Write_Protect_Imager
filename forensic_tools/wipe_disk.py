"""
Secure Disk Wipe Module
Wipe devices with verification using native Python I/O (Windows-compatible)
"""

import os
import time
import ctypes
import hashlib
from typing import Optional, Dict

from PySide6 import QtCore, QtWidgets

from .utils import APP_TITLE, APP_VERSION, IS_WINDOWS

if IS_WINDOWS:
    from ctypes import wintypes


class WipeWorker(QtCore.QThread):
    """
    Background worker for secure disk wiping using native Windows I/O.
    Uses diskpart clean followed by WriteFile for reliable wiping.
    """
    progress = QtCore.Signal(int, str)
    log = QtCore.Signal(str)
    finished = QtCore.Signal(str)
    failed = QtCore.Signal(str)
    
    def __init__(self, device_index: int, device_info: Dict, passes: int = 1, format_after_wipe: bool = False):
        super().__init__()
        self.device_index = device_index
        self.device_info = device_info
        self.passes = passes
        self.format_after_wipe = format_after_wipe
        self.expected_size = device_info.get('size', 0)
        self._cancel = False
        self._cancel_lock = QtCore.QMutex()
        self.process = None
    
    def request_cancel(self):
        """Thread-safe cancellation request."""
        self._cancel_lock.lock()
        self._cancel = True
        process_to_terminate = self.process
        self._cancel_lock.unlock()
        
        if process_to_terminate:
            try:
                process_to_terminate.terminate()
            except:
                pass
    
    def _is_cancelled(self) -> bool:
        """Thread-safe check for cancellation."""
        self._cancel_lock.lock()
        cancelled = self._cancel
        self._cancel_lock.unlock()
        return cancelled
    
    def _get_volumes_on_disk(self, disk_index: int) -> list:
        """Get list of volume paths (e.g., '\\\\.\\E:') for volumes on the specified physical disk."""
        volumes = []
        
        # Use GetLogicalDrives to only check drives that actually exist
        drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
        
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
        
        # Only check drives D-Z that exist (skip A, B for floppies, C for system)
        for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            # Skip if drive doesn't exist
            if not (drive_mask & (1 << i)):
                continue
            
            # Skip A, B (floppy), C (usually system)
            if letter in "ABC":
                continue
            
            volume_path = f"\\\\.\\{letter}:"
            
            try:
                # Quick check - get drive type first to skip network/CD drives
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                # 2 = REMOVABLE, 3 = FIXED, skip others (0=unknown, 1=no root, 4=network, 5=cdrom, 6=ramdisk)
                if drive_type not in (2, 3):
                    continue
                
                h = ctypes.windll.kernel32.CreateFileW(
                    volume_path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    0,
                    None
                )
                
                if h == INVALID_HANDLE:
                    continue
                
                try:
                    class STORAGE_DEVICE_NUMBER(ctypes.Structure):
                        _fields_ = [
                            ("DeviceType", wintypes.DWORD),
                            ("DeviceNumber", wintypes.DWORD),
                            ("PartitionNumber", wintypes.DWORD),
                        ]
                    
                    sdn = STORAGE_DEVICE_NUMBER()
                    bytes_returned = wintypes.DWORD()
                    
                    result = ctypes.windll.kernel32.DeviceIoControl(
                        h,
                        IOCTL_STORAGE_GET_DEVICE_NUMBER,
                        None, 0,
                        ctypes.byref(sdn), ctypes.sizeof(sdn),
                        ctypes.byref(bytes_returned),
                        None
                    )
                    
                    if result and sdn.DeviceNumber == disk_index:
                        volumes.append((letter, volume_path))
                        self.log.emit(f"[WIPE] Found volume {letter}: on PhysicalDrive{disk_index}")
                finally:
                    ctypes.windll.kernel32.CloseHandle(h)
                    
            except Exception:
                continue
        
        return volumes
    
    def _lock_and_dismount_volumes(self, volumes: list) -> list:
        """Lock and dismount volumes. Returns list of locked volume handles."""
        locked_handles = []
        
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        FSCTL_LOCK_VOLUME = 0x00090018
        FSCTL_DISMOUNT_VOLUME = 0x00090020
        
        for letter, volume_path in volumes:
            try:
                self.log.emit(f"[WIPE] Locking volume {letter}:...")
                
                # Open volume with write access
                h = ctypes.windll.kernel32.CreateFileW(
                    volume_path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    0,
                    None
                )
                
                if h == INVALID_HANDLE:
                    error = ctypes.windll.kernel32.GetLastError()
                    self.log.emit(f"[WIPE] Warning: Cannot open volume {letter}: (error {error})")
                    continue
                
                bytes_returned = wintypes.DWORD()
                
                # Lock the volume
                result = ctypes.windll.kernel32.DeviceIoControl(
                    h,
                    FSCTL_LOCK_VOLUME,
                    None, 0,
                    None, 0,
                    ctypes.byref(bytes_returned),
                    None
                )
                
                if not result:
                    error = ctypes.windll.kernel32.GetLastError()
                    self.log.emit(f"[WIPE] Warning: Cannot lock volume {letter}: (error {error})")
                    ctypes.windll.kernel32.CloseHandle(h)
                    continue
                
                self.log.emit(f"[WIPE] Volume {letter}: locked")
                
                # Dismount the volume
                result = ctypes.windll.kernel32.DeviceIoControl(
                    h,
                    FSCTL_DISMOUNT_VOLUME,
                    None, 0,
                    None, 0,
                    ctypes.byref(bytes_returned),
                    None
                )
                
                if result:
                    self.log.emit(f"[WIPE] Volume {letter}: dismounted")
                else:
                    error = ctypes.windll.kernel32.GetLastError()
                    self.log.emit(f"[WIPE] Warning: Cannot dismount volume {letter}: (error {error})")
                
                # Keep the handle open to maintain the lock
                locked_handles.append((letter, h))
                
            except Exception as e:
                self.log.emit(f"[WIPE] Error with volume {letter}: {e}")
        
        return locked_handles
    
    def _unlock_volumes(self, locked_handles: list):
        """Release locked volume handles."""
        FSCTL_UNLOCK_VOLUME = 0x0009001C
        
        for letter, h in locked_handles:
            try:
                bytes_returned = wintypes.DWORD()
                ctypes.windll.kernel32.DeviceIoControl(
                    h,
                    FSCTL_UNLOCK_VOLUME,
                    None, 0,
                    None, 0,
                    ctypes.byref(bytes_returned),
                    None
                )
                ctypes.windll.kernel32.CloseHandle(h)
                self.log.emit(f"[WIPE] Volume {letter}: unlocked and released")
            except:
                pass
    
    def _format_to_exfat(self, disk_index: int) -> bool:
        """
        Create a new partition and format it as ExFAT using diskpart.
        Returns True on success, False on failure.
        """
        import subprocess
        import tempfile
        
        self.log.emit(f"[FORMAT] Creating partition and formatting to ExFAT...")
        self.progress.emit(0, "Formatting to ExFAT...")
        
        try:
            # Create diskpart script
            # After wipe, diskpart may still have cached partition info
            # Use rescan and clean to ensure fresh state before creating partition
            format_script = f"""rescan
select disk {disk_index}
clean
create partition primary
format fs=exfat quick label=WIPED
assign
exit
"""
            script_path = os.path.join(tempfile.gettempdir(), 'diskpart_format.txt')
            with open(script_path, 'w') as f:
                f.write(format_script)
            
            self.log.emit(f"[FORMAT] Running diskpart...")
            self.progress.emit(20, "Running diskpart...")
            
            if self._is_cancelled():
                return False
            
            # Run diskpart
            self.process = subprocess.Popen(
                ['diskpart', '/s', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Poll for completion
            while self.process.poll() is None:
                if self._is_cancelled():
                    self.log.emit(f"[FORMAT] Cancellation requested...")
                    self._terminate_process()
                    self._cleanup_file(script_path)
                    return False
                time.sleep(0.5)
            
            stdout, stderr = self.process.communicate()
            return_code = self.process.returncode
            self.process = None
            
            self._cleanup_file(script_path)
            
            self.log.emit(f"[FORMAT] Diskpart exit code: {return_code}")
            
            # Log ALL output for debugging
            if stdout:
                for line in stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('Microsoft') and not line.startswith('Copyright'):
                        self.log.emit(f"[FORMAT] {line}")
            
            if stderr:
                self.log.emit(f"[FORMAT] Stderr: {stderr}")
            
            self.progress.emit(80, "Format completing...")
            
            # Check for success indicators
            stdout_lower = stdout.lower() if stdout else ""
            
            # Diskpart says "DiskPart succeeded" for each successful command
            # Count successes - we need at least 4 (clean, create, format, assign)
            success_count = stdout_lower.count('succeeded')
            
            if success_count >= 4:
                self.log.emit(f"[FORMAT] Format completed successfully ({success_count} operations succeeded)")
                self.progress.emit(100, "Format complete")
                
                time.sleep(2)  # Give Windows time to mount the drive
                
                new_letter = self._find_new_drive_letter(disk_index)
                if new_letter:
                    self.log.emit(f"[FORMAT] Drive is now available as {new_letter}:")
                else:
                    self.log.emit(f"[FORMAT] Drive formatted but no letter assigned (may need manual assignment)")
                
                return True
            
            # Check for specific errors
            if 'error' in stdout_lower or 'failed' in stdout_lower:
                self.log.emit(f"[FORMAT] Diskpart reported an error")
                return False
            
            # If return code is 0 and no errors, assume success
            if return_code == 0:
                self.log.emit(f"[FORMAT] Diskpart completed (return code 0)")
                self.progress.emit(100, "Format complete")
                
                time.sleep(2)
                new_letter = self._find_new_drive_letter(disk_index)
                if new_letter:
                    self.log.emit(f"[FORMAT] Drive is now available as {new_letter}:")
                
                return True
            
            self.log.emit(f"[FORMAT] Format may have failed (return code: {return_code})")
            return False
                
        except Exception as e:
            self.log.emit(f"[FORMAT] Error: {e}")
            import traceback
            self.log.emit(f"[FORMAT] {traceback.format_exc()}")
            return False
    
    def _find_new_drive_letter(self, disk_index: int) -> str:
        """Find the drive letter assigned to the new partition on the specified disk."""
        try:
            # Use GetLogicalDrives to only check drives that actually exist
            drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
            
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            INVALID_HANDLE = ctypes.c_void_p(-1).value
            IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
            
            for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                # Skip if drive doesn't exist
                if not (drive_mask & (1 << i)):
                    continue
                
                # Skip A, B, C
                if letter in "ABC":
                    continue
                
                # Quick drive type check
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                if drive_type not in (2, 3):  # REMOVABLE or FIXED only
                    continue
                
                volume_path = f"\\\\.\\{letter}:"
                
                try:
                    h = ctypes.windll.kernel32.CreateFileW(
                        volume_path,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        None,
                        OPEN_EXISTING,
                        0,
                        None
                    )
                    
                    if h == INVALID_HANDLE:
                        continue
                    
                    try:
                        class STORAGE_DEVICE_NUMBER(ctypes.Structure):
                            _fields_ = [
                                ("DeviceType", wintypes.DWORD),
                                ("DeviceNumber", wintypes.DWORD),
                                ("PartitionNumber", wintypes.DWORD),
                            ]
                        
                        sdn = STORAGE_DEVICE_NUMBER()
                        bytes_returned = wintypes.DWORD()
                        
                        result = ctypes.windll.kernel32.DeviceIoControl(
                            h,
                            IOCTL_STORAGE_GET_DEVICE_NUMBER,
                            None, 0,
                            ctypes.byref(sdn), ctypes.sizeof(sdn),
                            ctypes.byref(bytes_returned),
                            None
                        )
                        
                        if result and sdn.DeviceNumber == disk_index:
                            return letter
                    finally:
                        ctypes.windll.kernel32.CloseHandle(h)
                        
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        return ""

    def run(self):
        """
        Secure disk wipe using native Windows I/O.
        
        Process:
        1. Use diskpart to clean disk (removes partitions, releases locks)
        2. Use native WriteFile to write zeros (real-time progress)
        3. Verify by reading back and checking for non-zero bytes
        4. Format to ExFAT if requested
        """
        import subprocess
        import tempfile
        
        if not IS_WINDOWS:
            self.failed.emit("Wipe only supported on Windows")
            return
        
        start_ts = time.time()
        device_path = f"\\\\.\\PhysicalDrive{self.device_index}"
        
        try:
            # Header
            self.log.emit(f"{'='*60}")
            self.log.emit(f"SECURE DISK WIPE")
            self.log.emit(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.log.emit(f"{'='*60}")
            self.log.emit(f"")
            self.log.emit(f"[INFO] Target: PhysicalDrive{self.device_index}")
            self.log.emit(f"[INFO] Size: {self.expected_size:,} bytes ({self.expected_size/(1024**3):.2f} GB)")
            self.log.emit(f"[INFO] Method: Native Windows I/O (zero-fill)")
            self.log.emit(f"[INFO] Block size: 4 MB")
            self.log.emit(f"[INFO] Format after wipe: {'Yes (ExFAT)' if self.format_after_wipe else 'No'}")
            self.log.emit(f"")
            
            # ============================================
            # Step 1: Clean disk with diskpart
            # ============================================
            self.log.emit(f"[STEP 1/4] Cleaning disk (removing partitions)...")
            self.progress.emit(0, "Cleaning disk...")
            
            clean_script = f"""select disk {self.device_index}
clean
exit
"""
            script_path = os.path.join(tempfile.gettempdir(), 'diskpart_clean.txt')
            with open(script_path, 'w') as f:
                f.write(clean_script)
            
            self.process = subprocess.Popen(
                ['diskpart', '/s', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            while self.process.poll() is None:
                if self._is_cancelled():
                    self._terminate_process()
                    self._cleanup_file(script_path)
                    self.failed.emit("Cancelled by user")
                    return
                time.sleep(0.2)
            
            stdout, stderr = self.process.communicate()
            self.process = None
            self._cleanup_file(script_path)
            
            # Check for access denied error
            if 'access is denied' in stdout.lower():
                self.log.emit(f"[STEP 1/4] Access denied - device may be locked by Windows")
                self.failed.emit(
                    "Access denied - device is locked by Windows.\n\n"
                    "Please unplug and replug the USB device, then try again."
                )
                return
            
            if 'succeeded' not in stdout.lower() and 'clean' not in stdout.lower():
                self.log.emit(f"[STEP 1/4] Diskpart output: {stdout}")
                self.failed.emit("Failed to clean disk. Unplug and replug the device, then try again.")
                return
            
            self.log.emit(f"[STEP 1/4] Disk cleaned successfully")
            
            # Small delay for Windows to release the disk
            time.sleep(1)
            
            # ============================================
            # Step 2: Write zeros using native Windows I/O
            # ============================================
            self.log.emit(f"")
            self.log.emit(f"[STEP 2/4] Writing zeros to entire disk...")
            self.progress.emit(1, "Opening device...")
            
            # Windows API constants
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            INVALID_HANDLE = ctypes.c_void_p(-1).value
            
            chunk_size = 4 * 1024 * 1024  # 4 MB chunks
            
            # Open the physical disk (should work now after diskpart clean)
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if handle == INVALID_HANDLE:
                error_code = ctypes.windll.kernel32.GetLastError()
                self.log.emit(f"[ERROR] Cannot open device: Windows error {error_code}")
                self.failed.emit(f"Cannot open device (error {error_code})")
                return
            
            self.log.emit(f"[STEP 2/4] Device opened, writing zeros...")
            
            try:
                # Prepare zero buffer
                zero_buffer = b'\x00' * chunk_size
                bytes_written_ref = wintypes.DWORD()
                
                total_written = 0
                last_pct = -1
                last_log_pct = -10
                wipe_start = time.time()
                
                while total_written < self.expected_size:
                    if self._is_cancelled():
                        ctypes.windll.kernel32.CloseHandle(handle)
                        self.failed.emit("Cancelled by user")
                        return
                    
                    # Calculate write size for this chunk
                    remaining = self.expected_size - total_written
                    write_size = min(chunk_size, remaining)
                    
                    # Use smaller buffer for final chunk
                    if write_size < chunk_size:
                        write_buffer = b'\x00' * write_size
                    else:
                        write_buffer = zero_buffer
                    
                    # Write zeros
                    success = ctypes.windll.kernel32.WriteFile(
                        handle,
                        write_buffer,
                        write_size,
                        ctypes.byref(bytes_written_ref),
                        None
                    )
                    
                    actual_written = bytes_written_ref.value
                    
                    if not success or actual_written == 0:
                        error_code = ctypes.windll.kernel32.GetLastError()
                        # Error 38 = end of disk (normal)
                        if error_code == 38:
                            self.log.emit(f"[STEP 2/4] Reached end of disk")
                            break
                        # Error 5 = access denied
                        elif error_code == 5:
                            self.log.emit(f"[ERROR] Access denied at offset {total_written}")
                            ctypes.windll.kernel32.CloseHandle(handle)
                            self.failed.emit(f"Access denied (error 5). Try ejecting and reconnecting the drive.")
                            return
                        else:
                            # Log error but continue (like dd conv=noerror)
                            self.log.emit(f"[WARN] Write error at {total_written}: error {error_code}")
                            total_written += write_size
                            continue
                    
                    total_written += actual_written
                    
                    # Calculate and update progress
                    if self.expected_size > 0:
                        pct = min(99, int(total_written * 100 / self.expected_size))
                        
                        if pct != last_pct:
                            elapsed = time.time() - wipe_start
                            speed_mbps = (total_written / (1024*1024)) / max(0.1, elapsed)
                            remaining_bytes = self.expected_size - total_written
                            eta_seconds = (remaining_bytes / (1024*1024)) / max(0.1, speed_mbps)
                            
                            # Format ETA
                            if eta_seconds > 60:
                                eta_str = f"{int(eta_seconds//60)}m {int(eta_seconds%60)}s"
                            else:
                                eta_str = f"{int(eta_seconds)}s"
                            
                            # Format sizes
                            written_gb = total_written / (1024**3)
                            total_gb = self.expected_size / (1024**3)
                            
                            self.progress.emit(pct, f"Wiping: {pct}% | {written_gb:.2f}/{total_gb:.2f} GB | {speed_mbps:.1f} MB/s | ETA: {eta_str}")
                            last_pct = pct
                        
                        # Log at every 10%
                        if pct >= last_log_pct + 10:
                            elapsed = time.time() - wipe_start
                            speed_mbps = (total_written / (1024*1024)) / max(0.1, elapsed)
                            self.log.emit(f"[STEP 2/4] {pct}% complete - {total_written/(1024**3):.2f} GB at {speed_mbps:.1f} MB/s")
                            last_log_pct = pct
                
                # Flush buffers
                ctypes.windll.kernel32.FlushFileBuffers(handle)
                
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
            
            # Calculate wipe statistics
            wipe_duration = time.time() - wipe_start
            avg_speed = (total_written / (1024*1024)) / max(0.1, wipe_duration)
            
            self.log.emit(f"")
            self.log.emit(f"[STEP 2/4] {'='*50}")
            self.log.emit(f"[STEP 2/4] WIPE COMPLETE")
            self.log.emit(f"[STEP 2/4] {'='*50}")
            self.log.emit(f"[STEP 2/4] Data written: {total_written/(1024**3):.2f} GB ({total_written:,} bytes)")
            self.log.emit(f"[STEP 2/4] Duration: {wipe_duration:.1f} seconds")
            self.log.emit(f"[STEP 2/4] Average speed: {avg_speed:.1f} MB/s")
            
            if self._is_cancelled():
                self.failed.emit("Cancelled by user")
                return
            
            # ============================================
            # Step 3: Verify
            # ============================================
            self.log.emit(f"")
            self.log.emit(f"[STEP 3/4] Verifying wipe...")
            self.progress.emit(95, "Verifying...")
            
            verified, md5_hash = self._verify_wipe_native(device_path, 4 * 1024 * 1024)
            
            end_ts = time.time()
            duration = end_ts - start_ts
            
            if not verified:
                self.log.emit(f"[VERIFY] FAILED - Non-zero data detected")
                self.failed.emit("Verification failed: non-zero data found on disk")
                return
            
            self.log.emit(f"[VERIFY] PASSED - All zeros confirmed")
            self.log.emit(f"[VERIFY] MD5: {md5_hash}")
            
            # ============================================
            # Step 4: Format (if requested)
            # ============================================
            if self.format_after_wipe:
                self.log.emit(f"")
                self.log.emit(f"[STEP 4/4] Formatting to ExFAT...")
                
                # Give Windows a moment to recognize the disk is clean
                time.sleep(2)
                
                self.progress.emit(97, "Formatting to ExFAT...")
                
                format_success = self._format_to_exfat(self.device_index)
                
                # Final summary
                self.log.emit(f"")
                self.log.emit(f"{'='*60}")
                self.log.emit(f"WIPE OPERATION COMPLETE")
                self.log.emit(f"{'='*60}")
                self.log.emit(f"Total duration: {duration:.1f} seconds")
                self.log.emit(f"MD5 hash: {md5_hash}")
                self.log.emit(f"Format: {'Success' if format_success else 'Failed'}")
                self.log.emit(f"{'='*60}")
                
                if format_success:
                    self.finished.emit(
                        f"Wipe and format completed!\n\n"
                        f"Duration: {duration:.1f} seconds\n"
                        f"MD5: {md5_hash}\n\n"
                        f"Device securely erased and formatted to ExFAT."
                    )
                else:
                    self.finished.emit(
                        f"Wipe completed, format failed.\n\n"
                        f"Duration: {duration:.1f} seconds\n"
                        f"MD5: {md5_hash}\n\n"
                        f"Disk wiped but you may need to format manually."
                    )
            else:
                # Final summary (no format)
                self.log.emit(f"")
                self.log.emit(f"{'='*60}")
                self.log.emit(f"WIPE OPERATION COMPLETE")
                self.log.emit(f"{'='*60}")
                self.log.emit(f"Total duration: {duration:.1f} seconds")
                self.log.emit(f"MD5 hash: {md5_hash}")
                self.log.emit(f"{'='*60}")
                
                self.finished.emit(
                    f"Wipe completed!\n\n"
                    f"Duration: {duration:.1f} seconds\n"
                    f"MD5: {md5_hash}\n\n"
                    f"All data securely erased."
                )
        
        except Exception as e:
            self.log.emit(f"[ERROR] {str(e)}")
            import traceback
            self.log.emit(f"[ERROR] {traceback.format_exc()}")
            self.failed.emit(f"Wipe failed: {str(e)}")
        
        finally:
            if self.process:
                self._terminate_process()
    
    def _cleanup_file(self, path):
        """Remove a temporary file."""
        try:
            if os.path.exists(path):
                os.remove(path)
        except:
            pass
    
    def _terminate_process(self):
        """Terminate any running subprocess."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None
    
    def _verify_wipe(self, device_path: str, chunk_size: int) -> tuple:
        """Verify device contains all zeros. Returns (passed, md5_hash)."""
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        
        handle = None
        
        try:
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if handle == INVALID_HANDLE:
                self.log.emit(f"[VERIFY] Cannot open device for verification")
                return False, ""
            
            md5 = hashlib.md5()
            total_read = 0
            passed = True
            non_zero_locations = 0
            last_pct = -1
            
            read_buffer = ctypes.create_string_buffer(chunk_size)
            bytes_read_ref = wintypes.DWORD()
            
            while True:
                if self._is_cancelled():
                    return False, ""
                
                success = ctypes.windll.kernel32.ReadFile(
                    handle,
                    read_buffer,
                    chunk_size,
                    ctypes.byref(bytes_read_ref),
                    None
                )
                
                bytes_read = bytes_read_ref.value
                if not success or bytes_read == 0:
                    break
                
                data = read_buffer.raw[:bytes_read]
                md5.update(data)
                
                # Check for non-zero bytes
                if any(b != 0 for b in data):
                    passed = False
                    non_zero_locations += 1
                    if non_zero_locations <= 3:
                        # Find first non-zero
                        for i, b in enumerate(data):
                            if b != 0:
                                self.log.emit(f"[VERIFY] Non-zero at offset {total_read + i}: 0x{b:02x}")
                                break
                
                total_read += bytes_read
                
                if self.expected_size > 0:
                    pct = min(100, int(total_read * 100 / self.expected_size))
                    if pct != last_pct:
                        self.progress.emit(pct, f"Verifying: {pct}%")
                        last_pct = pct
            
            if non_zero_locations > 3:
                self.log.emit(f"[VERIFY] ... and {non_zero_locations - 3} more locations with non-zero data")
            
            self.log.emit(f"[VERIFY] Read {total_read:,} bytes")
            
            return passed, md5.hexdigest()
        
        except Exception as e:
            self.log.emit(f"[VERIFY] Error: {e}")
            return False, ""
        
        finally:
            if handle is not None and handle != INVALID_HANDLE:
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass
    
    def _verify_wipe_native(self, device_path: str, chunk_size: int) -> tuple:
        """
        Verify the device contains all zeros using native Windows I/O.
        Returns (verification_passed: bool, md5_hash: str)
        """
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        
        handle = None
        
        try:
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,  # No special flags
                None
            )
            
            if handle == INVALID_HANDLE:
                self.log.emit("[VERIFY] Failed to open device for verification")
                return False, ""
            
            md5 = hashlib.md5()
            bytes_read_total = 0
            verification_passed = True
            non_zero_count = 0
            last_pct = -1
            
            read_buffer = (ctypes.c_char * chunk_size)()
            bytes_read_ref = wintypes.DWORD()
            
            while True:
                if self._is_cancelled():
                    return False, ""
                
                success = ctypes.windll.kernel32.ReadFile(
                    handle,
                    read_buffer,
                    chunk_size,
                    ctypes.byref(bytes_read_ref),
                    None
                )
                
                bytes_read = bytes_read_ref.value
                
                if not success or bytes_read == 0:
                    break
                
                # Convert to bytes for processing
                data = bytes(read_buffer[:bytes_read])
                md5.update(data)
                
                # Check for non-zero bytes
                if any(b != 0 for b in data):
                    if non_zero_count < 5:  # Only log first 5 occurrences
                        offset = bytes_read_total
                        # Find first non-zero byte position
                        for i, b in enumerate(data):
                            if b != 0:
                                self.log.emit(f"[VERIFY] Non-zero byte at offset {offset + i}: 0x{b:02x}")
                                break
                    non_zero_count += 1
                    verification_passed = False
                
                bytes_read_total += bytes_read
                
                # Update progress
                if self.expected_size > 0:
                    pct = min(100, int(bytes_read_total * 100 / self.expected_size))
                    if pct != last_pct:
                        self.progress.emit(pct, f"Verifying: {pct}%")
                        last_pct = pct
            
            if non_zero_count > 5:
                self.log.emit(f"[VERIFY] ... and {non_zero_count - 5} more non-zero locations")
            
            self.log.emit(f"[VERIFY] Verified {bytes_read_total:,} bytes")
            
            return verification_passed, md5.hexdigest()
        
        except Exception as e:
            self.log.emit(f"[VERIFY] Verification error: {e}")
            return False, ""
        
        finally:
            if handle is not None and handle != INVALID_HANDLE:
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass


class WipeDialog(QtWidgets.QDialog):
    """Dialog for secure disk wiping with progress monitoring."""
    
    def __init__(self, parent: QtWidgets.QWidget, blocker, logger):
        super().__init__(parent)
        self.setWindowTitle("Secure Disk Wipe")
        self.setModal(True)
        self.resize(750, 550)
        
        self.blocker = blocker
        self.logger = logger
        self._worker: Optional[WipeWorker] = None
        
        self.setStyleSheet("""
            QDialog {
                background: #1a1d23;
            }
            QGroupBox {
                background: #1e2228;
                border: 2px solid #2a2f3a;
                border-radius: 10px;
                margin-top: 12px;
                padding: 16px;
                font-weight: 600;
                color: #e8e8e8;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
                color: #8a919e;
            }
            QLabel {
                color: #c0c0c0;
                font-size: 12px;
            }
            QComboBox {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                padding: 8px 12px;
                color: #e8e8e8;
                min-height: 20px;
            }
            QComboBox:hover {
                border-color: #4a90e2;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #8a919e;
                margin-right: 10px;
            }
            QComboBox QAbstractItemView {
                background: #252932;
                border: 2px solid #353945;
                selection-background-color: #4a90e2;
                color: #e8e8e8;
            }
            QProgressBar {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                font-weight: 600;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #dc2626, stop:1 #991b1b);
                border-radius: 4px;
            }
            QPlainTextEdit {
                background: #0d1117;
                border: 2px solid #2a2f3a;
                border-radius: 6px;
                color: #58a6ff;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        
        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Warning banner
        warning_frame = QtWidgets.QFrame()
        warning_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7f1d1d, stop:1 #991b1b);
                border-radius: 8px;
                padding: 12px;
            }
            QLabel {
                color: #fecaca;
                font-weight: 600;
            }
        """)
        warning_layout = QtWidgets.QHBoxLayout(warning_frame)
        warning_icon = QtWidgets.QLabel("⚠️")
        warning_icon.setStyleSheet("font-size: 24px;")
        warning_layout.addWidget(warning_icon)
        warning_text = QtWidgets.QLabel(
            "WARNING: This will PERMANENTLY DESTROY all data on the selected device!\n"
            "This action cannot be undone. Make sure you have selected the correct device."
        )
        warning_text.setWordWrap(True)
        warning_layout.addWidget(warning_text, 1)
        layout.addWidget(warning_frame)
        
        # Device selection group
        device_group = QtWidgets.QGroupBox("Select Device")
        device_layout = QtWidgets.QHBoxLayout(device_group)
        
        self.cmb_device = QtWidgets.QComboBox()
        self.cmb_device.setMinimumWidth(400)
        device_layout.addWidget(self.cmb_device, 1)
        
        self.btn_refresh = QtWidgets.QPushButton("↻ Refresh")
        self.btn_refresh.setStyleSheet("""
            QPushButton {
                background: #2d3440;
                color: #e8e8e8;
                border: 2px solid #3a4150;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #3a4150;
            }
        """)
        self.btn_refresh.clicked.connect(self.refresh_devices)
        device_layout.addWidget(self.btn_refresh)
        
        layout.addWidget(device_group)
        
        # Wipe options group
        options_group = QtWidgets.QGroupBox("Wipe Options")
        options_layout = QtWidgets.QVBoxLayout(options_group)
        
        # Method info row
        row1_layout = QtWidgets.QHBoxLayout()
        method_label = QtWidgets.QLabel("Method: Native Windows I/O (writes zeros to all sectors)")
        method_label.setStyleSheet("color: #8a919e; font-size: 12px;")
        row1_layout.addWidget(method_label)
        row1_layout.addStretch()
        options_layout.addLayout(row1_layout)
        
        # Format checkbox row
        row2_layout = QtWidgets.QHBoxLayout()
        self.chk_format = QtWidgets.QCheckBox("Format to ExFAT after wipe")
        self.chk_format.setChecked(True)  # Default to enabled
        self.chk_format.setStyleSheet("color: #e8e8e8;")
        row2_layout.addWidget(self.chk_format)
        
        format_info = QtWidgets.QLabel("(Creates partition and formats for immediate reuse)")
        format_info.setStyleSheet("color: #6b7280; font-size: 11px; font-style: italic;")
        row2_layout.addWidget(format_info)
        row2_layout.addStretch()
        options_layout.addLayout(row2_layout)
        
        layout.addWidget(options_group)
        
        # Progress group
        progress_group = QtWidgets.QGroupBox("Progress")
        progress_layout = QtWidgets.QVBoxLayout(progress_group)
        
        self.pbar = QtWidgets.QProgressBar()
        self.pbar.setMinimum(0)
        self.pbar.setMaximum(100)
        self.pbar.setValue(0)
        progress_layout.addWidget(self.pbar)
        
        self.lbl_status = QtWidgets.QLabel("Ready")
        self.lbl_status.setStyleSheet("color: #8a919e; font-size: 12px;")
        progress_layout.addWidget(self.lbl_status)
        
        layout.addWidget(progress_group)
        
        # Log output
        log_group = QtWidgets.QGroupBox("Operation Log")
        log_layout = QtWidgets.QVBoxLayout(log_group)
        
        self.log_text = QtWidgets.QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group)
        
        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_start = QtWidgets.QPushButton("🗑️ Start Secure Wipe")
        self.btn_start.setMinimumWidth(160)
        self.btn_start.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #dc2626, stop:1 #b91c1c);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-weight: 700;
                font-size: 14px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ef4444, stop:1 #dc2626);
            }
            QPushButton:disabled {
                background: #4a5568;
                color: #a0aec0;
            }
        """)
        self.btn_start.clicked.connect(self.on_start_wipe)
        btn_layout.addWidget(self.btn_start)
        
        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setMinimumWidth(120)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                background: #2d3440;
                color: #e8e8e8;
                border: 2px solid #3a4150;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background: #3a4150;
                border-color: #4a5162;
            }
            QPushButton:disabled {
                background: #1e2129;
                color: #5a6270;
                border-color: #2a2f3a;
            }
        """)
        self.btn_cancel.clicked.connect(self.on_cancel)
        btn_layout.addWidget(self.btn_cancel)
        
        self.btn_close = QtWidgets.QPushButton("Close")
        self.btn_close.setMinimumWidth(120)
        self.btn_close.setStyleSheet("""
            QPushButton {
                background: #2d3440;
                color: #e8e8e8;
                border: 2px solid #3a4150;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background: #3a4150;
                border-color: #4a5162;
            }
        """)
        self.btn_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
        
        self.refresh_devices()
    
    def refresh_devices(self):
        """Refresh the list of available removable devices."""
        self.cmb_device.clear()
        devices = self.blocker.list_physical()
        
        if not devices:
            self.cmb_device.addItem("No removable devices found", None)
            self.btn_start.setEnabled(False)
            return
        
        for dev in devices:
            idx = dev['index']
            size = dev['size']
            vendor = dev.get('vendor', '')
            product = dev.get('product', '')
            
            size_gb = size / (1024**3)
            
            # Include vendor/product in display if available
            device_name = f"PhysicalDrive{idx}"
            if vendor and product:
                device_name += f" - {vendor} {product}"
            elif vendor:
                device_name += f" - {vendor}"
            elif product:
                device_name += f" - {product}"
            
            self.cmb_device.addItem(
                f"{device_name} ({size_gb:.2f} GB)",
                dev  # Store entire dict
            )
        
        self.btn_start.setEnabled(True)
    
    def on_start_wipe(self):
        """Start the secure wipe operation."""
        device_data = self.cmb_device.currentData()
        if not device_data:
            QtWidgets.QMessageBox.warning(self, "No Device", "No device selected")
            return
        
        device_index = device_data['index']
        device_size = device_data['size']
        format_after = self.chk_format.isChecked()
        
        # Estimate time
        est_seconds = max(30, int(device_size / (1024**3) * 30))
        est_time = f"{est_seconds // 60} min {est_seconds % 60} sec"
        
        # Build confirmation message
        format_msg = "\n\nAfter wiping, the device will be formatted to ExFAT." if format_after else ""
        
        # First confirmation
        reply = QtWidgets.QMessageBox.warning(
            self, "⚠️ DANGER - Confirm Wipe",
            f"You are about to PERMANENTLY DESTROY all data on:\n\n"
            f"    PhysicalDrive{device_index}\n"
            f"    Size: {device_size/(1024**3):.2f} GB\n\n"
            f"Method: Native Windows I/O (writes zeros to every sector)\n"
            f"Estimated time: {est_time}{format_msg}\n\n"
            f"THIS ACTION CANNOT BE UNDONE!\n\n"
            f"Are you absolutely sure you want to proceed?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        
        if reply != QtWidgets.QMessageBox.Yes:
            return
        
        # Second confirmation - type WIPE
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Final Confirmation Required",
            "To confirm, type 'WIPE' below (case-sensitive):"
        )
        
        if not ok or text != "WIPE":
            QtWidgets.QMessageBox.information(self, "Cancelled", "Wipe operation cancelled")
            return
        
        # Clear log
        self.log_text.clear()
        
        format_after_wipe = self.chk_format.isChecked()
        
        self.logger.info(f"[WIPE] Starting secure disk wipe")
        self.logger.info(f"[WIPE] Device: PhysicalDrive{device_index}")
        self.logger.info(f"[WIPE] Size: {device_size:,} bytes ({device_size/(1024**3):.2f} GB)")
        self.logger.info(f"[WIPE] Format after wipe: {'Yes (ExFAT)' if format_after_wipe else 'No'}")
        self.logger.info(f"[WIPE] Method: Native Windows I/O")
        
        device_info = {'index': device_index, 'size': device_size}
        
        self._worker = WipeWorker(device_index, device_info, 1, format_after_wipe)
        self._worker.progress.connect(self.on_progress)
        self._worker.log.connect(self.on_log)
        self._worker.finished.connect(self.on_finished)
        self._worker.failed.connect(self.on_failed)
        
        # Disable UI during operation
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_refresh.setEnabled(False)
        self.cmb_device.setEnabled(False)
        self.chk_format.setEnabled(False)
        self.btn_close.setEnabled(False)
        
        # Reset progress bar style
        self.pbar.setStyleSheet("""
            QProgressBar {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                font-weight: 600;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #dc2626, stop:1 #991b1b);
                border-radius: 4px;
            }
        """)
        self.lbl_status.setStyleSheet("color: #8a919e; font-size: 12px;")
        
        self._worker.start()
    
    def on_cancel(self):
        """Request cancellation of the wipe operation."""
        if self._worker:
            reply = QtWidgets.QMessageBox.question(
                self, "Cancel Wipe",
                "Are you sure you want to cancel the wipe operation?\n\n"
                "Note: The device may be left in a partially wiped state.",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if reply == QtWidgets.QMessageBox.Yes:
                self._worker.request_cancel()
                self.btn_cancel.setEnabled(False)
                self.btn_cancel.setText("Cancelling...")
                self.logger.info("[WIPE] Cancellation requested...")
    
    def on_progress(self, pct: int, status: str):
        """Update progress display."""
        self.pbar.setValue(pct)
        self.lbl_status.setText(status)
    
    def on_log(self, msg: str):
        """Append message to log display."""
        self.log_text.appendPlainText(msg)
        self.logger.info(msg)
    
    def on_finished(self, message: str):
        """Handle successful completion."""
        self.pbar.setValue(100)
        self.pbar.setStyleSheet("""
            QProgressBar {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                font-weight: 600;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #52c884, stop:1 #3a9b6a);
                border-radius: 4px;
            }
        """)
        self.lbl_status.setText("Wipe completed and verified successfully!")
        self.lbl_status.setStyleSheet("color: #52c884; font-size: 12px; font-weight: 600;")
        
        self._reset_ui()
        
        QtWidgets.QMessageBox.information(
            self, "✓ Wipe Complete",
            message
        )
    
    def on_failed(self, error: str):
        """Handle failure or cancellation."""
        self.pbar.setStyleSheet("""
            QProgressBar {
                background: #252932;
                border: 2px solid #353945;
                border-radius: 6px;
                text-align: center;
                color: #e8e8e8;
                font-weight: 600;
                height: 28px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #f59e0b, stop:1 #d97706);
                border-radius: 4px;
            }
        """)
        self.lbl_status.setText("Wipe failed or cancelled")
        self.lbl_status.setStyleSheet("color: #ff6b6b; font-size: 12px; font-weight: 600;")
        
        self._reset_ui()
        
        QtWidgets.QMessageBox.critical(self, "Wipe Failed", error)
    
    def _reset_ui(self):
        """Reset UI elements after operation completes."""
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setText("Cancel")
        self.btn_refresh.setEnabled(True)
        self.cmb_device.setEnabled(True)
        self.chk_format.setEnabled(True)
        self.btn_close.setEnabled(True)
        self.btn_start.setEnabled(True)
