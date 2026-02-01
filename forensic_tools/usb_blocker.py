"""
USB Write Blocker
Registry-based write protection for USB devices
"""

import ctypes
from typing import List
from .utils import IS_WINDOWS, get_write_block_state

if IS_WINDOWS:
    from ctypes import wintypes


class USBWriteBlocker:
    """
    USB Write Blocker using Windows Registry.
    Uses DUAL protection: StorageDevicePolicies + Group Policy RemovableStorageDevices.
    """
    
    # Device class GUIDs for Group Policy
    GUID_DISK_DRIVES = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"  # Covers SD cards, USB drives
    GUID_REMOVABLE = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"    # Removable storage devices
    
    def __init__(self):
        self.registry_protected = False
        # Method 1: Storage Device Policies (standard approach)
        self.key_path_storage = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        # Method 2: Group Policy Removable Storage Access (catches SD card readers)
        self.key_path_gp_disk = rf"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{self.GUID_DISK_DRIVES}"
        self.key_path_gp_removable = rf"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{self.GUID_REMOVABLE}"

    def enable(self) -> bool:
        """Enable USB write protection via dual registry method."""
        if not IS_WINDOWS:
            return False
        
        import winreg
        success_count = 0
        
        try:
            # Method 1: StorageDevicePolicies (standard)
            k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_storage)
            winreg.SetValueEx(k, "WriteProtect", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        try:
            # Method 2a: Group Policy - Disk Drives (covers SD cards, USB drives)
            k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_disk)
            winreg.SetValueEx(k, "Deny_Write", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        try:
            # Method 2b: Group Policy - Removable Storage
            k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_removable)
            winreg.SetValueEx(k, "Deny_Write", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        # Consider successful if at least one method worked
        if success_count > 0:
            self.registry_protected = True
            get_write_block_state()["enabled"] = True
            return True
        
        return False

    def disable(self) -> bool:
        """Disable USB write protection via dual registry method."""
        if not IS_WINDOWS:
            return False
        
        import winreg
        success_count = 0
        
        try:
            # Method 1: Clear StorageDevicePolicies
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_storage, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "WriteProtect", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        try:
            # Method 2a: Clear Group Policy - Disk Drives
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_disk, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "Deny_Write", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        try:
            # Method 2b: Clear Group Policy - Removable Storage
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_removable, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "Deny_Write", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(k)
            success_count += 1
        except Exception:
            pass
        
        # Consider successful if at least one method worked
        if success_count > 0:
            self.registry_protected = False
            get_write_block_state()["enabled"] = False
            return True
        
        return False

    def verify(self) -> bool:
        """Verify if USB write protection is currently enabled via any method."""
        if not IS_WINDOWS:
            return False
        
        import winreg
        
        # Check Method 1: StorageDevicePolicies
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_storage, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(k, "WriteProtect")
            winreg.CloseKey(k)
            if bool(val):
                return True
        except Exception:
            pass
        
        # Check Method 2a: Group Policy - Disk Drives
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_disk, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(k, "Deny_Write")
            winreg.CloseKey(k)
            if bool(val):
                return True
        except Exception:
            pass
        
        # Check Method 2b: Group Policy - Removable Storage
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.key_path_gp_removable, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(k, "Deny_Write")
            winreg.CloseKey(k)
            if bool(val):
                return True
        except Exception:
            pass
        
        return False

    def enable_device_protection(self, device_index: int) -> bool:
        """
        Enable write protection on a SPECIFIC device using IOCTL commands.
        This directly marks the physical disk as read-only at the device level.
        
        Args:
            device_index: Physical drive index (e.g., 1 for PhysicalDrive1)
        
        Returns:
            True if successful, False otherwise
        """
        if not IS_WINDOWS:
            return False
        
        # Windows IOCTL constants
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F4
        DISK_ATTRIBUTE_READ_ONLY = 0x0000000000000002
        
        # Structure for SET_DISK_ATTRIBUTES
        class SET_DISK_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Version", wintypes.DWORD),
                ("Persist", wintypes.BOOLEAN),
                ("Reserved1", wintypes.BYTE * 3),
                ("Attributes", ctypes.c_ulonglong),
                ("AttributesMask", ctypes.c_ulonglong),
                ("Reserved2", wintypes.DWORD * 4),
            ]
        
        handle = None
        try:
            # Open the physical drive
            device_path = f"\\\\.\\PhysicalDrive{device_index}"
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if handle == -1 or handle == 0:
                return False
            
            # Set up the attributes structure
            attrs = SET_DISK_ATTRIBUTES()
            attrs.Version = ctypes.sizeof(SET_DISK_ATTRIBUTES)
            attrs.Persist = False  # Don't persist across reboots
            attrs.Attributes = DISK_ATTRIBUTE_READ_ONLY  # Set read-only
            attrs.AttributesMask = DISK_ATTRIBUTE_READ_ONLY  # Mask to modify
            
            bytes_returned = wintypes.DWORD()
            
            # Send IOCTL command
            success = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_DISK_SET_DISK_ATTRIBUTES,
                ctypes.byref(attrs),
                ctypes.sizeof(attrs),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            return bool(success)
            
        except Exception:
            return False
        finally:
            if handle and handle != -1 and handle != 0:
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass

    def disable_device_protection(self, device_index: int) -> bool:
        """
        Disable write protection on a SPECIFIC device using IOCTL commands.
        Clears the read-only flag at the device level.
        
        Args:
            device_index: Physical drive index (e.g., 1 for PhysicalDrive1)
        
        Returns:
            True if successful, False otherwise
        """
        if not IS_WINDOWS:
            return False
        
        # Windows IOCTL constants
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F4
        DISK_ATTRIBUTE_READ_ONLY = 0x0000000000000002
        
        # Structure for SET_DISK_ATTRIBUTES
        class SET_DISK_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Version", wintypes.DWORD),
                ("Persist", wintypes.BOOLEAN),
                ("Reserved1", wintypes.BYTE * 3),
                ("Attributes", ctypes.c_ulonglong),
                ("AttributesMask", ctypes.c_ulonglong),
                ("Reserved2", wintypes.DWORD * 4),
            ]
        
        handle = None
        try:
            # Open the physical drive
            device_path = f"\\\\.\\PhysicalDrive{device_index}"
            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            if handle == -1 or handle == 0:
                return False
            
            # Set up the attributes structure
            attrs = SET_DISK_ATTRIBUTES()
            attrs.Version = ctypes.sizeof(SET_DISK_ATTRIBUTES)
            attrs.Persist = False  # Don't persist across reboots
            attrs.Attributes = 0  # Clear read-only
            attrs.AttributesMask = DISK_ATTRIBUTE_READ_ONLY  # Mask to modify
            
            bytes_returned = wintypes.DWORD()
            
            # Send IOCTL command
            success = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_DISK_SET_DISK_ATTRIBUTES,
                ctypes.byref(attrs),
                ctypes.sizeof(attrs),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            return bool(success)
            
        except Exception:
            return False
        finally:
            if handle and handle != -1 and handle != 0:
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass

    @staticmethod
    def list_physical() -> List[dict]:
        """
        Returns list of device info dicts for REMOVABLE drives only (USB devices).
        Uses IOCTL_STORAGE_QUERY_PROPERTY to filter out internal/fixed drives.
        Extracts vendor, product, and serial number from device descriptor.
        
        Returns:
            List of dicts: [{'index': int, 'size': int, 'vendor': str, 'product': str, 'serial': str}, ...]
        """
        if not IS_WINDOWS:
            return []
        
        # Windows API constants
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 1
        FILE_SHARE_WRITE = 2
        OPEN_EXISTING = 3
        IOCTL_DISK_GET_LENGTH_INFO = 0x7405C
        IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        
        # Storage property query structures
        class STORAGE_PROPERTY_QUERY(ctypes.Structure):
            _fields_ = [
                ("PropertyId", wintypes.DWORD),
                ("QueryType", wintypes.DWORD),
                ("AdditionalParameters", wintypes.BYTE * 1),
            ]
        
        class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
            _fields_ = [
                ("Version", wintypes.DWORD),
                ("Size", wintypes.DWORD),
                ("DeviceType", wintypes.BYTE),
                ("DeviceTypeModifier", wintypes.BYTE),
                ("RemovableMedia", wintypes.BOOLEAN),
                ("CommandQueueing", wintypes.BOOLEAN),
                ("VendorIdOffset", wintypes.DWORD),
                ("ProductIdOffset", wintypes.DWORD),
                ("ProductRevisionOffset", wintypes.DWORD),
                ("SerialNumberOffset", wintypes.DWORD),
                ("BusType", wintypes.DWORD),
                ("RawPropertiesLength", wintypes.DWORD),
                ("RawDeviceProperties", wintypes.BYTE * 1),
            ]
        
        devs = []
        for i in range(32):
            h = INVALID_HANDLE
            try:
                h = ctypes.windll.kernel32.CreateFileW(
                    f"\\\\.\\PhysicalDrive{i}",
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    0,
                    None
                )
                if h == INVALID_HANDLE:
                    continue
                
                # Check if drive is removable using IOCTL
                query = STORAGE_PROPERTY_QUERY()
                query.PropertyId = 0  # StorageDeviceProperty
                query.QueryType = 0   # PropertyStandardQuery
                
                buffer_size = ctypes.sizeof(STORAGE_DEVICE_DESCRIPTOR) + 512
                buffer = ctypes.create_string_buffer(buffer_size)
                bytes_returned = wintypes.DWORD()
                
                is_removable = False
                ok = ctypes.windll.kernel32.DeviceIoControl(
                    h,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ctypes.byref(query),
                    ctypes.sizeof(query),
                    buffer,
                    buffer_size,
                    ctypes.byref(bytes_returned),
                    None
                )
                
                if ok:
                    desc = ctypes.cast(buffer, ctypes.POINTER(STORAGE_DEVICE_DESCRIPTOR)).contents
                    is_removable = bool(desc.RemovableMedia)
                    # Note: BusType 7 = USB, but RemovableMedia is more reliable
                    
                    # Extract vendor, product, serial from buffer
                    vendor = ""
                    product = ""
                    serial = ""
                    
                    try:
                        # Offsets point to null-terminated strings in buffer
                        if desc.VendorIdOffset > 0 and desc.VendorIdOffset < buffer_size:
                            vendor = ctypes.string_at(ctypes.addressof(buffer) + desc.VendorIdOffset).decode('ascii', errors='ignore').strip()
                        if desc.ProductIdOffset > 0 and desc.ProductIdOffset < buffer_size:
                            product = ctypes.string_at(ctypes.addressof(buffer) + desc.ProductIdOffset).decode('ascii', errors='ignore').strip()
                        if desc.SerialNumberOffset > 0 and desc.SerialNumberOffset < buffer_size:
                            serial = ctypes.string_at(ctypes.addressof(buffer) + desc.SerialNumberOffset).decode('ascii', errors='ignore').strip()
                    except Exception:
                        # If string extraction fails, continue with empty strings
                        pass
                
                # Only include removable drives (filters out internal/fixed drives)
                if not is_removable:
                    continue
                
                # Get drive size
                size_info = ctypes.c_ulonglong()
                bytes_returned = wintypes.DWORD()
                ok = ctypes.windll.kernel32.DeviceIoControl(
                    h,
                    IOCTL_DISK_GET_LENGTH_INFO,
                    None,
                    0,
                    ctypes.byref(size_info),
                    ctypes.sizeof(size_info),
                    ctypes.byref(bytes_returned),
                    None
                )
                
                if ok and size_info.value > 0:
                    devs.append({
                        'index': i,
                        'size': size_info.value,
                        'vendor': vendor,
                        'product': product,
                        'serial': serial
                    })
            except Exception:
                # Silently skip drives that can't be accessed
                pass
            finally:
                # CRITICAL: Always close handle to prevent resource leak
                if h != INVALID_HANDLE:
                    try:
                        ctypes.windll.kernel32.CloseHandle(h)
                    except:
                        pass
        
        return devs
