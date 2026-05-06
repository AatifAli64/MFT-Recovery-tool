import sys
import ctypes
from ctypes import wintypes
from base_disk_handler import BaseDiskHandler

# Windows Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

if sys.platform == 'win32':
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    # Setup argument types for safety
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    
    kernel32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    
    kernel32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel32.ReadFile.restype = wintypes.BOOL
    
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

class LiveDiskHandler(BaseDiskHandler):
    def __init__(self):
        self.handle = None
        self.size = 0

    def open_live_disk(self, drive_path: str) -> bool:
        if sys.platform != 'win32':
            print("Live disk analysis is only supported on Windows.")
            return False
            
        try:
            self.handle = kernel32.CreateFileW(
                drive_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )
            
            if self.handle == INVALID_HANDLE_VALUE:
                err = ctypes.get_last_error()
                print(f"Error opening live disk: Windows Error {err}")
                self.handle = None
                return False
                
            self.size = 0  # Would need IOCTL to get real size
            return True
        except Exception as e:
            print(f"Error opening live disk: {e}")
            self.handle = None
            return False

    def read_bytes(self, offset: int, length: int) -> bytes:
        if not self.handle:
            return b''
            
        # Seek
        ret = kernel32.SetFilePointerEx(self.handle, ctypes.c_longlong(offset), None, 0)
        if not ret:
            # End of disk or invalid offset
            return b''
            
        # Read
        buffer = ctypes.create_string_buffer(length)
        bytes_read = wintypes.DWORD(0)
        
        ret = kernel32.ReadFile(self.handle, buffer, length, ctypes.byref(bytes_read), None)
        if not ret:
            err = ctypes.get_last_error()
            if err == 5: # ERROR_ACCESS_DENIED
                raise PermissionError(f"[Errno 13] Permission denied (Windows Error 5) reading at offset {offset}")
            elif err in (87, 38, 21, 27): # ERROR_INVALID_PARAMETER, ERROR_HANDLE_EOF, ERROR_NOT_READY, ERROR_SECTOR_NOT_FOUND
                return b''
            else:
                raise OSError(f"Windows Error {err} reading at offset {offset}")
                
        return buffer.raw[:bytes_read.value]

    def get_size(self) -> int:
        return self.size

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
