import sys
from base_disk_handler import BaseDiskHandler

class LiveDiskHandler(BaseDiskHandler):
    def __init__(self):
        self.file_handle = None
        self.size = 0

    def open_live_disk(self, drive_path: str) -> bool:
        if sys.platform != 'win32':
            return False
        try:
            self.file_handle = open(drive_path, 'rb')
            # Hard to get size for physical drive via standard seek
            self.size = 0  # Would need IOCTL to get real size
            return True
        except Exception as e:
            print(f"Error opening live disk: {e}")
            return False

    def read_bytes(self, offset: int, length: int) -> bytes:
        if self.file_handle:
            self.file_handle.seek(offset)
            return self.file_handle.read(length)
        return b''

    def get_size(self) -> int:
        return self.size

    def close(self):
        if self.file_handle:
            self.file_handle.close()
