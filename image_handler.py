import os
import threading
from base_disk_handler import BaseDiskHandler

try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    HAS_PYEWF = False

class ImageFileHandler(BaseDiskHandler):
    def __init__(self):
        self.file_handle = None
        self.is_ewf = False
        self.ewf_handle = None
        self.size = 0
        self._lock = threading.RLock()

    def open_image(self, filepath: str) -> bool:
        with self._lock:
            try:
                # --- ADD THIS LINE ---
                # This converts 'D:/yeh_hai.E01' to 'D:\yeh_hai.E01' on Windows
                filepath = os.path.normpath(filepath) 
                # ---------------------

                if filepath.lower().endswith('.e01'):
                    if not HAS_PYEWF:
                        raise ImportError("pyewf library is missing. Cannot open E01 images.")
                    
                    filenames = pyewf.glob(filepath)
                    self.ewf_handle = pyewf.handle()
                    self.ewf_handle.open(filenames)
                    self.is_ewf = True
                    self.size = self.ewf_handle.get_media_size()
                else:
                    self.file_handle = open(filepath, 'rb')
                    self.file_handle.seek(0, 2)
                    self.size = self.file_handle.tell()
                    self.file_handle.seek(0)
                return True
                
            except Exception as e:
                self.close()
                raise RuntimeError(f"Failed to initialize forensic image: {str(e)}")

    def read_bytes(self, offset: int, length: int) -> bytes:
        if self.is_ewf:
            self.ewf_handle.seek(offset)
            return self.ewf_handle.read(length)
        elif self.file_handle:
            self.file_handle.seek(offset)
            return self.file_handle.read(length)
        return b''

    def get_size(self) -> int:
        return self.size

    def close(self):
        if self.is_ewf and self.ewf_handle:
            self.ewf_handle.close()
        elif self.file_handle:
            self.file_handle.close()
