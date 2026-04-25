from abc import ABC, abstractmethod

class BaseDiskHandler(ABC):
    @abstractmethod
    def read_bytes(self, offset: int, length: int) -> bytes:
        pass

    @abstractmethod
    def get_size(self) -> int:
        pass

    @abstractmethod
    def close(self):
        pass
