from abc import ABC, abstractmethod
from kinetix.schemas.base import BaseLogEvent
from typing import List

class OutputProvider(ABC):
    @abstractmethod
    def write(self, event: BaseLogEvent):
        """Write a single event to the output."""
        pass

    @abstractmethod
    def flush(self):
        """Ensure all buffered events are written."""
        pass

    @abstractmethod
    def close(self):
        """Close the output stream."""
        pass
