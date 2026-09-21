import threading
from datetime import datetime, timedelta


class SimulatedClock:
    """Thread-safe virtual clock for multi-day/multi-week baseline generation.

    Decouples event timestamps from wall-clock time: workers advance this
    clock by the (diurnal/weekend-aware) delay TemporalEngine computes,
    instead of sleeping in real time for that long, so a realistic historical
    window (e.g. 7 simulated days) can be produced in a short real run.
    """

    def __init__(self, start: datetime, end: datetime):
        if end <= start:
            raise ValueError("SimulatedClock end must be after start")
        self.start = start
        self.end = end
        self._current = start
        self._lock = threading.Lock()

    @property
    def current(self) -> datetime:
        with self._lock:
            return self._current

    def advance(self, delay_seconds: float) -> datetime:
        """Atomically allocate the next timestamp and move the clock forward."""
        with self._lock:
            ts = self._current
            self._current += timedelta(seconds=delay_seconds)
            return ts

    def finished(self) -> bool:
        return self.current >= self.end

    def progress(self) -> float:
        """Fraction of the simulated window covered so far, clamped to [0, 1]."""
        total = (self.end - self.start).total_seconds()
        if total <= 0:
            return 1.0
        done = (self.current - self.start).total_seconds()
        return max(0.0, min(1.0, done / total))
