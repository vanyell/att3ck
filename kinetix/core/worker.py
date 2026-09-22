import threading
import queue
import logging
import time
from typing import List, Optional
from kinetix.schemas.base import BaseLogEvent
from kinetix.outputs.base import OutputProvider
from kinetix.core.temporal import TemporalEngine
from kinetix.core.simclock import SimulatedClock

logger = logging.getLogger(__name__)

# Datetime fields (beyond `timestamp`) that some schemas stamp with
# datetime.now() at construction time. When a SimulatedClock is active these
# are shifted by the same offset as `timestamp` so an event's internal times
# stay consistent with its simulated position instead of leaking real "now".
_SECONDARY_TIME_FIELDS = ("start_time", "end_time", "last_modified_time")

class LogWorker(threading.Thread):
    # How long a worker will wait to hand off a follow-up before shedding it.
    # Long enough to ride out a brief drain stall, short enough that a
    # saturated queue cannot stall shutdown.
    FOLLOW_UP_PUT_TIMEOUT = 2.0

    def __init__(
        self,
        worker_id: int,
        input_queue: queue.Queue,
        output_providers: List[OutputProvider],
        stop_event: threading.Event,
        temporal_engine: Optional[TemporalEngine] = None,
        sim_clock: Optional[SimulatedClock] = None
    ):
        super().__init__(name=f"Worker-{worker_id}")
        self.worker_id = worker_id
        self.input_queue = input_queue
        self.output_providers = output_providers
        self.stop_event = stop_event
        self.temporal_engine = temporal_engine
        self.sim_clock = sim_clock
        self.event_count = 0  # Track throughput
        self.shed_follow_ups = 0  # Follow-ups dropped under backpressure

    def _enqueue_follow_up(self, follow_up) -> bool:
        """Queue a Markov follow-up, never blocking indefinitely.

        A bare put() deadlocks the pool. The workers are this queue's only
        consumers, so once it is full and every worker is parked in put(),
        nothing can drain it — the workers wait on each other forever and
        never look at stop_event again. The producer side hits this whenever
        AttackChain fills the queue faster than the pool drains it, which is
        the normal state under --baseline-ratio.

        Follow-ups are derived noise rather than scenario content, so shedding
        one under backpressure is strictly better than wedging the run.
        Returns True if it was queued.
        """
        deadline = time.monotonic() + self.FOLLOW_UP_PUT_TIMEOUT
        while not self.stop_event.is_set():
            try:
                # Short chunks rather than one long timeout, so a shutdown
                # during backpressure is noticed promptly.
                self.input_queue.put(follow_up, timeout=0.1)
                return True
            except queue.Full:
                if time.monotonic() >= deadline:
                    break

        self.shed_follow_ups += 1
        if self.shed_follow_ups == 1 or self.shed_follow_ups % 100 == 0:
            logger.warning(
                f"Worker {self.worker_id} shed a Markov follow-up under "
                f"backpressure ({self.shed_follow_ups} total)."
            )
        return False

    def run(self):
        logger.info(f"Worker {self.worker_id} started.")
        while not self.stop_event.is_set() or not self.input_queue.empty():
            try:
                # Get event from queue
                event = self.input_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            
            try:
                # 2. Temporal Enrichment - Spacing out events realistically
                if self.sim_clock:
                    # Simulated-clock mode: advance a virtual timeline instead
                    # of sleeping in real time, so a multi-day/week baseline
                    # can be generated far faster than wall-clock would allow.
                    delay = self.temporal_engine.calculate_delay(self.sim_clock.current) \
                        if self.temporal_engine else 1.0
                    old_ts = event.timestamp
                    new_ts = self.sim_clock.advance(delay)
                    offset = new_ts - old_ts
                    event.timestamp = new_ts
                    for field in _SECONDARY_TIME_FIELDS:
                        if hasattr(event, field):
                            setattr(event, field, getattr(event, field) + offset)
                elif self.temporal_engine:
                    delay = self.temporal_engine.calculate_delay(event.timestamp)
                    # Sleep in short increments so we can be interrupted by stop_event
                    slept = 0.0
                    while slept < delay and not self.stop_event.is_set():
                        step = min(0.1, delay - slept)
                        time.sleep(step)
                        slept += step
                
                # 3. Markov Branching - Generate follow-up noisy events
                MAX_MARKOV_DEPTH = 3
                if self.temporal_engine and event.depth < MAX_MARKOV_DEPTH:
                    next_type = self.temporal_engine.get_next_event_type(event.event_type)
                    if next_type:
                        follow_up = self.temporal_engine.create_follow_up(event, next_type)
                        if follow_up:
                            follow_up.depth = event.depth + 1
                            self._enqueue_follow_up(follow_up)
               
                for provider in self.output_providers:
                    try:
                        provider.write(event)
                    except Exception as e:
                        logger.error(f"Worker {self.worker_id} - Error writing to provider: {e}")
                
                self.event_count += 1
            except Exception as e:
                logger.error(f"Worker {self.worker_id} - Unexpected error: {e}")
            finally:
                # C3 FIX: Always mark task as done to prevent deadlock
                self.input_queue.task_done()

        logger.info(f"Worker {self.worker_id} shutting down.")
