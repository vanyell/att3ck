import threading
import queue
import logging
import time
from typing import List, Optional
from kinetix.core.worker import LogWorker
from kinetix.outputs.base import OutputProvider
from kinetix.core.temporal import TemporalEngine

logger = logging.getLogger(__name__)

class KinetixEngine:
    def __init__(self, output_providers: List[OutputProvider], worker_count: int = 4, temporal_engine: Optional[TemporalEngine] = None):
        self.output_providers = output_providers
        self.worker_count = worker_count
        self.temporal_engine = temporal_engine or TemporalEngine()
        self.event_queue = queue.Queue(maxsize=10000)
        self.workers: List[LogWorker] = []
        self._stop_event = threading.Event()
        self._running = False

    def start(self):
        """Initialize and start the worker pool."""
        if self._running:
            return

        logger.info(f"Starting Kinetix Engine with {self.worker_count} workers...")
        self._running = True
        self._stop_event.clear()

        for i in range(self.worker_count):
            worker = LogWorker(
                worker_id=i,
                input_queue=self.event_queue,
                output_providers=self.output_providers,
                stop_event=self._stop_event,
                temporal_engine=self.temporal_engine
            )
            worker.start()
            self.workers.append(worker)

    def stop(self):
        """Gracefully shut down workers and flush output."""
        logger.info("Stopping Kinetix Engine...")
        self._stop_event.set()
        
        total_events = 0
        # Wait for workers to finish and collect stats
        for worker in self.workers:
            worker.join()
            logger.info(f"Worker {worker.worker_id} processed {worker.event_count} events.")
            total_events += worker.event_count
        
        for provider in self.output_providers:
            provider.flush()
            provider.close()
            
        self._running = False
        self.workers = []
        logger.info(f"Kinetix Engine stopped. Total events processed: {total_events}")

    def emit(self, event):
        """Add an event to the processing queue."""
        try:
            self.event_queue.put(event, timeout=1.0)
        except queue.Full:
            logger.warning("Event queue full, dropping event!")

    def wait_for_completion(self, timeout: float = 0):
        """Block until all events in the queue have been processed.
        
        If timeout > 0, raises queue.Empty if queue is not empty after timeout seconds.
        """
        if timeout > 0:
            deadline = time.monotonic() + timeout
            while not self.event_queue.empty():
                if time.monotonic() > deadline:
                    remaining = self.event_queue.qsize()
                    logger.warning(f"Drain timeout after {timeout}s — {remaining} events remaining in queue.")
                    break
                try:
                    self.event_queue.get(timeout=min(0.5, timeout))
                    self.event_queue.task_done()
                except queue.Empty:
                    if self.event_queue.empty():
                        break
        else:
            self.event_queue.join()
