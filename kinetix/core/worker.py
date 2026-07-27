import threading
import queue
import logging
import time
from typing import List, Optional
from kinetix.schemas.base import BaseLogEvent
from kinetix.outputs.base import OutputProvider
from kinetix.core.temporal import TemporalEngine

logger = logging.getLogger(__name__)

class LogWorker(threading.Thread):
    def __init__(
        self, 
        worker_id: int, 
        input_queue: queue.Queue, 
        output_providers: List[OutputProvider],
        stop_event: threading.Event,
        temporal_engine: Optional[TemporalEngine] = None
    ):
        super().__init__(name=f"Worker-{worker_id}")
        self.worker_id = worker_id
        self.input_queue = input_queue
        self.output_providers = output_providers
        self.stop_event = stop_event
        self.temporal_engine = temporal_engine
        self.event_count = 0  # Track throughput

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
                if self.temporal_engine:
                    delay = self.temporal_engine.calculate_delay(event.timestamp)
                    # Sleep in short increments so we can be interrupted by stop_event
                    slept = 0.0
                    while slept < delay and not self.stop_event.is_set():
                        time.sleep(min(0.1, delay - slept))
                        slept += 0.1
                
                # 3. Markov Branching - Generate follow-up noisy events
                MAX_MARKOV_DEPTH = 3
                if self.temporal_engine and event.depth < MAX_MARKOV_DEPTH:
                    next_type = self.temporal_engine.get_next_event_type(event.event_type)
                    if next_type:
                        follow_up = self.temporal_engine.create_follow_up(event, next_type)
                        if follow_up:
                            follow_up.depth = event.depth + 1
                            self.input_queue.put(follow_up)
               
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
