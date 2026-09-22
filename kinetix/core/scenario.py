from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import time
import threading
import logging

logger = logging.getLogger(__name__)

class Scenario(ABC):
    def __init__(self, scenario_id: str, name: str):
        self.scenario_id = scenario_id
        self.name = name
        self.is_running = False

    @abstractmethod
    def run(self, engine):
        """Execute the scenario logic, pushing events to the engine."""
        pass

class AttackChain(Scenario):
    """
    Multi-stage state machine for complex attacks.
    """
    def __init__(self, scenario_id: str, name: str, stages: List[Dict] = None, stress: bool = False):
        super().__init__(scenario_id, name)
        self.stages = stages or []
        self.current_stage = 0
        self.stress = stress

    def run(self, engine, stop_event: threading.Event = None,
            deadline: Optional[float] = None) -> bool:
        """Emit every stage in order. Returns True if a deadline cut it short.

        `deadline` is a time.monotonic() value, not a duration. It has to be
        checked at every point this loop can block, not just between stages:
        engine.emit() blocks for up to a second per event once the queue
        fills, so one --baseline-ratio 0.95 cycle can hold the chain for
        hours. A caller that only inspected elapsed time after run() returned
        would overrun --duration by that entire cycle.
        """
        self.is_running = True
        logger.info(f"Running Attack Chain: {self.name} ({self.scenario_id})")

        def expired() -> bool:
            return deadline is not None and time.monotonic() >= deadline

        timed_out = False

        for stage in self.stages:
            if not self.is_running:
                break
            if stop_event and stop_event.is_set():
                break
            if expired():
                timed_out = True
                break

            logger.info(f"Executing Stage: {stage.get('name')}")
            # Each stage emits a list of events
            events = stage.get("events", [])
            for event in events:
                # Checked per event, not per stage: a noise stage can hold
                # tens of thousands of events, and emit() blocks on a full
                # queue. Without this a Ctrl+C or an expired deadline goes
                # unnoticed until the whole stage has drained.
                if stop_event and stop_event.is_set():
                    break
                if expired():
                    timed_out = True
                    break
                event.scenario_id = self.scenario_id
                engine.emit(event)

            if timed_out:
                break

            if not self.stress:
                delay = stage.get("delay", 1.0)
                # Interruptible sleep — check stop_event in short increments
                slept = 0.0
                while slept < delay:
                    if stop_event and stop_event.is_set():
                        break
                    if expired():
                        timed_out = True
                        break
                    chunk = min(0.1, delay - slept)
                    time.sleep(chunk)
                    slept += chunk

            if timed_out:
                break

        self.is_running = False
        if timed_out:
            logger.info(f"Attack Chain {self.name} stopped: duration deadline reached.")
        else:
            logger.info(f"Attack Chain {self.name} completed.")
        return timed_out
