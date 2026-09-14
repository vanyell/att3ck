from abc import ABC, abstractmethod
from typing import List, Dict
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

    def run(self, engine, stop_event: threading.Event = None):
        self.is_running = True
        logger.info(f"Running Attack Chain: {self.name} ({self.scenario_id})")
        
        for stage in self.stages:
            if not self.is_running:
                break
            if stop_event and stop_event.is_set():
                break
                
            logger.info(f"Executing Stage: {stage.get('name')}")
            # Each stage emits a list of events
            events = stage.get("events", [])
            for event in events:
                event.scenario_id = self.scenario_id
                engine.emit(event)
                
            if not self.stress:
                delay = stage.get("delay", 1.0)
                # Interruptible sleep — check stop_event in short increments
                slept = 0.0
                while slept < delay:
                    if stop_event and stop_event.is_set():
                        break
                    chunk = min(0.1, delay - slept)
                    time.sleep(chunk)
                    slept += chunk
            
        self.is_running = False
        logger.info(f"Attack Chain {self.name} completed.")
