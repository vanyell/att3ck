from abc import ABC, abstractmethod
from typing import List, Optional, Dict
import time
import logging
from kinetix.schemas.base import BaseLogEvent

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
    def __init__(self, scenario_id: str, name: str, stages: List[Dict] = None):
        super().__init__(scenario_id, name)
        self.stages = stages or []
        self.current_stage = 0

    def run(self, engine):
        self.is_running = True
        logger.info(f"Running Attack Chain: {self.name} ({self.scenario_id})")
        
        for stage in self.stages:
            if not self.is_running:
                break
                
            logger.info(f"Executing Stage: {stage.get('name')}")
            # Each stage emits a list of events
            events = stage.get("events", [])
            for event in events:
                event.scenario_id = self.scenario_id
                engine.emit(event)
                
            # Simulate delay between stages if specified
            delay = stage.get("delay", 1.0)
            time.sleep(delay)
            
        self.is_running = False
        logger.info(f"Attack Chain {self.name} completed.")

class StandAloneScenario(Scenario):
    """
    Simulates individual malicious events or small bursts.
    """
    def __init__(self, scenario_id: str, name: str, events: List[BaseLogEvent]):
        super().__init__(scenario_id, name)
        self.events = events

    def run(self, engine):
        logger.info(f"Running Stand-alone Scenario: {self.name}")
        for event in self.events:
            event.scenario_id = self.scenario_id
            engine.emit(event)
