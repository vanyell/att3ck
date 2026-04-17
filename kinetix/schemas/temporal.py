from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class TimingProfile(BaseModel):
    name: str = "Standard Business"
    avg_delay_seconds: float = 1.0
    jitter_percent: float = 0.2  # 20% variance
    working_hours_start: int = 9  # 09:00
    working_hours_end: int = 17   # 17:00
    after_hours_multiplier: float = 0.1  # 10% activity at night
    stealth_mode: bool = False

class MarkovTransition(BaseModel):
    current_event: str
    next_event_probabilities: Dict[str, float]  # e.g., {"file_access": 0.7, "network_conn": 0.2, "cleanup": 0.1}

class TemporalConfig(BaseModel):
    profile: TimingProfile
    transitions: List[MarkovTransition] = []
