from typing import Optional, List, Dict, Any
from pydantic import Field
from kinetix.schemas.base import BaseLogEvent

class webServerEvent(BaseLogEvent):
    source: str = "web_server"
    event_type: str = "http_request"
    
    url: str
    http_method: str
    status_code: int
    user_agent: str
    referrer: Optional[str] = None
    response_time_ms: int

class DatabaseEvent(BaseLogEvent):
    source: str = "database"
    event_type: str = "db_query"
    
    db_name: str
    query_text: str
    operation: str  # SELECT, INSERT, UPDATE, DELETE, DROP
    rows_affected: Optional[int] = None
    status: str = "success"
