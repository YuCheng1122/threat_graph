from pydantic import BaseModel
from typing import Dict, List, Optional, Literal
from datetime import datetime

from app.ext.error import GraphDataRequestParamsError

class Tags(BaseModel):
  src_ip: Optional[List[str]] = None
  dest_ip: Optional[List[str]] = None


class Event(BaseModel):
  timestamp: datetime
  event_type: Literal['alert', 'flow']
  src_ip: str
  dest_ip: str
  src_port: int
  dest_port: int
  proto: str
  app_proto: str
  tags: Tags

  # Fields specific to alert event
  signature: Optional[str] = None
  severity: Optional[int] = None

  # Fields specific to flow events
  bytes_toclient: Optional[int] = None
  bytes_toserver: Optional[int] = None

  