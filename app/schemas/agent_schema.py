from pydantic import BaseModel
from datetime import datetime
from typing import List, Dict, Any, Optional

class AgentInfo(BaseModel):
    agent_id: str
    agent_name: str
    ip: str
    os: str
    os_version: str
    agent_status: str
    last_keep_alive: datetime
    registration_time: datetime

class AgentInfoResponse(BaseModel):
    success: bool
    content: AgentInfo
    message: str

class TacticLabel(BaseModel):
    label: str

class TacticDataPoint(BaseModel):
    timestamp: str
    count: int

class TacticData(BaseModel):
    name: str
    type: str
    data: List[TacticDataPoint]

class Tactic(BaseModel):
    label: List[TacticLabel]
    datas: List[TacticData]

class CVEBarchart(BaseModel):
    cve_name: str
    count: int

class MaliciousFile(BaseModel):
    malicious_file: str
    count: int

class Authentication(BaseModel):
    tactic: str
    count: int

class EventTable(BaseModel):
    timestamp: str
    agent_name: str
    rule_description: str
    rule_mitre_tactic: Optional[str]
    rule_mitre_id: Optional[str]
    rule_level: int

class AgentAlertsResponse(BaseModel):
    success: bool
    content: Dict[str, int]
    message: str

class AgentTacticLinechartResponse(BaseModel):
    success: bool
    content: List[Tactic]
    message: str

class AgentCVEBarchartResponse(BaseModel):
    success: bool
    content: List[CVEBarchart]
    message: str

class AgentMaliciousFileResponse(BaseModel):
    success: bool
    content: List[MaliciousFile]
    message: str

class AgentAuthenticationResponse(BaseModel):
    success: bool
    content: List[Authentication]
    message: str

class AgentEventTableResponse(BaseModel):
    success: bool
    content: List[EventTable]
    message: str
