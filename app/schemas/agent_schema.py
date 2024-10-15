from pydantic import BaseModel
from datetime import datetime
from typing import List, Dict, Any

class AgentInfo(BaseModel):
    agent_id: str
    agent_name: str
    ip: str
    os: str
    os_version: str
    agent_status: str
    last_keep_alive: datetime

class AgentInfoRequest(BaseModel):
    agent_name: str

class AgentInfoResponse(BaseModel):
    success: bool
    content: AgentInfo
    message: str

class AgentMitre(BaseModel):
    mitre_data: List[Dict[str, Any]]

class AgentMitreRequest(BaseModel):
    agent_name: str
    start_time: str
    end_time: str

class AgentRansomware(BaseModel):
    ransomware_data: Dict[str, List[str] | int]

class AgentRansomwareRequest(BaseModel):
    agent_name: str
    start_time: datetime
    end_time: datetime

class AgentCVE(BaseModel):
    cve_data: Dict[str, List[str] | int]

class AgentCVERequest(BaseModel):
    agent_name: str
    start_time: str
    end_time: str

class IoCItem(BaseModel):
    ioc_type: str
    ioc_count: int
    ioc_data: List[str]

class AgentIoC(BaseModel):
    ioc_data: List[IoCItem]

class AgentIoCRequest(BaseModel):
    agent_name: str
    start_time: str
    end_time: str

class AgentCompliance(BaseModel):
    compliance_data: Dict[str, List[str] | int]

class AgentComplianceRequest(BaseModel):
    agent_name: str
    start_time: str
    end_time: str

