from pydantic import BaseModel
from datetime import datetime
from typing import List, Dict

class AgentMitre(BaseModel):
    mitre_data: list

class AgentMitreRequest(BaseModel):
    agent_id: str
    start_time: str
    end_time: str

class AgentRansomware(BaseModel):
    ransomware_data: Dict[str, List[str] | int]

class AgentRansomwareRequest(BaseModel):
    agent_id: str
    start_time: str
    end_time: str

class AgentCVE(BaseModel):
    cve_data: Dict[str, List[str] | int]

class AgentCVERequest(BaseModel):
    agent_id: str
    start_time: str
    end_time: str

class IoCItem(BaseModel):
    ioc_type: str
    ioc_count: int
    ioc_data: List[str]

class AgentIoC(BaseModel):
    ioc_data: List[IoCItem]

class AgentIoCRequest(BaseModel):
    agent_id: str
    start_time: str
    end_time: str

class AgentCompliance(BaseModel):
    compliance_data: Dict[str, List[str] | int]

class AgentComplianceRequest(BaseModel):
    agent_id: str
    start_time: str
    end_time: str