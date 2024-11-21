from pydantic import BaseModel, Field
from typing import Dict, List
from datetime import datetime

#1. Agent Summary
class AgentSummaryContent(BaseModel):
    connected_agents: int = 0
    disconnected_agents: int = 0

class AgentSummary(BaseModel):
    agent_summary: AgentSummaryContent

class AgentSummaryRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the agent summary query")
    end_time: datetime = Field(..., description="End time for the agent summary query") 

class AgentSummaryResponse(BaseModel):
    success: bool
    content: AgentSummary
    message: str

#2. Agent OS
class OSInfo(BaseModel):
    os: str = Field(description="Operating System Name")
    count: int = Field(ge=0, description="Device Count")

class AgentOSContent(BaseModel):
    agent_os: List[OSInfo]

class AgentOSRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the agent OS query")
    end_time: datetime = Field(..., description="End time for the agent OS query")

class AgentOSResponse(BaseModel):
    success: bool
    content: AgentOSContent
    message: str

#3. Last 24 hours alerts
class AlertSeverity(BaseModel):
    critical_severity: int
    high_severity: int
    medium_severity: int
    low_severity: int

class Alerts(BaseModel):
    alerts: AlertSeverity

class AlertsRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the alerts query")
    end_time: datetime = Field(..., description="End time for the alerts query")

class AlertsResponse(BaseModel):
    success: bool
    content: Alerts
    message: str

#4. CVE Barchart
class CVEBarchart(BaseModel):
    cve_name: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$", description="CVE Name")
    count: int = Field(ge=0)

class CVEBarchartContent(BaseModel):
    cve_barchart: List[CVEBarchart]

class CVEBarchartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the CVE barchart query")
    end_time: datetime = Field(..., description="End time for the CVE barchart query")

class CVEBarchartResponse(BaseModel):
    success: bool
    content: CVEBarchartContent
    message: str

#5. Malicious File Barchart
class MaliciousFile(BaseModel):
    name: str = Field(description="Malicious File Name")
    count: int = Field(ge=0, description="Malicious File Count")

class MaliciousFileBarchart(BaseModel):
    malicious_file_barchart: List[MaliciousFile]

class MaliciousFileBarchartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the malicious file barchart query")
    end_time: datetime = Field(..., description="End time for the malicious file barchart query")

class MaliciousFileBarchartResponse(BaseModel):
    success: bool
    content: MaliciousFileBarchart
    message: str

#6. IoC Barchart
class IoC(BaseModel):
    ioc: str = Field(description="IoC")
    count: int = Field(ge=0, description="IoC Count")

class IoCBarchart(BaseModel):
    ioc_barchart: List[IoC]

class IoCBarchartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the IoC barchart query")
    end_time: datetime = Field(..., description="End time for the IoC barchart query")

class IoCBarchartResponse(BaseModel):
    success: bool
    content: IoCBarchart
    message: str

#7. Tactic Linechart
class TacticLabel(BaseModel):
    label: str = Field(description="Tactic Label")

class TacticData(BaseModel):
    name: str = Field(description="Tactic Name")
    type: str = Field(description="Chart Type")
    data: List[Dict] = Field(description="Tactic Data")

class Tactic(BaseModel):
    label: List[TacticLabel] = Field(description="Tactic Label")
    datas: List[TacticData] = Field(description="Tactic Data")

class TacticLineChart(BaseModel):
    tactic_linechart: List[Tactic]

class TacticLineChartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the tactic linechart query")
    end_time: datetime = Field(..., description="End time for the tactic linechart query")

class TacticLineChartResponse(BaseModel):
    success: bool
    content: TacticLineChart
    message: str

#8. Authentication Piechart
class Authentication(BaseModel):
    tactic: str = Field(description="Tactic")
    count: int = Field(ge=0, description="Tactic Count")

class AuthenticationPiechart(BaseModel):
    authentication_piechart: List[Authentication]

class AuthenticationPiechartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the authentication piechart query")
    end_time: datetime = Field(..., description="End time for the authentication piechart query")

class AuthenticationPiechartResponse(BaseModel):
    success: bool
    content: AuthenticationPiechart
    message: str

#9. Agent Name Piechart
class AgentNameWithEventCount(BaseModel):
    agent_name: str
    event_count: int = Field(ge=0, description="Event Count")

class AgentNamePiechart(BaseModel):
    agent_name: List[AgentNameWithEventCount]

class AgentNamePiechartRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the agent name piechart query")
    end_time: datetime = Field(..., description="End time for the agent name piechart query")

class AgentNamePiechartResponse(BaseModel):
    success: bool
    content: AgentNamePiechart
    message: str

#10. Event Table
class EventTable(BaseModel):
    timestamp: str
    agent_name: str
    rule_description: str
    rule_mitre_tactic: str
    rule_mitre_id: str
    rule_level: int

class EventTableContent(BaseModel):
    event_table: List[EventTable]

class EventTableRequest(BaseModel):
    start_time: datetime = Field(..., description="Start time for the event table query")
    end_time: datetime = Field(..., description="End time for the event table query")

class EventTableResponse(BaseModel):
    success: bool
    content: EventTableContent
    message: str
