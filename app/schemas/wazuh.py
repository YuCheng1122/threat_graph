from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime

class Agent(BaseModel):
    agent_name: str = Field(..., example="test-agent-1", description="Name of the agent")
    agent_id: str = Field(..., example="001", description="Unique identifier of the agent")
    ip: str = Field(..., example="192.168.1.100", description="IP address of the agent")
    agent_status: str = Field(..., example="Active", description="Current status of the agent")
    status_code: int = Field(..., example=0, description="Status code of the agent")
    last_keep_alive: datetime = Field(..., example="2023-07-30T12:00:00Z", description="Last keep alive timestamp")
    os: str = Field(..., example="Ubuntu", description="Operating system of the agent")
    os_version: str = Field(..., example="20.04", description="Version of the operating system")

class WazuhEvent(BaseModel):
    timestamp: datetime = Field(..., example="2023-07-30T12:05:00Z", description="Timestamp of the event")
    agent_id: str = Field(..., example="001", description="ID of the agent that generated the event")
    agent_ip: str = Field(..., example="192.168.1.100", description="IP of the agent that generated the event")
    rule_description: str = Field(..., example="File added to the system.", description="Description of the rule that triggered")
    rule_level: int = Field(..., example=3, description="Level of the rule that triggered")
    rule_id: str = Field(..., example="550", description="ID of the rule that triggered")
    rule_mitre_id: Optional[str] = Field(None, example="T1078", description="MITRE ATT&CK technique ID")
    rule_mitre_tactic: Optional[List[str]] = Field(None, example=["Persistence"], description="MITRE ATT&CK tactic")
    rule_mitre_technique: Optional[str] = Field(None, example="Valid Accounts", description="MITRE ATT&CK technique")
    event_type: str = Field(..., example="alert", description="Type of the event")
    src_ip: Optional[str] = Field(None, example="192.168.1.100", description="Source IP address")
    dest_ip: Optional[str] = Field(None, example="10.0.0.1", description="Destination IP address")
    src_port: Optional[int] = Field(None, example=12345, description="Source port")
    dest_port: Optional[int] = Field(None, example=80, description="Destination port")
    proto: Optional[str] = Field(None, example="TCP", description="Protocol used")
    app_proto: Optional[str] = Field(None, example="HTTP", description="Application protocol")

class AgentInfoRequest(BaseModel):
    agent: Agent
    events: List[WazuhEvent]

    class Config:
        schema_extra = {
            "example": {
                "agent": {
                    "agent_name": "test-agent-1",
                    "agent_id": "001",
                    "ip": "192.168.1.100",
                    "agent_status": "Active",
                    "status_code": 0,
                    "last_keep_alive": "2023-07-30T12:00:00Z",
                    "os": "Ubuntu",
                    "os_version": "20.04"
                },
                "events": [
                    {
                        "timestamp": "2023-07-30T12:05:00Z",
                        "agent_id": "001",
                        "agent_ip": "192.168.1.100",
                        "rule_description": "File added to the system.",
                        "rule_level": 3,
                        "rule_id": "550",
                        "rule_mitre_id": "T1078",
                        "rule_mitre_tactic": ["Persistence"],
                        "rule_mitre_technique": "Valid Accounts",
                        "event_type": "alert",
                        "src_ip": "192.168.1.100",
                        "dest_ip": "10.0.0.1",
                        "src_port": 12345,
                        "dest_port": 80,
                        "proto": "TCP",
                        "app_proto": "HTTP"
                    }
                ]
            }
        }

class AgentInfoResponse(BaseModel):
    message: str = Field(..., example="Agent info and events saved successfully", description="Response message")
    agent_id: str = Field(..., example="001", description="ID of the agent that was saved")

class GetAgentInfoByTimeResponse(BaseModel):
    agent_info: Dict
    events: List[Dict]

    class Config:
        schema_extra = {
            "example": {
                "agent_info": {
                    "agent_name": "test-agent-1",
                    "agent_id": "001",
                    "ip": "192.168.1.100",
                    "agent_status": "Active",
                    "status_code": 0,
                    "last_keep_alive": "2023-07-30T12:00:00Z",
                    "os": "Ubuntu",
                    "os_version": "20.04",
                    "groups": "testuser",
                    "wazuh_data_type": "agent_info"
                },
                "events": [
                    {
                        "timestamp": "2023-07-30T12:05:00Z",
                        "agent_id": "001",
                        "agent_ip": "192.168.1.100",
                        "rule_description": "File added to the system.",
                        "rule_level": 3,
                        "rule_id": "550",
                        "rule_mitre_id": "T1078",
                        "rule_mitre_tactic": ["Persistence"],
                        "rule_mitre_technique": "Valid Accounts",
                        "event_type": "alert",
                        "src_ip": "192.168.1.100",
                        "dest_ip": "10.0.0.1",
                        "src_port": 12345,
                        "dest_port": 80,
                        "proto": "TCP",
                        "app_proto": "HTTP",
                        "group": "testuser",
                        "wazuh_data_type": "wazuh_events"
                    }
                ]
            }
        }

class GetAgentInfoByGroupRequest(BaseModel):
    start_time: datetime = Field(..., example="2023-07-30T00:00:00Z", description="Start time for event query")
    end_time: datetime = Field(..., example="2023-07-31T00:00:00Z", description="End time for event query")

class GetAgentInfoByGroupResponse(BaseModel):
    agents: List[Dict]
    events: List[Dict]

    class Config:
        schema_extra = {
            "example": {
                "agents": [
                    {
                        "agent_name": "test-agent-1",
                        "agent_id": "001",
                        "ip": "192.168.1.100",
                        "agent_status": "Active",
                        "status_code": 0,
                        "last_keep_alive": "2023-07-30T12:00:00Z",
                        "os": "Ubuntu",
                        "os_version": "20.04",
                        "groups": "testuser",
                        "wazuh_data_type": "agent_info"
                    },
                    {
                        "agent_name": "test-agent-2",
                        "agent_id": "002",
                        "ip": "192.168.1.101",
                        "agent_status": "Active",
                        "status_code": 0,
                        "last_keep_alive": "2023-07-30T12:00:00Z",
                        "os": "CentOS",
                        "os_version": "7",
                        "groups": "testuser",
                        "wazuh_data_type": "agent_info"
                    }
                ],
                "events": [
                    {
                        "timestamp": "2023-07-30T12:05:00Z",
                        "agent_id": "001",
                        "agent_ip": "192.168.1.100",
                        "rule_description": "File added to the system.",
                        "rule_level": 3,
                        "rule_id": "550",
                        "rule_mitre_id": "T1078",
                        "rule_mitre_tactic": ["Persistence"],
                        "rule_mitre_technique": "Valid Accounts",
                        "event_type": "alert",
                        "src_ip": "192.168.1.100",
                        "dest_ip": "10.0.0.1",
                        "src_port": 12345,
                        "dest_port": 80,
                        "proto": "TCP",
                        "app_proto": "HTTP",
                        "group": "testuser",
                        "wazuh_data_type": "wazuh_events"
                    },
                    {
                        "timestamp": "2023-07-30T12:10:00Z",
                        "agent_id": "002",
                        "agent_ip": "192.168.1.101",
                        "rule_description": "Network connection detected",
                        "rule_level": 2,
                        "rule_id": "5001",
                        "event_type": "flow",
                        "src_ip": "192.168.1.101",
                        "dest_ip": "10.0.0.2",
                        "src_port": 54321,
                        "dest_port": 443,
                        "proto": "TCP",
                        "app_proto": "HTTPS",
                        "group": "testuser",
                        "wazuh_data_type": "wazuh_events"
                    }
                ]
            }
        }