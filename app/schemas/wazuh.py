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
    group_name: str = Field(..., example="group1", description="Name of the group this agent belongs to")
    wazuh_data_type: str = Field(default="agent_info", Literal=True, description="Type of Wazuh data")

class WazuhEvent(BaseModel):
    timestamp: datetime = Field(..., example="2023-07-30T12:05:00Z", description="Timestamp of the event")
    agent_id: str = Field(..., example="001", description="ID of the agent that generated the event")
    agent_ip: str = Field(..., example="192.168.1.100", description="IP of the agent that generated the event")
    rule_description: str = Field(..., example="File added to the system.", description="Description of the rule that triggered")
    rule_level: int = Field(..., example=3, description="Level of the rule that triggered")
    rule_id: str = Field(..., example="550", description="ID of the rule that triggered")
    rule_mitre_id: Optional[str] = Field(None, example="T1078", description="MITRE ATT&CK technique ID")
    rule_mitre_tactic: Optional[str] = Field(None, example="Persistence", description="MITRE ATT&CK tactic")
    rule_mitre_technique: Optional[str] = Field(None, example="Valid Accounts", description="MITRE ATT&CK technique")
    group_name: str = Field(..., example="group1", description="Name of the group this event belongs to")
    wazuh_data_type: str = Field(default="wazuh_events", Literal=True, description="Type of Wazuh data")

class AgentInfoRequest(BaseModel):
    agent: List[Agent]
    events: List[WazuhEvent]

    class Config:
        schema_extra = {
            "example": {
                "agent": [  # Changed from 'agents' to 'agent'
                    {
                        "agent_name": "Agent_001",
                        "agent_id": "001",
                        "ip": "192.168.1.101",
                        "agent_status": "active",
                        "status_code": 0,
                        "last_keep_alive": "2024-08-02T10:30:00Z",
                        "group_name": "threathunting",
                        "os": "Ubuntu",
                        "os_version": "20.04",
                        "wazuh_data_type": "agent_info"
                    },
                    {
                        "agent_name": "Agent_002",
                        "agent_id": "002",
                        "ip": "192.168.1.102",
                        "agent_status": "active",
                        "status_code": 0,
                        "last_keep_alive": "2024-08-02T10:35:00Z",
                        "group_name": "networksecurity",
                        "os": "Windows",
                        "os_version": "10",
                        "wazuh_data_type": "agent_info"
                    },
                    {
                        "agent_name": "Agent_003",
                        "agent_id": "003",
                        "ip": "192.168.1.103",
                        "agent_status": "disconnected",
                        "status_code": 1,
                        "last_keep_alive": "2024-08-02T09:45:00Z",
                        "group_name": "threathunting",
                        "os": "CentOS",
                        "os_version": "8",
                        "wazuh_data_type": "agent_info"
                    }
                ],
                "events": [
                    {
                        "timestamp": "2024-08-02T11:00:00Z",
                        "agent_id": "001",
                        "agent_ip": "192.168.1.101",
                        "rule_description": "File integrity checksum changed.",
                        "rule_level": 7,
                        "rule_id": "550",
                        "rule_mitre_id": "T1565",
                        "rule_mitre_tactic": ["Impact"],
                        "rule_mitre_technique": "Data Manipulation",
                        "group_name": "threathunting",
                        "wazuh_data_type": "wazuh_events"
                    },
                    {
                        "timestamp": "2024-08-02T11:05:00Z",
                        "agent_id": "002",
                        "agent_ip": "192.168.1.102",
                        "rule_description": "Multiple authentication failures.",
                        "rule_level": 10,
                        "rule_id": "5710",
                        "rule_mitre_id": "T1110",
                        "rule_mitre_tactic": ["Credential Access"],
                        "rule_mitre_technique": "Brute Force",
                        "group_name": "networksecurity",
                        "wazuh_data_type": "wazuh_events"
                    },
                    {
                        "timestamp": "2024-08-02T11:10:00Z",
                        "agent_id": "003",
                        "agent_ip": "192.168.1.103",
                        "rule_description": "Possible SQL injection attempt.",
                        "rule_level": 15,
                        "rule_id": "31101",
                        "rule_mitre_id": "T1190",
                        "rule_mitre_tactic": ["Initial Access"],
                        "rule_mitre_technique": "Exploit Public-Facing Application",
                        "group_name": "threathunting",
                        "wazuh_data_type": "wazuh_events"
                    }
                ]
            }
        }

class AgentInfoResponse(BaseModel):
    message: str = Field(..., example="Agents info and events saved successfully", description="Response message")
    agent_ids: List[str] = Field(..., example=["001", "002"], description="IDs of the agents that were saved")

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
                    "group_name": "group1",
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
                        "rule_mitre_tactic": "Persistence",
                        "rule_mitre_technique": "Valid Accounts",
                        "group_name": "group1",
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
                        "group_name": "group1",
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
                        "group_name": "group1",
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
                        "group_name": "group1",
                        "wazuh_data_type": "wazuh_events"
                    },
                    {
                        "timestamp": "2023-07-30T12:10:00Z",
                        "agent_id": "002",
                        "agent_ip": "192.168.1.101",
                        "rule_description": "Network connection detected",
                        "rule_level": 2,
                        "rule_id": "5001",
                        "group_name": "group1",
                        "wazuh_data_type": "wazuh_events"
                    }
                ]
            }
        }