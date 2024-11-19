from pydantic import BaseModel, Field
from typing import List
from datetime import datetime
from typing_extensions import Literal

class RDSEvent(BaseModel):
    timestamp: datetime = Field(..., example="2024-06-16T17:43:52+00:00", description="Timestamp of the event")
    tag_id: str = Field(..., example="0001", description="ID of the detection tag")
    tag: str = Field(..., example="ransomware", description="Type of detection")
    name: str = Field(..., example="detect the ransomware tool", description="Description of the detection")
    score: str = Field(..., example="100", description="Detection confidence score")

class RDSDetectionRequest(BaseModel):
    method: Literal["rds_detection"] = Field("rds_detection", description="Method type, must be 'rds_detection'")
    account: str = Field(..., example="xxxxx", description="Account identifier")
    edge_name: str = Field(..., example="xxxxx", description="Name of the edge device")
    edge_ip: str = Field(..., example="192.168.100.2", description="IP address of the edge device")
    edge_mac: str = Field(..., example="88:11:22:33:44:55", description="MAC address of the edge device")
    edge_os: str = Field(..., example="Windows", description="Operating system of the edge device")
    event: List[RDSEvent] = Field(..., description="List of detection events")

class RDSDetectionResponse(BaseModel):
    success: bool = Field(..., example=True, description="Indicates if the operation was successful")
    message: str = Field(..., example="RDS detection events saved successfully", description="Response message")
    events_saved: int = Field(..., example=2, description="Number of events that were saved")
