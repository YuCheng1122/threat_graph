from pydantic import BaseModel
from typing import Dict, Optional
from datetime import datetime

# Original models - keep unchanged
class ModbusEventCreate(BaseModel):
    device_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    modbus_function: int
    modbus_data: str
    alert: str
    additional_info: Dict
    
class ModbusEventsCreateResponse(BaseModel):
    message: str
    event_id: str

class ModbusEventsRequest(BaseModel):
    start_time: datetime
    end_time: datetime

class ModbusEventResponse(BaseModel):
    event_id: str
    device_id: str
    timestamp: str
    event_type: str
    source_port: int
    destination_ip: str
    destination_port: int
    modbus_function: int
    modbus_data: str
    alert: str
    additional_info: Dict

# New Syslog models
class SyslogDetails(BaseModel):
    in_interface: str
    out_interface: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int

class SyslogEventCreate(BaseModel):
    device: str
    timestamp: datetime
    severity: str
    message: str
    details: SyslogDetails

class SyslogEventResponse(BaseModel):
    event_id: str
    device: str
    timestamp: str
    severity: str
    message: str
    details: SyslogDetails
