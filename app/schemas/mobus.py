from pydantic import BaseModel
from typing import Dict, Optional
from datetime import datetime

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
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    modbus_function: int
    modbus_data: str
    alert: str
    additional_info: Dict
