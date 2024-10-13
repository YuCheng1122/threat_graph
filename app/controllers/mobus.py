from app.models.mobus_db import ModbusEventModel
from app.schemas.mobus import ModbusEventCreate, ModbusEventResponse
from datetime import datetime
from typing import List

modbus_model = ModbusEventModel()
class ModbusEventController:
    @staticmethod
    def create_modbus_event(event: ModbusEventCreate):
        return modbus_model.create_event(event)

    def get_modbus_events(start_time: datetime, end_time: datetime) -> List[ModbusEventResponse]:
        return modbus_model.get_events(start_time, end_time)