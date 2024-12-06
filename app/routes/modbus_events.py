from fastapi import APIRouter, Depends
from typing import List
from app.ext.error import UnauthorizedError, PermissionError, InternalServerError, UnprocessableEntityError
from app.schemas.mobus import (
    ModbusEventResponse, ModbusEventsRequest, ModbusEventCreate, ModbusEventsCreateResponse,
    SyslogEventCreate, SyslogEventResponse
)
from app.controllers.mobus import ModbusEventController
from logging import getLogger
from app.controllers.auth import AuthController
from app.models.user_db import UserModel

logger = getLogger('app_logger')

router = APIRouter()

@router.get("/get-events", response_model=List[ModbusEventResponse])
async def get_modbus_events(
    request: ModbusEventsRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the modbus events
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/modbus_events/events' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer Token'
    Response:
    [
        "event_id": "fjiosdjfoisdjf",
        "timestamp": "2024-10-10T00:00:00",
        "event_type": "modbus",
        "source_ip": "192.168.1.10",
        "source_port": 502,
        "device_id": "lvr2232326934",
        "destination_ip": "192.168.1.100",
        "destination_port": 502,
        "modbus_function": 3,
        "modbus_data": "0x001F",
        "alert": "Modbus Unauthorized Access",
        "additional_info": {"register": 40001, "error_code": "ILLEGAL_DATA_VALUE"}
    }
    """
    try:
        if current_user.user_role != 'admin' and current_user.username != 'redteam2':
            raise PermissionError
        else:
            events = ModbusEventController.get_modbus_events(request.start_time, request.end_time)
            return events
    except PermissionError:
        raise PermissionError("Permission denied")
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except Exception as e:
        logger.error(f"Error in get_modbus_events: {e}")
        raise InternalServerError from e
    
@router.post("/post-events", response_model=ModbusEventsCreateResponse)
async def post_modbus_events(
    event: ModbusEventCreate,
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Post the modbus events
    Request:
    curl -X 'POST' \
      'https://flask.aixsoar.com/api/modbus_events/events' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer Token' \
      -d '{"device_id": "lvr2232326934", "timestamp": "2024-10-10T00:00:00", "event_type": "modbus", "source_ip": "192.168.1.10", "source_port": 502, "destination_ip": "192.168.1.100", "destination_port": 502, "modbus_function": 3, "modbus_data": "0x001F", "alert": "Modbus Unauthorized Access", "additional_info": {"register": 40001, "error_code": "ILLEGAL_DATA_VALUE"}}'
    Response:
    {
        "message": "Event created successfully",
        "event_id": "fjiosdjfoisdjf"
    }
    """
    try:
        if current_user.user_role != 'admin':
            raise PermissionError
        event_id = ModbusEventController.create_modbus_event(event)
        return {"message": "Event created successfully", "event_id": event_id}
    except PermissionError:
        raise PermissionError("Permission denied")
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except Exception as e:
        logger.error(f"Error in post_modbus_events: {e}")
        raise InternalServerError from e

@router.get("/get-syslog", response_model=List[SyslogEventResponse])
async def get_syslog_events(
    request: ModbusEventsRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the syslog events
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/modbus_events/syslog' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer Token'
    Response:
    [
        {
            "event_id": "fjiosdjfoisdjf",
            "device": "4WAN_1LAN_IPSec_VPN_Router",
            "timestamp": "2023-12-03T00:01:22",
            "severity": "WARNING",
            "message": "Connection Accepted",
            "details": {
                "in_interface": "eth0",
                "out_interface": "eth1",
                "src_ip": "192.168.1.100",
                "dst_ip": "203.69.85.29",
                "protocol": "TCP",
                "src_port": 35932,
                "dst_port": 80
            }
        }
    ]
    """
    try:
        if current_user.user_role != 'admin' and current_user.username != 'redteam2':
            raise PermissionError
        else:
            events = ModbusEventController.get_syslog_events(request.start_time, request.end_time)
            return events
    except PermissionError:
        raise PermissionError("Permission denied")
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except Exception as e:
        logger.error(f"Error in get_syslog_events: {e}")
        raise InternalServerError from e

@router.post("/post-syslog", response_model=ModbusEventsCreateResponse)
async def post_syslog_events(
    event: SyslogEventCreate,
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Post syslog events
    Request:
    curl -X 'POST' \
      'https://flask.aixsoar.com/api/modbus_events/syslog' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer Token' \
      -d '{
        "device": "4WAN_1LAN_IPSec_VPN_Router",
        "timestamp": "2023-12-03T00:01:22",
        "severity": "WARNING",
        "message": "Connection Accepted",
        "details": {
            "in_interface": "eth0",
            "out_interface": "eth1",
            "src_ip": "192.168.1.100",
            "dst_ip": "203.69.85.29",
            "protocol": "TCP",
            "src_port": 35932,
            "dst_port": 80
        }
    }'
    Response:
    {
        "message": "Event created successfully",
        "event_id": "fjiosdjfoisdjf"
    }
    """
    try:
        if current_user.user_role != 'admin':
            raise PermissionError
        event_id = ModbusEventController.create_syslog_event(event)
        return {"message": "Event created successfully", "event_id": event_id}
    except PermissionError:
        raise PermissionError("Permission denied")
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except Exception as e:
        logger.error(f"Error in post_syslog_events: {e}")
        raise InternalServerError from e
