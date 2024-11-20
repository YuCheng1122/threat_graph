from fastapi import APIRouter, Depends, Query
from app.schemas.rds import RDSDetectionRequest, RDSDetectionResponse, RDSGetResponse
from app.controllers.rds import RDSController
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.ext.error import UnauthorizedError, ElasticsearchError, InternalServerError
from logging import getLogger
from datetime import datetime

# Get the centralized logger
logger = getLogger('app_logger')

router = APIRouter()

@router.post("/rds_events", response_model=RDSDetectionResponse)
async def post_rds_detection(
    detection: RDSDetectionRequest,
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to post RDS detection events.

    Request:
    curl -X 'POST' \
      'https://flask.aixsoar.com/api/rds/rds_events' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]' \
      -H 'Content-Type: application/json' \
      -d '{
        "method": "rds_detection",
        "account": "xxxxx",
        "edge_name": "xxxxx",
        "edge_ip": "192.168.100.2",
        "edge_mac": "88:11:22:33:44:55",
        "edge_os": "Windows",
        "edge_ssid": "Office-Network",
        "edge_dns_gateway": "192.168.1.1",
        "event": [
          {
            "timestamp": "2024-06-16T17:43:52+00:00",
            "tag_id": "0001",
            "tag": "ransomware",
            "file_hash": "a1b2c3d4e5f6",
            "file_name": "suspicious.exe",
            "file_path": "C:/Users/Admin/Downloads/",
            "score": "100"
          }
        ]
      }'

    Response:
    {
      "success": true,
      "message": "RDS detection events saved successfully",
      "events_saved": 1
    }
    """
    try:
        if current_user.disabled:
            raise UnauthorizedError("Unauthorized access")
        if current_user.user_role != "manager":
            raise UnauthorizedError("Unauthorized access")
        else:
            response = await RDSController.save_detection(detection)
            return response
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except ValueError as e:
        logger.error(f"Validation error in post_rds_detection: {str(e)}")
        raise InternalServerError(str(e))
    except ElasticsearchError as e:
        logger.error(f"Database error in post_rds_detection: {str(e)}")
        raise ElasticsearchError(str(e))
    except Exception as e:
        logger.error(f"Unexpected error in post_rds_detection: {str(e)}")
        raise InternalServerError()

@router.get("/rds_events", response_model=RDSGetResponse)
async def get_rds_detections(
    start_time: datetime = Query(..., description="Start time for filtering records"),
    end_time: datetime = Query(..., description="End time for filtering records"),
    account: str = Query(None, description="Optional account identifier to filter records"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get RDS detection events.

    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/rds/rds_events?start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T23:59:59Z&account=xxxxx' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'

    Response:
    {
      "success": true,
      "total": 2,
      "records": [
        {
          "timestamp": "2024-06-16T17:43:52+00:00",
          "account": "xxxxx",
          "edge_name": "xxxxx",
          "edge_ip": "192.168.100.2",
          "edge_mac": "88:11:22:33:44:55",
          "edge_os": "Windows",
          "edge_ssid": "Office-Network",
          "edge_dns_gateway": "192.168.1.1",
          "tag_id": "0001",
          "tag": "ransomware",
          "file_hash": "a1b2c3d4e5f6",
          "file_name": "suspicious.exe",
          "file_path": "C:/Users/Admin/Downloads/",
          "score": "100",
          "data_type": "rds_detection"
        }
      ]
    }
    """
    try:
        print(current_user.user_role)
        if current_user.disabled:
            raise UnauthorizedError("Unauthorized access")
        if current_user.user_role != "manager":
            raise UnauthorizedError("Unauthorized access")
        else:
            response = await RDSController.get_detections(start_time, end_time, account)
            return response
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except ElasticsearchError as e:
        logger.error(f"Database error in get_rds_detections: {str(e)}")
        raise ElasticsearchError(str(e))
    except Exception as e:
        logger.error(f"Unexpected error in get_rds_detections: {str(e)}")
        raise InternalServerError()
