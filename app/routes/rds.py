from fastapi import APIRouter, Depends
from app.schemas.rds import RDSDetectionRequest, RDSDetectionResponse
from app.controllers.rds import RDSController
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.ext.error import UnauthorizedError, ElasticsearchError, InternalServerError
from logging import getLogger

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
      'https://flask.aixsoar.com/api/rds/detection' \
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
        "event": [
          {
            "timestamp": "2024-06-16T17:43:52+00:00",
            "tag_id": "0001",
            "tag": "ransomware",
            "name": "detect the ransomware tool",
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
          raise PermissionError("User is disabled")
      if current_user.user_role == 'manager': 
        response = await RDSController.save_detection(detection)
        return response
      else:
          raise UnauthorizedError("Permission denied")
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except ValueError as e:
        raise InternalServerError(str(e))
    except ElasticsearchError as e:
        raise ElasticsearchError(str(e))
    except Exception as e:
        raise InternalServerError()
