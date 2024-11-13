from fastapi import APIRouter, Depends
from logging import getLogger

from app.models.user_db import UserModel
from app.controllers.auth import AuthController
from app.controllers.wazuh import AgentController
from app.controllers.dashboard_controller import DashboardController
from app.ext.error import PermissionError, InternalServerError, UnauthorizedError
from app.schemas.dashboard_schema import *


# Get the centralized logger
logger = getLogger('app_logger')

router = APIRouter()

@router.get("/agent_summary", response_model=AgentSummaryResponse)
async def get_agent_summary(
    request: AgentSummaryRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the agent connnection summary.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/agent_summary?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "agent_summary": {
        "connected_agents": 10,
        "disconnected_agents": 5
        }
      }
        "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            agent_summary = await DashboardController.clean_agent_summary(
                start_time=request.start_time,
                end_time=request.end_time,
            )
            return {
                "success": True,
                "content": agent_summary,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        agent_summary = await DashboardController.clean_agent_summary(
            start_time=request.start_time,
            end_time=request.end_time,
            user_groups=user_groups
        )
        return {
            "success": True,
            "content": agent_summary,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting agent summary: {e}")
        raise InternalServerError("Internal server error")

@router.get("/agent_os", response_model=AgentOSResponse)
async def get_agent_os(
    request: AgentOSRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the agent OS summary.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/agent_os?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "agent_os": [
        {"os": "Windows", "count": 10},
        {"os": "Linux", "count": 5}
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            agent_os_data = await DashboardController.clean_agent_os(
                start_time=request.start_time,
                end_time=request.end_time,
            )
            return {
                "success": True,
                "content": agent_os_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        agent_os_data = await DashboardController.clean_agent_os(
            start_time=request.start_time,
            end_time=request.end_time,
            user_groups=user_groups
        )
        return {
            "success": True,
            "content": agent_os_data,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting agent OS: {e}")
        raise InternalServerError("Internal server error")

@router.get("/alerts", response_model=AlertsResponse)
async def get_alerts(
    request: AlertsRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the different level alerts count.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/alerts?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "alerts":  {
            "critical_severity": 5,
            "high_severity": 10,
            "medium_severity": 15,
            "low_severity": 20
        }
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            alerts = await DashboardController.clean_alerts(
                start_time=request.start_time,
                end_time=request.end_time,
            )
            return {
                "success": True,
                "content": alerts,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        alerts = await DashboardController.clean_alerts(
            start_time=request.start_time,
            end_time=request.end_time,
            user_groups=user_groups
        )
        return {
            "success": True,
            "content": alerts,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise InternalServerError("Internal server error")

# Need to test
@router.get("/cve_barchart", response_model=CVEBarchartResponse)
async def get_cve_barchart(
    request: CVEBarchartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get the CVE barchart.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/cve_barchart?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "cve_barchart": [
        {"cve_name": "CVE-2024-0001", "count": 10},
        {"cve_name": "CVE-2024-0002", "count": 20}
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
            
        if current_user.user_role == 'admin': 
            cve_barchart = await DashboardController.clean_cve_barchart(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": cve_barchart,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        cve_barchart = await DashboardController.clean_cve_barchart(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": cve_barchart,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting cve barchart: {e}")
        raise InternalServerError("Internal server error")

@router.get("/ttp_linechart", response_model=TTPLineChartResponse)
async def get_ttp_linechart(
    request: TTPLineChartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """ 
    Get TTP linechart.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/ttp_linechart?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "ttp_linechart": [
        {"label": ['TTP-0001', 'TTP-0002],
        "datas": [
        {"name":"TTP-0001", "type": "line", "data":["2024-11-13", 10], ["2024-11-14", 20]},
        {"name":"TTP-0002", "type": "line", "data":["2024-11-13", 10], ["2024-11-14", 20]}
        ]
        },
        }
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            ttp_linechart = await DashboardController.clean_ttp_linechart(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": ttp_linechart,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        ttp_linechart = await DashboardController.clean_ttp_linechart(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": ttp_linechart,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting ttp linechart: {e}")
        raise InternalServerError("Internal server error")

# Need to test
@router.get("/malicious_file_barchart", response_model=MaliciousFileBarchartResponse)
async def get_malicious_file_barchart(
    request: MaliciousFileBarchartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get malicious file barchart.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/malicious_file_barchart?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "malicious_file_barchart": [
         {"malicious_file": "malicious_file1", "count": 10},
         {"malicious_file": "malicious_file2", "count": 20}
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            malicious_file_barchart = await DashboardController.clean_malicious_file_barchart(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": malicious_file_barchart,
                "message": "Success"
            }   
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        malicious_file_barchart = await DashboardController.clean_malicious_file_barchart(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": malicious_file_barchart,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting malicious file barchart: {e}")
        raise InternalServerError("Internal server error")

# Need to test
@router.get("/authentication_piechart", response_model=AuthenticationPiechartResponse)
async def get_authentication_piechart(
    request: AuthenticationPiechartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get authentication piechart.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/authentication_piechart?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "authentication_piechart": [
        {"authentication": "authentication1", "count": 10},
        {"authentication": "authentication2", "count": 20}
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            authentication_piechart = await DashboardController.clean_authentication_piechart(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": authentication_piechart,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        authentication_piechart = await DashboardController.clean_authentication_piechart(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": authentication_piechart,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting authentication piechart: {e}")
        raise InternalServerError("Internal server error")

@router.get("/agent_name", response_model=AgentNamePiechartResponse)
async def get_agent_name(
    request: AgentNamePiechartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get agent name piechart.
    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/dashboard/agent_name?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": {
        "agent_name": [
        {"agent_name": "agent1", "event_count": 10},
        {"agent_name": "agent2", "event_count": 20}
        ]
      },
      "message": "Success"
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            agent_name = await DashboardController.clean_agent_name(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": agent_name,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        agent_name = await DashboardController.clean_agent_name(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": agent_name,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting agent name: {e}")
        raise InternalServerError("Internal server error")

@router.get("/event_table", response_model=EventTableResponse)
async def get_event_table(
    request: EventTableRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Get event table.
    Request:
    curl -X 'GET' \
      'https://flask.avocadolab.ai/api/dashboard/event_table?start_time=2024-01-01T00%3A00%3A00&end_time=2025-01-01T00%3A00%3A00' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'

    Response:
    {
      "total": 0,
      "datas": [
        {
          "id": 0,
          "time": "string",
          "agent_id": "string",
          "rule_description": "string",
          "rule_mitre_tactic": "string",
          "rule_mitre_id": "string",
          "rule_level": 0
        }
      ]
    }
    
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin': 
            event_table = await DashboardController.clean_event_table(
                start_time=request.start_time,
                end_time=request.end_time
            )
            return {
                "success": True,
                "content": event_table,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        event_table = await DashboardController.clean_event_table(
            start_time=request.start_time,
            end_time=request.end_time,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": event_table,
            "message": "Success"
        }
    except UnauthorizedError as e:
        raise UnauthorizedError("Authentication required")
    except PermissionError as e:
        raise PermissionError("Permission denied")  
    except Exception as e:
        logger.error(f"Error getting event table: {e}")
        raise InternalServerError("Internal server error")
