from fastapi import APIRouter, Depends, Query
from datetime import datetime
from app.schemas.agent_schema import (AgentInfoResponse,
    AgentAlertsResponse, AgentTacticLinechartResponse, AgentCVEBarchartResponse,
    AgentMaliciousFileResponse, AgentAuthenticationResponse, AgentEventTableResponse
)
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.ext.error import UnauthorizedError, PermissionError, InternalServerError
from app.controllers.agent_detail_controller import AgentDetailController as ADController
from app.controllers.wazuh import AgentController
from logging import getLogger


logger = getLogger('app_logger')

router = APIRouter()

@router.get("/agent-info", response_model=AgentInfoResponse)
async def get_agent_info(
    agent_name: str,
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get the agent info.

    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/agent_detail/agent-info?agent_name=agent_name' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'
    Response:
    {
      "success": true,
      "content": [
        {
          "agent_id": "string",
          "agent_name": "string",
          "ip": "string",
          "os": "string",
          "os_version": "string",
          "agent_status": "string",
          "last_keep_alive": "2023-07-30T12:00:00Z",
          "registration_time": "2023-07-30T12:00:00Z"
        }
      ]
    }
    """
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            agent_details = await ADController.get_agent_info(agent_name)
            return AgentInfoResponse(success=True, message="Agent info retrieved successfully", content=agent_details)
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        agent_details = await ADController.get_agent_info(agent_name)
        return AgentInfoResponse(success=True, message="Agent info retrieved successfully", content=agent_details)
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error in get_agent_info endpoint: {e}")
        raise InternalServerError()

@router.get("/alerts", response_model=AgentAlertsResponse)
async def get_agent_alerts(
    agent_name: str = Query(..., description="Agent name to filter alerts"),
    start_time: datetime = Query(..., description="Start time for the alerts query"),
    end_time: datetime = Query(..., description="End time for the alerts query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get alerts for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            alerts = await ADController.clean_alerts(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
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
        alerts = await ADController.clean_alerts(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            user_groups=user_groups
        )
        return {
            "success": True,
            "content": alerts,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent alerts: {e}")
        raise InternalServerError()

@router.get("/tactic_linechart", response_model=AgentTacticLinechartResponse)
async def get_agent_tactic_linechart(
    agent_name: str = Query(..., description="Agent name to filter tactic data"),
    start_time: datetime = Query(..., description="Start time for the tactic linechart query"),
    end_time: datetime = Query(..., description="End time for the tactic linechart query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get tactic linechart for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            tactic_data = await ADController.clean_tactic_linechart(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
            )
            return {
                "success": True,
                "content": tactic_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        tactic_data = await ADController.clean_tactic_linechart(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": tactic_data,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent tactic linechart: {e}")
        raise InternalServerError()

@router.get("/cve_barchart", response_model=AgentCVEBarchartResponse)
async def get_agent_cve_barchart(
    agent_name: str = Query(..., description="Agent name to filter CVE data"),
    start_time: datetime = Query(..., description="Start time for the CVE barchart query"),
    end_time: datetime = Query(..., description="End time for the CVE barchart query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get CVE barchart for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            cve_data = await ADController.clean_cve_barchart(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
            )
            return {
                "success": True,
                "content": cve_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        cve_data = await ADController.clean_cve_barchart(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": cve_data,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent CVE barchart: {e}")
        raise InternalServerError()

@router.get("/malicious_file_barchart", response_model=AgentMaliciousFileResponse)
async def get_agent_malicious_file_barchart(
    agent_name: str = Query(..., description="Agent name to filter malicious file data"),
    start_time: datetime = Query(..., description="Start time for the malicious file barchart query"),
    end_time: datetime = Query(..., description="End time for the malicious file barchart query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get malicious file barchart for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            malicious_file_data = await ADController.clean_malicious_file_barchart(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
            )
            return {
                "success": True,
                "content": malicious_file_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        malicious_file_data = await ADController.clean_malicious_file_barchart(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": malicious_file_data,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent malicious file barchart: {e}")
        raise InternalServerError()

@router.get("/authentication_piechart", response_model=AgentAuthenticationResponse)
async def get_agent_authentication_piechart(
    agent_name: str = Query(..., description="Agent name to filter authentication data"),
    start_time: datetime = Query(..., description="Start time for the authentication piechart query"),
    end_time: datetime = Query(..., description="End time for the authentication piechart query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get authentication piechart for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            authentication_data = await ADController.clean_authentication_piechart(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
            )
            return {
                "success": True,
                "content": authentication_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        authentication_data = await ADController.clean_authentication_piechart(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": authentication_data,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent authentication piechart: {e}")
        raise InternalServerError()

@router.get("/event_table", response_model=AgentEventTableResponse)
async def get_agent_event_table(
    agent_name: str = Query(..., description="Agent name to filter events"),
    start_time: datetime = Query(..., description="Start time for the event table query"),
    end_time: datetime = Query(..., description="End time for the event table query"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """Get event table for a specific agent"""
    try:
        if current_user.disabled:
            raise PermissionError("User account is disabled")
        if current_user.user_role == 'admin':
            event_data = await ADController.clean_event_table(
                start_time=start_time,
                end_time=end_time,
                agent_name=agent_name
            )
            return {
                "success": True,
                "content": event_data,
                "message": "Success"
            }
        user_groups = UserModel.get_user_groups(current_user.id)
        permission_error = await AgentController.check_user_permission(current_user, user_groups)
        if permission_error:
            raise PermissionError("Permission denied")
        event_data = await ADController.clean_event_table(
            start_time=start_time,
            end_time=end_time,
            agent_name=agent_name,
            group_name=user_groups
        )
        return {
            "success": True,
            "content": event_data,
            "message": "Success"
        }
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except Exception as e:
        logger.error(f"Error getting agent event table: {e}")
        raise InternalServerError()
