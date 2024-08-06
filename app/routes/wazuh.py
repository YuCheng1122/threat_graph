import traceback
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from fastapi.exceptions import RequestValidationError
from app.schemas.wazuh import (
    AgentInfoRequest, AgentInfoResponse, 
    GetAgentInfoByTimeResponse, GetAgentInfoByGroupResponse, 
    GetAgentInfoByGroupRequest
)
from app.controllers.wazuh import AgentController
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.ext.error import UnauthorizedError, ElasticsearchError, PermissionError
from datetime import datetime
import logging

router = APIRouter()

@router.post("/info", response_model=AgentInfoResponse)
async def post_agent_info(
    agent_info: AgentInfoRequest,
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to post agent information and events.
    """
    
    try:
        agent_ids = []
        for agent in agent_info.agent:
            await AgentController.save_agent_info(agent)
            agent_ids.append(agent.agent_id)
        
        await AgentController.save_events(agent_info.events)
        
        return AgentInfoResponse(message="Agents info and events saved successfully", agent_ids=agent_ids)
    
    except (UnauthorizedError, PermissionError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
    except ElasticsearchError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    except RequestValidationError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid request")
    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.get("/info/by-time", response_model=GetAgentInfoByTimeResponse)
async def get_agent_info_by_time(
    request: Request,
    agent_id: str = Query(..., example="001"),
    start_time: datetime = Query(..., example="2023-07-30T00:00:00Z"),
    end_time: datetime = Query(..., example="2023-07-31T00:00:00Z"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get agent information and events for a specific time range.
    """
    try:
        agent_data = await AgentController.get_agent_info(agent_id, user=current_user)
        events = await AgentController.get_agent_events(agent_id, start_time, end_time, user=current_user)
        return GetAgentInfoByTimeResponse(agent_info=agent_data, events=events)
    except (UnauthorizedError, PermissionError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
    except NotFoundUserError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    except ElasticsearchError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    except Exception as e:
        logging.error(f"Unexpected error in get_agent_info_by_time: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@router.get("/info/by-group", response_model=GetAgentInfoByGroupResponse)
async def get_agent_info_by_group(
    get_request: GetAgentInfoByGroupRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get agent information and events for a group within a specific time range.
    """
    try:
        result = await AgentController.get_group_agents_and_events(user=current_user, start_time=get_request.start_time, end_time=get_request.end_time)
        return GetAgentInfoByGroupResponse(**result)
    except (UnauthorizedError, PermissionError):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
    except ElasticsearchError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    except Exception as e:
            logging.error(f"Unexpected error in get_agent_info_by_group: {str(e)}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")