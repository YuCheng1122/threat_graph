from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.schemas.wazuh import (
    AgentInfoRequest, AgentInfoResponse, 
    GetAgentInfoByTimeResponse, GetAgentInfoByGroupResponse, 
    GetAgentInfoByGroupRequest
)
from app.controllers.wazuh import AgentController
from app.controllers.auth import AuthController
from app.models.user import UserModel
from app.ext.error import UnauthorizedError, ElasticsearchError, NotFoundUserError
from datetime import datetime

router = APIRouter()

@router.post("/info", response_model=AgentInfoResponse)
async def post_agent_info(agent_info: AgentInfoRequest, current_user: UserModel = Depends(AuthController.get_current_user)):
    try:
        await AgentController.save_agent_info(agent_info.agent, current_user.username)
        await AgentController.save_events(agent_info.events, agent_info.agent.agent_id, current_user.username)
        return AgentInfoResponse(message="Agent info and events saved successfully", agent_id=agent_info.agent.agent_id)
    except UnauthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ElasticsearchError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    except RequestValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": e.errors()}
        )

@router.get("/info/by-time", response_model=GetAgentInfoByTimeResponse)
async def get_agent_info_by_time(
    agent_id: str = Query(..., example="001"),
    start_time: datetime = Query(..., example="2023-07-30T00:00:00Z"),
    end_time: datetime = Query(..., example="2023-07-31T00:00:00Z"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    try:
        agent_data = await AgentController.get_agent_info(agent_id, current_user.username)
        events = await AgentController.get_agent_events(agent_id, start_time, end_time, current_user.username)
        return GetAgentInfoByTimeResponse(agent_info=agent_data, events=events)
    except UnauthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except NotFoundUserError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ElasticsearchError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/info/by-group", response_model=GetAgentInfoByGroupResponse,
            responses={
                200: {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "example": GetAgentInfoByGroupResponse.Config.schema_extra["example"]
                        }
                    }
                }
            })
async def get_agent_info_by_group(
    request: GetAgentInfoByGroupRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    try:
        result = await AgentController.get_group_agents_and_events(current_user.username, request.start_time, request.end_time)
        return GetAgentInfoByGroupResponse(**result)
    except UnauthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ElasticsearchError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))