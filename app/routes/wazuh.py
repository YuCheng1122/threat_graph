from fastapi import APIRouter, Depends, Query
from app.schemas.wazuh import (
    AgentInfoRequest, AgentInfoResponse, AgentSummaryResponse,AgentMessagesResponse, AgentMessagesRequest, 
    LineChartRequest, LineChartResponse, TotalEventAPIResponse, TotalEventRequest, TotalEventResponse,
    PieChartAPIResponse, PieChartRequest, AgentInfoResponseContent
)
from app.controllers.wazuh import AgentController
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.ext.error import UnauthorizedError, ElasticsearchError, PermissionError, InternalServerError
from datetime import datetime
from typing import Dict
from dateutil.tz import tzutc
from logging import getLogger

# Get the centralized logger
logger = getLogger('app_logger')

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
        events_saved: Dict[str, int] = {}

        for agent in agent_info.agent:
            await AgentController.save_agent_info(agent)
            agent_ids.append(agent.agent_id)
        
        for agent_id in agent_ids:
            agent_events = [event for event in agent_info.events if event.agent_id == agent_id]
            event_count = await AgentController.save_events(agent_events)
            events_saved[agent_id] = event_count

        response_content = AgentInfoResponseContent(
            message="Agents info and events saved successfully",
            agent_ids=agent_ids,
            events_saved=events_saved
        )

        return AgentInfoResponse(success=True, content=response_content)
    
    except (UnauthorizedError, PermissionError):
        raise
    except Exception as e:
        logger.error(f"Error in get_agent_info endpoint: {e}")
        raise InternalServerError()
          
@router.get("/agents/summary", response_model=AgentSummaryResponse)
async def get_agent_summary(
    start_time: datetime = Query(..., description="Start time for the summary period"),
    end_time: datetime = Query(..., description="End time for the summary period"),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get a summary of agent information within a specified time range.
    """
    try:
        summary = await AgentController.get_agent_summary(user=current_user, start_time=start_time, end_time=end_time)
        return AgentSummaryResponse(agents=summary)
    except Exception as e:
        logger.error(f"Error in get_agent_summary endpoint: {e}")
        raise InternalServerError()

@router.get("/messages", response_model=AgentMessagesResponse)
async def get_agent_messages(
    request: AgentMessagesRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get recent high-level messages (rule_level > 8) for all agents the user has access to.
    """
    try:
        messages = await AgentController.get_messages(
            user=current_user, 
            start_time=request.start_time, 
            end_time=request.end_time, 
            limit=request.limit
        )
        return messages
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except ElasticsearchError as e:
        logger.error(f"Elasticsearch error: {e}")
        raise ElasticsearchError("Database error")
    except Exception as e:
        logger.error(f"Error in get_agent_messages endpoint: {e}")
        raise InternalServerError()
    
@router.get("/line-chart", response_model=LineChartResponse)
async def get_line_chart_data(
    request: LineChartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get line chart data for top rule descriptions over the specified time range.
    """
    try:
        start_time_utc = request.start_time.replace(tzinfo=tzutc())
        end_time_utc = request.end_time.replace(tzinfo=tzutc())
        
        chart_data = await AgentController.get_line_chart_data(start_time_utc, end_time_utc)
        return chart_data
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except ElasticsearchError as e:
        logger.error(f"Elasticsearch error: {e}")
        raise ElasticsearchError("Database error")
    except Exception as e:
        logger.error(f"Error in get_agent_line-chart endpoint: {e}")
        raise InternalServerError()

@router.get("/total-event", response_model=TotalEventAPIResponse)
async def get_total_event(
    request: TotalEventRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get the total count of events (levels 8-14) within a specified time range.
    """
    try:
        count = await AgentController.get_total_event_count(request.start_time, request.end_time)
        return TotalEventAPIResponse(success=True, content=TotalEventResponse(count=count))
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except ElasticsearchError as e:
        logger.error(f"Elasticsearch error: {e}")
        raise ElasticsearchError("Database error")
    except Exception as e:
        logger.error(f"Error in get_agent_line-chart endpoint: {e}")
        raise InternalServerError()

@router.get("/pie-chart", response_model=PieChartAPIResponse)
async def get_pie_chart_data(
    request: PieChartRequest = Depends(),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get pie chart data including Top 5 agents, Top MITRE ATT&CKs, Top 5 Events, and Top 5 Event Counts by Agent Name.
    """
    try:
        pie_chart_data = await AgentController.get_pie_chart_data(request.start_time, request.end_time)
        return PieChartAPIResponse(success=True, content=pie_chart_data)
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("Permission denied")
    except ElasticsearchError as e:
        logger.error(f"Elasticsearch error: {e}")
        raise ElasticsearchError("Database error")
    except Exception as e:
        logger.error(f"Error in get_agent_line-chart endpoint: {e}")
        raise InternalServerError()
