from typing import List, Dict
import logging
from functools import wraps
from app.models.wazuh_db import AgentModel, EventModel
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent
from app.ext.error import ElasticsearchError, NotFoundUserError, UnauthorizedError
from datetime import datetime

def handle_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except NotFoundUserError as e:
            logging.error(f"User not found: {str(e)}")
            raise
        except UnauthorizedError as e:
            logging.error(f"Unauthorized access: {str(e)}")
            raise
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            raise ElasticsearchError(f"Error in {func.__name__}: {str(e)}")
    return wrapper

class AgentController:
    @staticmethod
    @handle_exceptions
    async def save_agent_info(agent: AgentSchema, username: str):
        agent_model = AgentModel(agent, username)
        await AgentModel.save_to_elasticsearch(agent_model)

    @staticmethod
    @handle_exceptions
    async def save_events(events: List[WazuhEvent], agent_id: str, username: str):
        for event in events:
            event_model = EventModel(event, username)
            event_model.agent_id = agent_id
            await EventModel.save_to_elasticsearch(event_model)

    @staticmethod
    @handle_exceptions
    async def get_agent_info(agent_id: str, username: str) -> Dict:
        agent_data = await AgentModel.load_from_elasticsearch(agent_id)
        if agent_data['groups'] != username:
            raise UnauthorizedError(f"User {username} is not authorized to access this agent data")
        return agent_data

    @staticmethod
    @handle_exceptions
    async def get_agent_events(agent_id: str, start_time: datetime, end_time: datetime, username: str) -> List[Dict]:
        return await EventModel.load_from_elasticsearch_with_time_range(agent_id, start_time, end_time, username)

    @staticmethod
    @handle_exceptions
    async def get_group_agents_and_events(username: str, start_time: datetime, end_time: datetime) -> Dict[str, List[Dict]]:
        agents = await AgentModel.load_agents_by_group(username)
        events = await EventModel.load_group_events_from_elasticsearch(username, start_time, end_time)
        return {"agents": agents, "events": events}