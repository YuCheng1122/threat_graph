from typing import List, Dict
import logging
from functools import wraps
from app.models.wazuh_db import AgentModel, EventModel
from app.models.user_db import UserModel
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent
from app.ext.error import ElasticsearchError, NotFoundUserError, UnauthorizedError, PermissionError
from datetime import datetime
from fastapi import Depends, HTTPException, status

import traceback

def handle_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except (NotFoundUserError, UnauthorizedError, PermissionError):
            logging.error(f"Access denied in {func.__name__}")
            raise HTTPException(status_code=403, detail="Access denied")
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            logging.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail="Internal server error")
    return wrapper

class AgentController:
    
    @staticmethod
    async def check_user_permission(user: UserModel, group_name: str):
        logging.info(f"Checking permission for user {user.username} (id: {user.id}, role: {user.user_role}) for group {group_name}")
        if user.disabled:
            logging.warning(f"User {user.username} is disabled")
            raise PermissionError("User account is disabled", 403)
        if user.user_role == 'admin':
            logging.info(f"User {user.username} is admin, granting permission")
            return
        has_permission = UserModel.check_user_group(user.id, group_name)
        if not has_permission:
            logging.warning(f"Permission denied for user {user.username} for group {group_name}")
            raise PermissionError("Permission denied", 403)
        logging.info(f"Permission granted for user {user.username} for group {group_name}")
        
    @staticmethod
    @handle_exceptions
    async def save_agent_info(agent: AgentSchema, user: UserModel):
        AgentController.check_user_permission(user, agent.group_name)
        agent_model = AgentModel(agent)
        await AgentModel.save_to_elasticsearch(agent_model)

    @staticmethod
    @handle_exceptions
    async def save_events(events: List[WazuhEvent], agent_id: str, user: UserModel):
        try:
            agent = await AgentModel.load_from_elasticsearch(agent_id)
            if agent is None:
                logging.error(f"Agent with ID {agent_id} not found when trying to save events")
                raise HTTPException(status_code=404, detail=f"Agent with ID {agent_id} not found")
            
            if user.user_role != 'admin':
                await AgentController.check_user_permission(user, agent['group_name'])
            
            for event in events:
                event_model = EventModel(event)
                event_model.agent_id = agent_id
                await EventModel.save_to_elasticsearch(event_model)
        except Exception as e:
            logging.error(f"Error in save_events: {str(e)}")
            logging.error(traceback.format_exc())
            raise
            
    @staticmethod
    @handle_exceptions
    async def get_agent_info(agent_id: str, user: UserModel) -> Dict:
        logging.info(f"Fetching agent info for agent_id={agent_id}")
        agent_data = await AgentModel.load_from_elasticsearch(agent_id)
        if user.user_role != 'admin':
            await AgentController.check_user_permission(user, agent_data['group_name'])
        logging.info(f"Agent data fetched: {agent_data}")
        return agent_data

    @staticmethod
    @handle_exceptions
    async def get_agent_events(agent_id: str, start_time: datetime, end_time: datetime, user: UserModel) -> List[Dict]:
        logging.info(f"Fetching agent events for agent_id={agent_id} from {start_time} to {end_time}")
        agent = await AgentModel.load_from_elasticsearch(agent_id)
        if user.user_role != 'admin':
            await AgentController.check_user_permission(user, agent['group_name'])
        events = await EventModel.load_from_elasticsearch_with_time_range(agent_id, start_time, end_time)
        logging.info(f"Events data fetched: {events}")
        return events

    @staticmethod
    @handle_exceptions
    async def get_group_agents_and_events(user: UserModel, start_time: datetime, end_time: datetime) -> Dict[str, List[Dict]]:
        logging.info(f"Fetching group agents and events for user={user.username} from {start_time} to {end_time}")
        try:
            if user.user_role == 'admin':
                logging.info("User is admin, loading all agents and events")
                agents = await AgentModel.load_all_agents()
                events = await EventModel.load_all_events_from_elasticsearch(start_time, end_time)
            else:
                logging.info(f"User is not admin, loading agents and events for user groups")
                user_groups = UserModel.get_user_groups(user.username)
                logging.info(f"User groups: {user_groups}")
                group_names = [group['group_name'] for group in user_groups]
                agents = await AgentModel.load_agents_by_groups(group_names)
                events = await EventModel.load_group_events_from_elasticsearch(group_names, start_time, end_time)
                        
            logging.info(f"Retrieved {len(agents)} agents and {len(events)} events")
            return {"agents": agents, "events": events}
        except Exception as e:
            logging.error(f"Error in get_group_agents_and_events: {str(e)}")
            logging.error(traceback.format_exc())
            raise
