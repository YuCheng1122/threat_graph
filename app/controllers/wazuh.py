from typing import List, Dict, Any
import logging
from functools import wraps
from app.models.wazuh_db import AgentModel, EventModel
from app.models.user_db import UserModel
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent
from app.ext.error import ElasticsearchError, UnauthorizedError, PermissionError, HTTPError, UserNotFoundError
from datetime import datetime
import traceback

def handle_exceptions(func):
    """
    Decorator to handle common exceptions in controller methods.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except UserNotFoundError as e:
            logging.error(f"User not found in {func.__name__}: {str(e)}")
            raise HTTPError(status_code=404, detail="User not found")
        except (UnauthorizedError, PermissionError) as e:
            logging.error(f"Access denied in {func.__name__}: {str(e)}")
            raise HTTPError(status_code=403, detail="Access denied")
        except ElasticsearchError as e:
            logging.error(f"Elasticsearch error in {func.__name__}: {str(e)}")
            raise HTTPError(status_code=500, detail="Database error")
        except Exception as e:
            logging.error(f"Unexpected error in {func.__name__}: {str(e)}")
            logging.error(traceback.format_exc())
            raise HTTPError(status_code=500, detail="Internal server error")
    return wrapper

class AgentController:
    
    @staticmethod
    async def check_user_permission(user: UserModel, group_name: str) -> None:
        """
        Check if a user has permission to access a specific group, we will check db table to verify user's permission.
        """
        logging.info(f"Checking permission for user {user.username} (id: {user.id}, role: {user.user_role}) for group {group_name}")
        if user.disabled:
            logging.warning(f"User {user.username} is disabled")
            raise PermissionError("User account is disabled")
        if user.user_role == 'admin':
            logging.info(f"User {user.username} is admin, granting permission")
            return
        has_permission = UserModel.check_user_group(user.id, group_name)
        if not has_permission:
            logging.warning(f"Permission denied for user {user.username} for group {group_name}")
            raise PermissionError("Permission denied")
        logging.info(f"Permission granted for user {user.username} for group {group_name}")

    @staticmethod
    async def save_agent_info(agent: AgentSchema) -> None:
        """
        Save agent information to Elasticsearch.
        """
        try:
            agent_model = AgentModel(agent)
            print(f"Saving agent info: {agent_model.to_dict()}")
            result = AgentModel.save_to_elasticsearch(agent_model)
            print(f"Agent info saved for agent ID: {agent.agent_id}. Result: {result}")
        except Exception as e:
            print(f"Error in save_agent_info: {str(e)}")
            raise

    @staticmethod
    async def save_events(events: List[WazuhEvent]) -> None:
        """
        Save multiple events to Elasticsearch.
        """
        try:
            for event in events:
                event_model = EventModel(event)
                print(f"Saving event: {event_model.to_dict()}")
                result = EventModel.save_to_elasticsearch(event_model)
                print(f"Event saved for agent ID: {event.agent_id}. Result: {result}")
            print("Finished processing all events.")
        except Exception as e:
            print(f"Error in save_events: {str(e)}")
            raise
        
    @staticmethod
    @handle_exceptions
    async def get_agent_events(agent_id: str, start_time: datetime, end_time: datetime, user: UserModel) -> List[Dict]:
        """
        Retrieve agent events for a specific time range.
        """
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
        """
        Retrieve agents and events for a user's groups within a specific time range.
        """
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
