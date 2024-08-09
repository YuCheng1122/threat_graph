from typing import List, Dict, Any
import logging
from functools import wraps
from app.models.wazuh_db import AgentModel, EventModel
from app.models.user_db import UserModel
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent
from app.schemas.wazuh import AgentSummary
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
    async def save_events(events: List[WazuhEvent]) -> int:
        """
        Save multiple events to Elasticsearch and return the count of successfully saved events.
        """
        saved_count = 0
        try:
            for event in events:
                event_model = EventModel(event)
                print(f"Saving event: {event_model.to_dict()}")
                result = EventModel.save_to_elasticsearch(event_model)
                if result:  # Assuming save_to_elasticsearch returns True on success
                    saved_count += 1
                    print(f"Event saved for agent ID: {event.agent_id}. Result: {result}")
                else:
                    print(f"Failed to save event for agent ID: {event.agent_id}")
            print(f"Finished processing all events. Successfully saved {saved_count} events.")
            return saved_count
        except Exception as e:
            print(f"Error in save_events: {str(e)}")
            return saved_count  # Return the number of events saved before the error occurred
        
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

    @staticmethod
    @handle_exceptions
    async def get_agent_summary(user: UserModel) -> List[AgentSummary]:
        """
        Retrieve a summary of agent data from Elasticsearch.
        """
        logging.info(f"Fetching agent summary for user={user.username}")
        try:
            if user.user_role == 'admin':
                agents = await AgentModel.load_all_agents()
            else:
                user_groups = UserModel.get_user_groups(user.username)
                group_names = [group['group_name'] for group in user_groups]
                agents = await AgentModel.load_agents_by_groups(group_names)

            logging.info(f"Retrieved {len(agents)} agents")

            total_agents = len(agents)
            active_agents = 0
            windows_agents = 0
            active_windows_agents = 0
            linux_agents = 0
            active_linux_agents = 0
            macos_agents = 0
            active_macos_agents = 0

            for agent in agents:
                logging.debug(f"Processing agent: {agent}")
                is_active = agent['agent_status'].lower() == 'active'
                os_type = AgentController.determine_os(agent['os'])

                if is_active:
                    active_agents += 1

                if os_type == 'windows':
                    windows_agents += 1
                    if is_active:
                        active_windows_agents += 1
                elif os_type == 'linux':
                    linux_agents += 1
                    if is_active:
                        active_linux_agents += 1
                elif os_type == 'macos':
                    macos_agents += 1
                    if is_active:
                        active_macos_agents += 1

            summary = [
                AgentSummary(id=1, agent_name="Active agents", data=active_agents),
                AgentSummary(id=2, agent_name="Total agents", data=total_agents),
                AgentSummary(id=3, agent_name="Active Windows agents", data=active_windows_agents),
                AgentSummary(id=4, agent_name="Windows agents", data=windows_agents),
                AgentSummary(id=5, agent_name="Active Linux agents", data=active_linux_agents),
                AgentSummary(id=6, agent_name="Linux agents", data=linux_agents),
                AgentSummary(id=7, agent_name="Active MacOS agents", data=active_macos_agents),
                AgentSummary(id=8, agent_name="MacOS agents", data=macos_agents),
            ]

            logging.info(f"Agent summary: {summary}")
            return summary
        except Exception as e:
            logging.error(f"Error in get_agent_summary: {str(e)}")
            raise