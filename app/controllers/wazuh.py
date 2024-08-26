from typing import List, Dict, Any
import logging
import json
from collections import defaultdict, Counter
from functools import wraps
from app.models.wazuh_db import AgentModel, EventModel
from app.models.user_db import UserModel
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent, PieChartData, PieChartItem
from app.schemas.wazuh import AgentSummary, AgentMessagesResponse, AgentMessage, LineChartResponse, LineData
from app.ext.error import ElasticsearchError, UnauthorizedError, PermissionError, HTTPError, UserNotFoundError
from datetime import datetime
import traceback
from dateutil.parser import parse
from dateutil.tz import tzutc

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
    @handle_exceptions
    async def save_agent_info(agent: AgentSchema) -> None:
        """
        Save agent information to Elasticsearch.
        """
        agent_model = AgentModel(agent)
        logging.info(f"Saving agent info: {agent_model.to_dict()}")
        result = AgentModel.save_to_elasticsearch(agent_model)
        logging.info(f"Agent info saved for agent ID: {agent.agent_id}. Result: {result}")

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

        # error type : write own defined error handler, such as what kind of db error,
        


        except Exception as e:
            logging.error(f"Error in get_group_agents_and_events: {str(e)}")
            logging.error(traceback.format_exc())
            raise

    @staticmethod
    def determine_os(os_name: str) -> str:
        os_name = os_name.lower()
        if any(keyword in os_name for keyword in ['windows', 'microsoft']):
            return 'windows'
        elif any(keyword in os_name for keyword in ['linux', 'ubuntu', 'centos', 'redhat', 'debian']):
            return 'linux'
        elif any(keyword in os_name for keyword in ['mac', 'darwin']):
            return 'macos'
        else:
            return 'other'

    @staticmethod
    @handle_exceptions
    async def get_agent_summary(user: UserModel, start_time: datetime, end_time: datetime) -> List[AgentSummary]:
        logging.info(f"Fetching agent summary for user_id={user.id} from {start_time} to {end_time}")
        
        if user.user_role == 'admin':
            group_names = None  # Admin can see all groups
        else:
            group_names = UserModel.get_user_groups(user.id)  # Remove await here
            logging.info(f"User groups: {group_names}")
            if not group_names:
                logging.warning(f"No groups found for user {user.id}")
                return []

        agents = await AgentModel.load_agents(start_time, end_time, group_names)

        logging.info(f"Retrieved {len(agents)} agents")
        summary = AgentController.calculate_agent_summary(agents)
        logging.info(f"Agent summary: {json.dumps([s.dict() for s in summary], indent=2)}")
        return summary

    @staticmethod
    def calculate_agent_summary(agents: List[Dict]) -> List[AgentSummary]:
        total_agents = len(agents)
        active_agents = 0
        windows_agents = 0
        active_windows_agents = 0
        linux_agents = 0
        active_linux_agents = 0
        macos_agents = 0
        active_macos_agents = 0

        logging.info(f"Processing {total_agents} agents")

        for idx, agent in enumerate(agents, 1):
            logging.debug(f"Processing agent {idx}/{total_agents}: {json.dumps(agent, indent=2)}")
            
            is_active = agent.get('agent_status', '').lower() == 'active'
            os_type = AgentController.determine_os(agent.get('os', ''))
            
            logging.debug(f"Agent {idx} - Is Active: {is_active}, OS Type: {os_type}")

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
            else:
                logging.warning(f"Unknown OS type for agent {idx}: {os_type}")

        logging.info(f"Summary - Total: {total_agents}, Active: {active_agents}")
        logging.info(f"Windows - Total: {windows_agents}, Active: {active_windows_agents}")
        logging.info(f"Linux - Total: {linux_agents}, Active: {active_linux_agents}")
        logging.info(f"MacOS - Total: {macos_agents}, Active: {active_macos_agents}")

        return [
            AgentSummary(id=1, agent_name="Active agents", data=active_agents),
            AgentSummary(id=2, agent_name="Total agents", data=total_agents),
            AgentSummary(id=3, agent_name="Active Windows agents", data=active_windows_agents),
            AgentSummary(id=4, agent_name="Windows agents", data=windows_agents),
            AgentSummary(id=5, agent_name="Active Linux agents", data=active_linux_agents),
            AgentSummary(id=6, agent_name="Linux agents", data=linux_agents),
            AgentSummary(id=7, agent_name="Active MacOS agents", data=active_macos_agents),
            AgentSummary(id=8, agent_name="MacOS agents", data=macos_agents),
        ]
    
    # -------------------------------------------------------------------------------- Event logic 

    @staticmethod
    @handle_exceptions
    async def get_messages(user: UserModel, start_time: datetime, end_time: datetime, limit: int = 20) -> AgentMessagesResponse:
        """
        Retrieve high-level messages (rule_level > 8) for all agents the user has access to within the specified time range.
        """
        logging.info(f"Fetching high-level messages for user={user.username}, start_time={start_time}, end_time={end_time}, limit={limit}")
        
        # Check user permissions
        if user.user_role != 'admin':
            group_names = UserModel.get_user_groups(user.id)
            if not group_names:
                logging.warning(f"No groups found for user {user.id}")
                return AgentMessagesResponse(total=0, datas=[])
        else:
            group_names = None  # Admin can see all groups

        messages, total_count = await EventModel.load_messages(start_time, end_time, group_names, limit)
        
        # Convert to AgentMessage schema
        agent_messages = []
        for i, msg in enumerate(messages, start=1):
            try:
                agent_message = AgentMessage(
                    id=i,
                    time=datetime.fromisoformat(msg.get('timestamp', '')).strftime('%b %d, %Y @ %H:%M:%S.%f')[:-3],
                    agent_id=msg.get('agent_id', ''),
                    rule_description=msg.get('rule_description', ''),
                    rule_mitre_tactic=msg.get('rule_mitre_tactic'),
                    rule_mitre_id=msg.get('rule_mitre_id'),
                    rule_level=msg.get('rule_level', 0)
                )
                agent_messages.append(agent_message)
            except Exception as e:
                logging.error(f"Error processing message: {e}")
                continue
        
        logging.info(f"Retrieved {len(agent_messages)} high-level messages out of {total_count} total")
        
        return AgentMessagesResponse(total=total_count, datas=agent_messages)
    
    @staticmethod
    async def get_line_chart_data(start_time: datetime, end_time: datetime) -> LineChartResponse:
        start_time = start_time.replace(tzinfo=tzutc())
        end_time = end_time.replace(tzinfo=tzutc())
        
        events = await EventModel.get_events_in_timerange(start_time, end_time)
        
        rule_counts = defaultdict(lambda: defaultdict(int))
        time_range = end_time - start_time
        interval = time_range / 4
        
        for event in events:
            event_data = event['_source']
            rule_description = event_data.get('rule_description', 'Unknown')
            event_time = parse(event_data['timestamp']).replace(tzinfo=tzutc())
            
            interval_index = min(4, int((event_time - start_time) / interval))
            interval_start = start_time + interval * interval_index
            
            rule_counts[rule_description][interval_start] += 1
        
        top_rules = sorted(rule_counts.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]
        
        line_datas = []
        for rule, counts in top_rules:
            data_points = [
                (start_time + interval * i, counts.get(start_time + interval * i, 0))
                for i in range(5)
            ]
            line_data = LineData(name=rule, data=data_points)
            line_datas.append(line_data)
        
        return LineChartResponse(label=[data.name for data in line_datas], datas=line_datas)
    
    @staticmethod
    async def get_total_event_count(start_time: datetime, end_time: datetime) -> str:
        count = await EventModel.get_high_level_event_count(start_time, end_time)
        return f"{count:,}" 
    
    @staticmethod
    async def get_pie_chart_data(start_time: datetime, end_time: datetime) -> PieChartData:
        events = await EventModel.get_events_for_pie_chart(start_time, end_time)
        
        agents_counter = Counter()
        mitre_counter = Counter()
        events_counter = Counter()
        agent_event_counter = Counter()

        for event in events:
            event_data = event['_source']
            agent_id = event_data.get('agent_id', '')
            rule_description = event_data.get('rule_description', '')
            mitre_technique = event_data.get('rule_mitre_technique', '')

            if agent_id:
                agents_counter[agent_id] += 1
            if mitre_technique:
                mitre_counter[mitre_technique] += 1
            if rule_description:
                events_counter[rule_description] += 1
        # Identify the top 5 events based on rule_description count
        top_5_events = events_counter.most_common(5)

        # Find the agent IDs associated with these top 5 events
        for event in events:
            event_data = event['_source']
            agent_id = event_data.get('agent_id', '')
            rule_description = event_data.get('rule_description', '')

            if rule_description in dict(top_5_events) and agent_id:
                agent_event_counter[agent_id] += 1

        def get_top_5(counter):
            items = []
            for name, count in counter.most_common():
                if name and name.lower() != 'unknown' and len(items) < 5:
                    items.append(PieChartItem(value=count, name=name))
            return items

        return PieChartData(
            top_agents=get_top_5(agents_counter),
            top_mitre=get_top_5(mitre_counter),
            top_events=get_top_5(events_counter),
            top_event_counts=get_top_5(agent_event_counter)
        )
        
    @staticmethod
    @handle_exceptions
    async def save_events(events: List[WazuhEvent]) -> int:
        """
        Save multiple events to Elasticsearch and return the count of successfully saved events.
        """
        saved_count = 0
        for event in events:
            event_model = EventModel(event)
            logging.info(f"Saving event: {event_model.to_dict()}")
            result = EventModel.save_to_elasticsearch(event_model)
            if result:  # Assuming save_to_elasticsearch returns True on success
                saved_count += 1
                logging.info(f"Event saved for agent ID: {event.agent_id}. Result: {result}")
            else:
                logging.warning(f"Failed to save event for agent ID: {event.agent_id}")
        logging.info(f"Finished processing all events. Successfully saved {saved_count} events.")
        return saved_count
        