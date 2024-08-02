from datetime import datetime
from typing import Optional, List, Dict
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
import os
from dotenv import load_dotenv, find_dotenv
import logging
from functools import wraps

from ..schemas.wazuh import Agent as AgentSchema, WazuhEvent
from ..ext.error import ElasticsearchError, NotFoundUserError

# Set up logging
logging.basicConfig(level=logging.DEBUG, filename='app_errors.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
try:
    load_dotenv(find_dotenv())
except Exception as e:
    logging.error(f"Error loading .env file: {str(e)}")
    raise

# Create a single Elasticsearch instance
es = Elasticsearch(
    [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
    http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
)

def get_index_name():
    return f"{datetime.now().strftime('%Y_%m')}_agents_data"

def handle_es_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except NotFoundError as e:
            raise NotFoundUserError(str(e), 404)
        except Exception as e:
            logging.error(f"Elasticsearch error in {func.__name__}: {str(e)}")
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)
    return wrapper

class AgentModel:
    def __init__(self, agent: AgentSchema):
        self.agent_name = agent.agent_name
        self.agent_id = agent.agent_id
        self.ip = agent.ip
        self.agent_status = agent.agent_status
        self.status_code = agent.status_code
        self.last_keep_alive = agent.last_keep_alive
        self.group_name = agent.group_name
        self.os = agent.os
        self.os_version = agent.os_version
        self.wazuh_data_type = "agent_info"


    def to_dict(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "ip": self.ip,
            "agent_status": self.agent_status,
            "status_code": self.status_code,
            "last_keep_alive": self.last_keep_alive.isoformat() if self.last_keep_alive else None,
            "os": self.os,
            "os_version": self.os_version,
            "group_name": self.group_name, 
            "wazuh_data_type": self.wazuh_data_type
        }


    @staticmethod
    @handle_es_exceptions
    async def save_to_elasticsearch(agent: 'AgentModel'):
        es.index(index=get_index_name(), id=agent.agent_id, body=agent.to_dict())


    @staticmethod
    @handle_es_exceptions
    async def load_from_elasticsearch(agent_id: str) -> Optional[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent_id": agent_id}},
                        {"term": {"wazuh_data_type": "agent_info"}}
                    ]
                }
            }
        }
        response = es.search(index=get_index_name(), body=query)
        hits = response['hits']['hits']
        return hits[0]['_source'] if hits else None

    @staticmethod
    @handle_es_exceptions
    async def load_all_agents() -> List[Dict]:
        query = {
            "query": {"term": {"wazuh_data_type": "agent_info"}},
            "size": 10000
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]

    @staticmethod
    @handle_es_exceptions
    async def load_agents_by_groups(group_names: List[str]) -> List[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"group_name": group_names}}, 
                        {"term": {"wazuh_data_type": "agent_info"}}
                    ]
                }
            },
            "size": 10000
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]

class EventModel:
    def __init__(self, event: WazuhEvent):
        self.timestamp = event.timestamp
        self.agent_id = event.agent_id
        self.agent_ip = event.agent_ip
        self.rule_description = event.rule_description
        self.rule_level = event.rule_level
        self.rule_id = event.rule_id
        self.rule_mitre_id = event.rule_mitre_id
        self.rule_mitre_tactic = event.rule_mitre_tactic
        self.rule_mitre_technique = event.rule_mitre_technique
        self.wazuh_data_type = "wazuh_events"
        self.group_name = event.group_name

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "agent_ip": self.agent_ip,
            "rule_description": self.rule_description,
            "rule_level": self.rule_level,
            "rule_id": self.rule_id,
            "rule_mitre_id": self.rule_mitre_id,
            "rule_mitre_tactic": self.rule_mitre_tactic,
            "rule_mitre_technique": self.rule_mitre_technique,
            "group_name": self.group_name,
            "wazuh_data_type": self.wazuh_data_type
        }

    @staticmethod
    @handle_es_exceptions
    async def save_to_elasticsearch(event: 'EventModel'):
        es.index(index=get_index_name(), body=event.to_dict())

    @staticmethod
    @handle_es_exceptions
    async def load_group_events_from_elasticsearch(group_names: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                        {"terms": {"group_name": group_names}},
                        {"term": {"wazuh_data_type": "wazuh_events"}}
                    ]
                }
            },
            "size": 10000
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]

    @staticmethod
    @handle_es_exceptions
    async def load_from_elasticsearch_with_time_range(agent_id: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                        {"term": {"agent_id": agent_id}},
                        {"term": {"wazuh_data_type": "wazuh_events"}}
                    ]
                }
            },
            "size": 10000
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
    
    @staticmethod
    @handle_es_exceptions
    async def load_all_events_from_elasticsearch(start_time: datetime, end_time: datetime) -> List[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                        {"term": {"wazuh_data_type": "wazuh_events"}}
                    ]
                }
            },
            "size": 10000
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]
