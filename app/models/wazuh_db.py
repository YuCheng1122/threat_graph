from datetime import datetime
from typing import Optional, List, Dict
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError
import os
import logging
from functools import wraps

from dotenv import load_dotenv, find_dotenv
from ..schemas.wazuh import Agent as AgentSchema, WazuhEvent
from ..ext.error import ElasticsearchError, UserNotFoundError

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

# Maximum number of results to return from Elasticsearch queries
MAX_RESULTS = 10000

def create_index_with_mapping():
    """
    Create an Elasticsearch index with the appropriate mapping for agent and event data.
    The index name includes the current year and month.
    """
    index_name = f"{datetime.now().strftime('%Y_%m')}_agents_data"
    if not es.indices.exists(index=index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "agent_name": {"type": "keyword"},
                    "agent_id": {"type": "keyword"},
                    "ip": {"type": "ip"},
                    "agent_status": {"type": "keyword"},
                    "status_code": {"type": "integer"},
                    "last_keep_alive": {"type": "date"},
                    "os": {"type": "keyword"},
                    "os_version": {"type": "keyword"},
                    "group_name": {"type": "keyword"},
                    "wazuh_data_type": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    # Event specific fields
                    "rule_description": {"type": "text"},
                    "rule_level": {"type": "integer"},
                    "rule_id": {"type": "keyword"},
                    "rule_mitre_id": {"type": "keyword"},
                    "rule_mitre_tactic": {"type": "keyword"},
                    "rule_mitre_technique": {"type": "keyword"},
                    "agent_ip": {"type": "ip"}
                }
            }
        }
        try:
            es.indices.create(index=index_name, body=mapping)
            logging.info(f"Created new index with mapping: {index_name}")
        except RequestError as e:
            if e.error == 'resource_already_exists_exception':
                logging.info(f"Index {index_name} already exists, skipping creation")
            else:
                logging.error(f"Error creating index {index_name}: {str(e)}")
                raise
    else:
        logging.info(f"Index {index_name} already exists, using existing index")
    return index_name

def get_index_name():
    return create_index_with_mapping()

def handle_es_exceptions(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except NotFoundError as e:
            raise UserNotFoundError(str(e), 404)
        except Exception as e:
            logging.error(f"Elasticsearch error in {func.__name__}: {str(e)}")
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)
    return wrapper

class AgentModel:
    """
    Represents an agent in the Wazuh system. Handles the creation, storage, and retrieval of agent data.
    """
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
        self.timestamp = datetime.utcnow() 

    def to_dict(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "ip": self.ip,
            "agent_status": str(self.agent_status).lower(),
            "status_code": self.status_code,
            "last_keep_alive": self.last_keep_alive.isoformat() if self.last_keep_alive else None,
            "os": self.os,
            "os_version": self.os_version,
            "group_name": self.group_name, 
            "wazuh_data_type": self.wazuh_data_type,
            "timestamp": self.timestamp.isoformat()
        }

    @staticmethod
    def save_to_elasticsearch(agent: 'AgentModel'):
        try:
            index_name = get_index_name()
            agent_dict = agent.to_dict()
            logging.info(f"Saving agent info: {agent_dict}")
            logging.info(f"Agent status being saved: {agent_dict['agent_status']}")
            result = es.index(index=index_name, id=f"agent_{agent.agent_id}", body=agent_dict)
            logging.info(f"Agent {agent.agent_id} saved successfully. Result: {result}")
            return result
        except Exception as e:
            logging.error(f"Error saving agent {agent.agent_id} to Elasticsearch: {str(e)}")
            raise

    @staticmethod
    async def load_all_agents():
        """
        Load all agents from Elasticsearch.
        """
        query = {
            "query": {"term": {"wazuh_data_type": "agent_info"}},
            "size": 10000  # Adjust this value based on your needs
        }
        try:
            response = es.search(index=get_index_name(), body=query)
            agents = [hit['_source'] for hit in response['hits']['hits']]
            logging.info(f"Loaded {len(agents)} agents from Elasticsearch")
            return agents
        except Exception as e:
            logging.error(f"Error loading all agents: {str(e)}")
            raise
    
    @staticmethod
    async def load_agents_by_groups(group_names):
        """
        Load agents from Elasticsearch filtered by group names.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"wazuh_data_type": "agent_info"}},
                        {"terms": {"group_name": group_names}}
                    ]
                }
            },
            "size": 10000  # Adjust this value based on your needs
        }
        try:
            response = es.search(index=get_index_name(), body=query)
            agents = [hit['_source'] for hit in response['hits']['hits']]
            logging.info(f"Loaded {len(agents)} agents from Elasticsearch for groups: {group_names}")
            return agents
        except Exception as e:
            logging.error(f"Error loading agents by groups: {str(e)}")
            raise

    # @staticmethod
    # @handle_es_exceptions
    # async def load_from_elasticsearch(agent_id: str) -> Optional[Dict]:
    #     query = {
    #         "query": {
    #             "bool": {
    #                 "must": [
    #                     {"term": {"agent_id": agent_id}},
    #                     {"term": {"wazuh_data_type": "agent_info"}},
    #                     {"term": {"agent_status": "disconnected"}} 
    #                 ]
    #             }
    #         }
    #     }
    #     response = es.search(index=get_index_name(), body=query)
    #     hits = response['hits']['hits']
    #     return hits[0]['_source'] if hits else None

    # @staticmethod
    # @handle_es_exceptions
    # async def load_all_agents() -> List[Dict]:
    #     query = {
    #         "query": {"term": {"wazuh_data_type": "agent_info"}},
    #         "size": MAX_RESULTS
    #     }
    #     response = es.search(index=get_index_name(), body=query)
    #     return [hit['_source'] for hit in response['hits']['hits']]

    # @staticmethod
    # @handle_es_exceptions
    # async def load_agents_with_time_range(start_time: datetime, end_time: datetime) -> List[Dict]:
    #     query = {
    #         "query": {
    #             "bool": {
    #                 "must": [
    #                     {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
    #                     {"term": {"wazuh_data_type": "agent_info"}}
    #                 ]
    #             }
    #         },
    #         "size": MAX_RESULTS
    #     }
    #     response = es.search(index=get_index_name(), body=query)
    #     return [hit['_source'] for hit in response['hits']['hits']]

class EventModel:
    """
    Represents an event in the Wazuh system. Handles the creation, storage, and retrieval of event data.
    """
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
    def save_to_elasticsearch(event: 'EventModel'):
        try:
            index_name = get_index_name()
            event_dict = event.to_dict()
            logging.info(f"Saving event: {event_dict}")
            result = es.index(index=index_name, body=event_dict)
            logging.info(f"Event for agent {event.agent_id} saved successfully. Result: {result}")
            return result
        except Exception as e:
            logging.error(f"Error saving event for agent {event.agent_id} to Elasticsearch: {str(e)}")
            raise

    @staticmethod
    @handle_es_exceptions
    async def load_group_events_from_elasticsearch(group_names: List[str], start_time: datetime, end_time: datetime) -> List[Dict]:
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
            "size": MAX_RESULTS
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
            "size": MAX_RESULTS
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
            "size": MAX_RESULTS
        }
        response = es.search(index=get_index_name(), body=query)
        return [hit['_source'] for hit in response['hits']['hits']]