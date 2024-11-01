from datetime import datetime
from typing import Optional, List, Dict, Tuple
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError
import os
import json
import logging
from functools import wraps
from dotenv import load_dotenv, find_dotenv
from app.schemas.wazuh import Agent as AgentSchema, WazuhEvent
from app.ext.error import ElasticsearchError, UserNotFoundError
from logging import getLogger
from app.models.user_db import UserModel

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables
try:
    load_dotenv(find_dotenv())
except Exception as e:
    logger.error(f"Error loading .env file: {str(e)}")
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
        except RequestError as e:
                logger.error(f"Error creating index {index_name}: {str(e)}")
                raise
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
            logger.error(f"Elasticsearch error in {func.__name__}: {str(e)}")
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
        self.registration_time = agent.registration_time
    def to_dict(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "ip": self.ip,
            "agent_status": str(self.agent_status).lower(),
            "status_code": self.status_code,
            "last_keep_alive": self.last_keep_alive.isoformat() if self.last_keep_alive else None,
            "registration_time": self.registration_time.isoformat() if self.registration_time else None,
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
            result = es.index(index=index_name, id=f"agent_{agent.agent_id}", body=agent_dict)
            return result
        except Exception as e:
            logger.error(f"Error saving agent {agent.agent_id} to Elasticsearch: {str(e)}")
            raise

    @staticmethod
    @handle_es_exceptions
    async def load_agents(start_time: datetime, end_time: datetime, group_names: Optional[List[str]] = None):
        """
        Load agents from Elasticsearch within a specified time range, optionally filtered by group names.
        """
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"wazuh_data_type": "agent_info"}},
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat(),
                                        "format": "strict_date_optional_time"
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": MAX_RESULTS
            }

            if group_names:
                query["query"]["bool"]["must"].append({"terms": {"group_name": group_names}})
         
            index_name = get_index_name()
            response = es.search(index=index_name, body=query)
            
            agents = [hit['_source'] for hit in response['hits']['hits']]
            return agents
        except Exception as e:
            logger.error(f"Unexpected error in load_agents: {str(e)}")
            raise ElasticsearchError(f"Error loading agents: {str(e)}", 500)
    
    @staticmethod
    def get_latest_agent_details(group_names: Optional[List[str]] = None) -> List[Dict]:
        query = {
            "size": 10000,
            "_source": [
                "agent_name",
                "ip",
                "os",
                "agent_status",
                "last_keep_alive",
                "registration_time",
                "group_name"
            ],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"wazuh_data_type": "agent_info"}},
                        {
                            "range": {
                                "last_keep_alive": {
                                    "gte": "2024-09-09T00:00:00" 
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"last_keep_alive": {"order": "desc"}}
            ],
            "collapse": {
                "field": "agent_id"
            }
        }

        if group_names:
            query["query"]["bool"]["must"].append({"terms": {"group_name": group_names}})

        logger.info(f"Elasticsearch query: {json.dumps(query, indent=2)}")

        try:
            index_name = f"{datetime.now().strftime('%Y_%m')}_agents_data"
            result = es.search(index=index_name, body=query)
            
            # Log relevant parts of the Elasticsearch response
            logger.info(f"Total hits: {result['hits']['total']['value']}")
            logger.info(f"Max score: {result['hits']['max_score']}")
            
            agent_details = [hit['_source'] for hit in result['hits']['hits']]
            logger.info(f"Number of agents retrieved: {len(agent_details)}")
            logger.info(f"Sample agent detail: {json.dumps(agent_details[0] if agent_details else {}, indent=2)}")

            return agent_details
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {str(e)}")
            raise ElasticsearchError(f"Error loading agents: {str(e)}", 500)
        
class EventModel:
    """
    Represents an event in the Wazuh system. Handles the creation, storage, and retrieval of event data.
    """
    def __init__(self, event: WazuhEvent):
        self.timestamp = event.timestamp
        self.agent_id = event.agent_id
        self.agent_name = event.agent_name
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
            "agent_name": self.agent_name,
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
            raise ElasticsearchError(f"Error loading agents: {str(e)}", 500)

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
        try:
            response = es.search(index=get_index_name(), body=query)
            return [hit['_source'] for hit in response['hits']['hits']]
        except Exception as e:
            raise ElasticsearchError(f"Error getting events: {str(e)}")

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
        try:
            response = es.search(index=get_index_name(), body=query)
            return [hit['_source'] for hit in response['hits']['hits']]
        except Exception as e:
            raise ElasticsearchError(f"Error getting events: {str(e)}")
        
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
        try:
            response = es.search(index=get_index_name(), body=query)
            return [hit['_source'] for hit in response['hits']['hits']]
        except Exception as e:
            raise ElasticsearchError(f"Error getting events: {str(e)}")
        
    @staticmethod
    async def get_events_in_timerange(current_user: UserModel, start_time: datetime, end_time: datetime, size: int = 10000) -> List[Dict]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"wazuh_data_type": "wazuh_events"}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lt": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "size": size,
            "sort": [
                {"timestamp": "asc"}
            ]
        }
        try:
            if current_user.user_role == 'admin':
                result = es.search(index=get_index_name(), body=query)
            else:
                group_names = UserModel.get_user_groups(current_user.id)
                permission_granted = UserModel.check_user_group(current_user.id, group_names)
                if not permission_granted:
                    return []
                query["query"]["bool"]["must"].append({"terms": {"group_name": group_names}})
                result = es.search(index=get_index_name(), body=query)
            return result['hits']['hits']
        except Exception as e:
            raise ElasticsearchError(f"Error getting events: {str(e)}")
    
    @staticmethod
    async def get_high_level_event_count(current_user: UserModel, start_time: datetime, end_time: datetime) -> int:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lt": end_time.isoformat()
                                }
                            }
                        },
                        {
                            "range": {
                                "rule_level": {
                                    "gte": 8,
                                    "lte": 14
                                }
                            }
                        }
                    ]
                }
            }
        }
        try:
            if current_user.user_role == 'admin':
                result = es.count(index=get_index_name(), body=query)
            else:
                group_names = UserModel.get_user_groups(current_user.id)
                permission_granted = UserModel.check_user_group(current_user.id, group_names)
                if not permission_granted:
                    return "0"
                query["query"]["bool"]["must"].append({"terms": {"group_name": group_names}})
                result = es.count(index=get_index_name(), body=query)
            logger.info(f"High-level event count: {result['count']}")
            return result['count']
        except Exception as e:
            raise ElasticsearchError(f"Error getting high-level event count: {str(e)}")
        
    @staticmethod
    async def get_events_for_pie_chart(current_user: UserModel, start_time: datetime, end_time: datetime, size: int = 10000) -> List[Dict]:
        query = {
            "query": {
                "bool": {   
                    "must": [
                        {"term": {"wazuh_data_type": "wazuh_events"}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lt": end_time.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "size": size,
            "sort": [
                {"timestamp": "asc"}
            ]
        }
        try:
            if current_user.user_role == 'admin':
                result = es.search(index=get_index_name(), body=query)
            else:
                group_names = UserModel.get_user_groups(current_user.id)
                permission_granted = UserModel.check_user_group(current_user.id, group_names)
                if not permission_granted:
                    return []
                query["query"]["bool"]["must"].append({"terms": {"group_name": group_names}})
                result = es.search(index=get_index_name(), body=query)
            return result['hits']['hits']
        except Exception as e:
            raise ElasticsearchError(f"Error getting events for pie chart: {str(e)}")
        
    @staticmethod
    async def load_messages(start_time: datetime, end_time: datetime, group_names: Optional[List[str]] = None, limit: int = 100) -> Tuple[List[Dict], int]:
        """
        Load high-level messages (rule_level >=8) from Elasticsearch within a specified time range.
        """
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lt": end_time.isoformat()
                            }
                        }
                    },
                    {
                        "range": {
                            "rule_level": {
                                "gte": 8
                            }
                        }
                    }
                ]
            }
        }
        
        if group_names:
            query["bool"]["must"].append({"terms": {"group_name": group_names}})
        
        body = {
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": limit,
            }
        
        logger.info(f"Loading messages with query: {body}")
        
        try:
            result = es.search(index=get_index_name(), body=body)
            messages = [hit['_source'] for hit in result['hits']['hits']]
            total_count = result['hits']['total']['value']
            logger.info(f"Loaded {len(messages)} messages for {group_names} from {start_time} to {end_time}")
            logger.info(f"Messages: {messages}")
            
            return messages, total_count
        except Exception as e:
            raise ElasticsearchError(f"Error loading high-level messages: {str(e)}")
