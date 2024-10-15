from elasticsearch import Elasticsearch
from dotenv import load_dotenv, find_dotenv
import os
from logging import getLogger
from datetime import datetime, timedelta
from typing import Dict, Any, List

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
    [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME'), }],
    http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
)
max_results = os.getenv('MAX_RESULTS')
es_agent_index = os.getenv('ES_AGENT_INDEX')
final_es_agent_index = f"{datetime.now().strftime('%Y_%m')}{es_agent_index}"

class AgentDetail:
    def __init__(self, agent_name: str):
        self.agent_name = agent_name

    def _get_base_query(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        return {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    ]
                }
            },
            "size": max_results,
            "sort": [
                {"timestamp": "asc"}
            ]
        }

    def _execute_query(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            result = es.search(index=final_es_agent_index, body=query)
            return result['hits']['hits']
        except Exception as e:
            logger.error(f"Error executing Elasticsearch query: {str(e)}")
            raise
        
    def get_agent_info(self, agent_name: str) -> Dict[str, Any]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent_name": agent_name}}
                    ]
                }
            },
            "_source": ["agent_id", "agent_name", "ip", "os", "os_version", "agent_status", "last_keep_alive"],
            "size": 1,
            "sort": [
                {"last_keep_alive": "desc"}
            ]
        }
        
        try:
            result = es.search(index=final_es_agent_index, body=query)
            hits = result['hits']['hits']
            if hits:
                return hits[0]['_source']
            else:
                return {}
        except Exception as e:
            logger.error(f"Error executing Elasticsearch query for agent info: {str(e)}")
            raise

    def get_mitre_data(self, start_time: str, end_time:str) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["_source"] = ["rule_mitre_id", "rule_mitre_tactic", "rule_mitre_technique", "rule_description"]
        return self._execute_query(query)

    def get_ransomware_data(self, agent_name: str, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["query"]["bool"]["must"].extend([
            {"term": {"agent_name": agent_name}},
            {"term": {"rule_id": 87105}},
            {"term": {"wazuh_data_type": "wazuh_events"}}
        ])
        query["_source"] = ["rule_description", "rule_id"]
        
        logger.info(f"Ransomware query for agent {agent_name}: {query}")

        results = self._execute_query(query)
        return results

    def get_cve_data(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["_source"] = ["rule_cve"]
        return self._execute_query(query)

    def get_ioc_data(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["_source"] = ["rule_ioc"]
        return self._execute_query(query)

    def get_compliance_data(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["_source"] = ["rule_compliance"]
        return self._execute_query(query)