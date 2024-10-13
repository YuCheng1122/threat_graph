from elasticsearch import Elasticsearch
from dotenv import load_dotenv, find_dotenv
import os
from logging import getLogger
from datetime import datetime
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
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def _get_base_query(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        return {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                        {"term": {"agent_id": self.agent_id}}
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
            result = es.search(index=f"{datetime.now().strftime('%Y_%m')}{es_agent_index}", body=query)
            return result['hits']['hits']
        except Exception as e:
            logger.error(f"Error executing Elasticsearch query: {str(e)}")
            raise
        
    def get_mitre_data(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["_source"] = ["rule_mitre_id", "rule_mitre_tactic", "rule_mitre_technique", "rule_description"]
        return self._execute_query(query)

    def get_ransomware_data(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        query = self._get_base_query(start_time, end_time)
        query["query"]["bool"]["must"].append({"terms": {"rule.id": [87105]}})
        query["_source"] = ["rule.description", "rule.id"]
        logger.info(f"ransomware query: {query}")
        return self._execute_query(query)

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