from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv, find_dotenv
import os
import json
from logging import getLogger
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables
try:
    load_dotenv(find_dotenv())
except Exception as e:
    logger.error(f"Error loading .env file: {str(e)}")
    raise

# Create a single Elasticsearch instance
es = AsyncElasticsearch(
    [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME'), }],
    http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
)
max_results = os.getenv('MAX_RESULTS')
es_agent_index = os.getenv('ES_AGENT_INDEX')
final_es_agent_index = f"{datetime.now().strftime('%Y_%m')}{es_agent_index}"

class AgentDetailModel:
    @staticmethod
    async def load_agent_info(agent_name: str) -> Dict[str, Any]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent_name": agent_name}}
                    ]
                }
            },
            "_source": ["agent_id", "agent_name", "ip", "os", "os_version", "agent_status", "last_keep_alive", "registration_time"],
            "size": 1,
            "sort": [
                {"last_keep_alive": "desc"}
            ]
        }
        
        try:
            result = await es.search(index=final_es_agent_index, body=query)
            hits = result['hits']['hits']
            if hits:
                return hits[0]['_source']
            else:
                return {}
        except Exception as e:
            logger.error(f"Error executing Elasticsearch query for agent info: {str(e)}")
            raise

    @staticmethod
    async def load_alerts(start_time: datetime, end_time: datetime, user_groups: List[str] = None, agent_name: str = None) -> Dict:
        """Get alerts by severity level"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if user_groups:
            must_conditions.append({"terms": {"group_name": user_groups}})
        
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "severity_levels": {
                    "terms": {"field": "rule_level"}
                }
            }
        }
        result = await es.search(index=final_es_agent_index, body=query)
        severity_map = {
            "12-15": "critical_severity",
            "8-11": "high_severity",
            "4-7": "medium_severity",
            "0-3": "low_severity"
        }
        counts = {level: 0 for level in severity_map.values()}
        for bucket in result['aggregations']['severity_levels']['buckets']:
            level = int(bucket['key'])
            for range_str, severity in severity_map.items():
                min_level, max_level = map(int, range_str.split('-'))
                if min_level <= level <= max_level:
                    counts[severity] += bucket['doc_count']
        return counts
    
    @staticmethod
    async def load_tactic_linechart(start_time: datetime, end_time: datetime, group_name: List[str]=None, agent_name: str = None) -> List[Dict]:
        """Get tactic timeline data"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"exists": {"field": "rule_mitre_tactic"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            {"bool": {"must_not": [
                {"term": {"rule_mitre_tactic": ""}},
                {"prefix": {"rule_mitre_tactic": "CVE-"}}
            ]}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})
            
        # First get all tactics in the time range
        tactic_query = {
            "size": 0,
            "query": {"bool": {"must": must_conditions}},
            "aggs": {
                "tactics": {
                    "terms": {
                        "field": "rule_mitre_tactic",
                        "size": 50
                    }
                }
            }
        }
        
        tactic_result = await es.search(index=final_es_agent_index, body=tactic_query)
        tactics = [bucket['key'] for bucket in tactic_result['aggregations']['tactics']['buckets'] 
                  if bucket['key'].strip()]
        
        if not tactics:
            return [{"label": [], "datas": []}]
        
        # Then get time series data for each tactic
        time_query = {
            "size": 0,
            "query": {"bool": {"must": must_conditions}},
            "aggs": {
                "by_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "1h",
                        "format": "yyyy-MM-dd'T'HH:mm:ss",
                        "extended_bounds": {
                            "min": start_time.isoformat(),
                            "max": end_time.isoformat()
                        }
                    },
                    "aggs": {
                        "by_tactic": {
                            "terms": {
                                "field": "rule_mitre_tactic",
                                "size": len(tactics)
                            }
                        }
                    }
                }
            }
        }
        
        time_result = await es.search(index=final_es_agent_index, body=time_query)
        
        # Create time buckets for all hours in range
        all_times = [bucket['key_as_string'] 
                    for bucket in time_result['aggregations']['by_time']['buckets']]
        
        # Initialize series data for each tactic
        tactic_series = []
        for tactic in tactics:
            data_points = []
            for time_bucket in time_result['aggregations']['by_time']['buckets']:
                count = 0
                for tactic_bucket in time_bucket['by_tactic']['buckets']:
                    if tactic_bucket['key'] == tactic:
                        count = tactic_bucket['doc_count']
                        break
                data_points.append({
                    "timestamp": time_bucket['key_as_string'],
                    "count": count
                })
            
            tactic_series.append({
                "name": tactic,
                "type": "line",
                "data": data_points
            })
        
        return [{
            "label": [{"label": tactic} for tactic in tactics],
            "datas": tactic_series
        }]
    
    @staticmethod
    async def load_cve_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None, agent_name: str = None) -> List[Dict]:
        """Get CVE statistics from rule_mitre_tactic"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            {"prefix": {"rule_mitre_tactic": "CVE-"}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})
        
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "cve_stats": {
                    "terms": {
                        "field": "rule_mitre_tactic",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        
        return [
            {"cve_name": bucket["key"], "count": bucket["doc_count"]}
            for bucket in result["aggregations"]["cve_stats"]["buckets"]
        ]

    @staticmethod
    async def load_malicious_file_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None, agent_name: str = None) -> List[Dict]:
        """Get malicious file statistics from rule_id 87105 and 100003"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"terms": {"rule_id": ["87105", "100003"]}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})
                
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": must_conditions
                }
            }
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        
        def extract_filepath(description: str) -> str:
            """Extract file path from rule description"""
            pattern = r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.(?:zip|exe|bat|cmd|ps1|vbs|js)'
            match = re.search(pattern, description)
            return match.group(0) if match else description
        
        file_counts = {}
        for hit in result['hits']['hits']:
            description = hit['_source']['rule_description']
            filepath = extract_filepath(description)
            file_counts[filepath] = file_counts.get(filepath, 0) + 1
        
        return [
            {
                "malicious_file": filepath,
                "count": count
            }
            for filepath, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
        ]

    @staticmethod
    async def load_authentication_piechart(start_time: datetime, end_time: datetime, group_name: List[str]=None, agent_name: str = None) -> List[Dict]:
        """Get authentication failure techniques statistics"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"term": {"rule_id": "60204"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name and len(group_name) > 0:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "by_technique": {
                    "terms": {
                        "field": "rule_mitre_technique",
                        "size": 20,
                        "min_doc_count": 1
                    }
                }
            }
        }

        result = await es.search(index=final_es_agent_index, body=query)
        return [
            {
                "tactic": bucket['key'],
                "count": bucket['doc_count']
            }
            for bucket in result['aggregations']['by_technique']['buckets']
            if bucket['key'].strip()
        ]
    
    @staticmethod
    async def load_event_table(start_time: datetime, end_time: datetime, group_name: Optional[List[str]] = None, agent_name: Optional[str] = None) -> List[Dict]:
        """Get event table data"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        if agent_name:
            must_conditions.append({"term": {"agent_name": agent_name}})
            
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [
                {"timestamp": {"order": "desc"}}
            ]
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        return [hit['_source'] for hit in result['hits']['hits']]
