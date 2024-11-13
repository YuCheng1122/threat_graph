from elasticsearch import AsyncElasticsearch
from dotenv import load_dotenv, find_dotenv
import os
import json
from logging import getLogger
from datetime import datetime
from typing import Dict, List, Optional

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

class DashboardModel:
    @staticmethod
    async def load_agent_summary(start_time: datetime, end_time: datetime, group_name: List[str] = None) -> Dict:
        """Get connected and disconnected agents count"""
        must_conditions = [
            {"term": {"wazuh_data_type": "agent_info"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        # 只有在提供 group_name 時才添加群組過濾
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "status_count": {
                    "terms": {"field": "agent_status"}
                }
            }
        }
        result = await es.search(index=final_es_agent_index, body=query)
        buckets = result['aggregations']['status_count']['buckets']
        
        return {
            "connected": next((b['doc_count'] for b in buckets if b['key'] == 'active'), 0),
            "disconnected": next((b['doc_count'] for b in buckets if b['key'] == 'disconnected'), 0)
        }

    @staticmethod
    async def load_agent_os(start_time: datetime, end_time: datetime, group_name: List[str] = None) -> List[Dict]:
        """Get OS distribution"""
        must_conditions = [
            {"term": {"wazuh_data_type": "agent_info"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "os_distribution": {
                    "terms": {"field": "os"}
                }
            }
        }
        result = await es.search(index=final_es_agent_index, body=query)
        return [{"os": bucket["key"], "count": bucket["doc_count"]} 
                for bucket in result['aggregations']['os_distribution']['buckets']]

    @staticmethod
    async def load_alerts(start_time: datetime, end_time: datetime, user_groups: List[str] = None) -> Dict:
        """Get alerts by severity level"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if user_groups:
            must_conditions.append({"terms": {"group_name": user_groups}})
            
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
    async def load_cve_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> List[Dict]:
        """Get CVE statistics from rule_description"""
        must_conditions = [
            {"wildcard": {"rule_description": "*CVE-*"}},  # 抓取包含 CVE- 的描述
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "cve_stats": {
                    "terms": {
                        "field": "rule_description.keyword",
                        "size": 10,
                        "include": ".*CVE-\\d{4}-\\d{4,7}.*"  # 使用正則表達式匹配 CVE ID
                    }
                }
            }
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        
        # 從 description 中提取 CVE ID
        def extract_cve(description: str) -> str:
            import re
            match = re.search(r'CVE-\d{4}-\d{4,7}', description)
            return match.group(0) if match else description
        
        return [
            {
                "cve_name": extract_cve(bucket['key']),
                "count": bucket['doc_count']
            }
            for bucket in result['aggregations']['cve_stats']['buckets']
        ]

    @staticmethod
    async def load_ttp_linechart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> List[Dict]:
        """Get TTP timeline data"""
        must_conditions = [
            {"exists": {"field": "rule_mitre_id"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            {"bool": {
                "must_not": {
                    "term": {"rule_mitre_id": ""}  # 過濾掉空值
                }
            }}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
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
                        "field": "rule_mitre_id",
                        "size": 10,
                        "min_doc_count": 1  # 只返回至少有一個文檔的桶
                    },
                    "aggs": {
                        "by_time": {
                            "date_histogram": {
                                "field": "timestamp",
                                "fixed_interval": "1h",
                                "format": "yyyy-MM-dd HH:mm:ss"
                            }
                        }
                    }
                }
            }
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        
        # 取得所有非空的技術和時間點
        techniques = [tech['key'] for tech in result['aggregations']['by_technique']['buckets'] if tech['key'].strip()]
        all_times = set()
        
        for tech_bucket in result['aggregations']['by_technique']['buckets']:
            if tech_bucket['key'].strip():  # 只處理非空的技術
                for time_bucket in tech_bucket['by_time']['buckets']:
                    all_times.add(time_bucket['key_as_string'])
        
        all_times = sorted(list(all_times))
        
        # 建構數據
        technique_data = {}
        for tech in techniques:
            technique_data[tech] = {time: 0 for time in all_times}
        
        # 填充數據
        for tech_bucket in result['aggregations']['by_technique']['buckets']:
            tech = tech_bucket['key']
            if tech.strip():  # 只處理非空的技術
                for time_bucket in tech_bucket['by_time']['buckets']:
                    time = time_bucket['key_as_string']
                    technique_data[tech][time] = time_bucket['doc_count']
        
        # 格式化為所需的結構
        technique_series = []
        for tech in techniques:
            data_points = []
            for time in all_times:
                data_points.append({
                    "time": time,
                    "value": technique_data[tech][time]
                })
            technique_series.append({
                "name": tech,
                "type": "line",
                "data": data_points
            })
        
        return [{
            "label": [{"label": tech} for tech in techniques],
            "datas": technique_series
        }]
    
    @staticmethod
    async def load_malicious_file_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> List[Dict]:
        """Get malicious file statistics from rule_id 87105"""
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"term": {"rule_id": "87105"}},  # 特定規則 ID
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "malicious_files": {
                    "terms": {
                        "field": "rule_description.keyword",
                        "size": 20  # 增加返回數量
                    }
                }
            }
        }
        
        result = await es.search(index=final_es_agent_index, body=query)
        
        return [
            {
                "malicious_file": bucket['key'],
                "count": bucket['doc_count']
            }
            for bucket in result['aggregations']['malicious_files']['buckets']
        ]

    @staticmethod
    async def load_authentication_piechart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> List[Dict]:
        """Get authentication failure techniques statistics"""

        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"wildcard": {"rule_description": "*Multiple authentication failures*"}},
            {"exists": {"field": "rule_mitre_technique"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name and len(group_name) > 0:
            must_conditions.append({"terms": {"group_name": group_name}})

        query = {
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
    async def load_agent_events(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> List[Dict]:
        """Get agent event statistics"""
        must_conditions = [
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        ]
        
        if group_name:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent_name"}
                }
            }
        }
        result = await es.search(index=final_es_agent_index, body=query)
        return [
            {"agent_name": bucket['key'], "event_count": bucket['doc_count']}
            for bucket in result['aggregations']['by_agent']['buckets']
        ]

    @staticmethod
    async def load_event_table(start_time: datetime, end_time: datetime, group_name: Optional[List[str]] = None) -> List[Dict]:
        """Get event details"""
        # 構建基礎的 must 條件
        must_conditions = [
            {"term": {"wazuh_data_type": "wazuh_events"}},
            {"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            {"range": {"rule_level": {"gte": 8}}} 
        ]
        
        # 如果提供了 group_name，添加群組過濾
        if group_name and len(group_name) > 0:
            must_conditions.append({"terms": {"group_name": group_name}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"timestamp": "desc"}],
            "size": int(max_results)
        }

        try:
            result = await es.search(index=final_es_agent_index, body=query)
            logger.debug(f"Event table query: {json.dumps(query, indent=2)}") 
            
            return [
                {
                    "timestamp": hit['_source']['timestamp'],
                    "agent_name": hit['_source']['agent_name'],
                    "rule_description": hit['_source'].get('rule_description', ''),
                    "rule_mitre_tactic": hit['_source'].get('rule_mitre_tactic', ''),
                    "rule_mitre_id": hit['_source'].get('rule_mitre_id', ''),
                    "rule_level": hit['_source'].get('rule_level', 0)
                }
                for hit in result['hits']['hits']
            ]
        except Exception as e:
            logger.error(f"Error in load_event_table: {str(e)}")
            raise
