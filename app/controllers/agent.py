from app.models.agent_db import AgentDetail
from logging import getLogger
from functools import wraps
from app.ext.error import UserNotFoundError, UnauthorizedError, PermissionError, ElasticsearchError, HTTPError
from datetime import datetime
from typing import Dict, List

# Get the centralized logger
logger = getLogger('app_logger')

def handle_exceptions(func):
    """
    Decorator to handle common exceptions in controller methods.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except UserNotFoundError:
            raise UserNotFoundError()
        except UnauthorizedError:
            raise UnauthorizedError("Authentication required")
        except PermissionError:
            raise PermissionError("Permission denied")
        except ElasticsearchError as e:
            raise ElasticsearchError("Database error")
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            raise HTTPError(status_code=500, detail="Internal server error")
    return wrapper


class AgentDetailController:
    @staticmethod
    @handle_exceptions
    async def get_agent_mitre(agent_id: str, start_time: str, end_time: str):

        agent_detail = AgentDetail(agent_id)
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        raw_data = agent_detail.get_mitre_data(start_datetime, end_datetime)
        
        mitre_data = []
        for hit in raw_data:
            source = hit['_source']
            mitre_tactic = source.get('rule_mitre_tactic')
            mitre_technique = source.get('rule_mitre_technique')
            mitre_id = source.get('rule_mitre_id')
            
            if mitre_tactic and mitre_technique and mitre_id:
                mitre_data.append({
                    "mitre_tactic": mitre_tactic,
                    "mitre_technique": mitre_technique,
                    "mitre_count": 1,
                    "mitre_ids": [mitre_id],
                    "rule_description": source.get('rule_description', '')
                })
        
        aggregated_data = {}
        for item in mitre_data:
            key = (item['mitre_tactic'], item['mitre_technique'])
            if key not in aggregated_data:
                aggregated_data[key] = item
            else:
                aggregated_data[key]['mitre_count'] += 1
                aggregated_data[key]['mitre_ids'].extend(item['mitre_ids'])
        
        final_mitre_data = list(aggregated_data.values())
        for item in final_mitre_data:
            item['mitre_ids'] = list(set(item['mitre_ids']))
        
        return final_mitre_data
    
    @staticmethod
    @handle_exceptions
    async def get_agent_ransomware(agent_id: str, start_time: str, end_time: str) -> Dict[str, List[str] | int]:
        agent_detail = AgentDetail(agent_id)
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        raw_data = agent_detail.get_ransomware_data(start_datetime, end_datetime)
        
        ransomware_descriptions = set()
        for hit in raw_data:
            source = hit['_source']
            if 'rule' in source and 'description' in source['rule']:
                ransomware_descriptions.add(source['rule']['description'])
        return {
            "ransomware_name": list(ransomware_descriptions),
            "ransomware_count": len(ransomware_descriptions)
        }

    @staticmethod
    @handle_exceptions
    async def get_agent_cve(agent_id: str, start_time: str, end_time: str) -> Dict[str, List[str] | int]:
        logger.info(f"get_agent_cve called with agent_id: {agent_id}, start_time: {start_time}, end_time: {end_time}")
        
        agent_detail = AgentDetail(agent_id)
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        raw_data = agent_detail.get_cve_data(start_datetime, end_datetime)
        
        cve_names = set()
        for hit in raw_data:
            source = hit['_source']
            if 'rule_cve' in source:
                cve_names.add(source['rule_cve'])
        
        return {
            "cve_name": list(cve_names),
            "cve_count": len(cve_names)
        }

    @staticmethod
    @handle_exceptions
    async def get_agent_ioc(agent_id: str, start_time: str, end_time: str) -> List[Dict[str, str | int | List[str]]]:
        logger.info(f"get_agent_ioc called with agent_id: {agent_id}, start_time: {start_time}, end_time: {end_time}")
        
        agent_detail = AgentDetail(agent_id)
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        raw_data = agent_detail.get_ioc_data(start_datetime, end_datetime)
        
        ioc_data = {}
        for hit in raw_data:
            source = hit['_source']
            if 'rule_ioc' in source:
                ioc_type = source['rule_ioc'].get('type')
                ioc_value = source['rule_ioc'].get('value')
                if ioc_type and ioc_value:
                    if ioc_type not in ioc_data:
                        ioc_data[ioc_type] = set()
                    ioc_data[ioc_type].add(ioc_value)
        
        return [
            {
                "ioc_type": ioc_type,
                "ioc_count": len(ioc_values),
                "ioc_data": list(ioc_values)
            }
            for ioc_type, ioc_values in ioc_data.items()
        ]

    @staticmethod
    @handle_exceptions
    async def get_agent_compliance(agent_id: str, start_time: str, end_time: str) -> Dict[str, List[str] | int]:
        logger.info(f"get_agent_compliance called with agent_id: {agent_id}, start_time: {start_time}, end_time: {end_time}")
        
        agent_detail = AgentDetail(agent_id)
        start_datetime = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_datetime = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        raw_data = agent_detail.get_compliance_data(start_datetime, end_datetime)
        
        compliance_names = set()
        for hit in raw_data:
            source = hit['_source']
            if 'rule_compliance' in source:
                compliance_names.add(source['rule_compliance'])
        
        return {
            "compliance_name": list(compliance_names),
            "compliance_count": len(compliance_names)
        }