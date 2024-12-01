from datetime import datetime
from typing import Dict, List, Optional
from app.models.agent_db import AgentDetailModel
from logging import getLogger

logger = getLogger('app_logger')

class AgentDetailController:

    @staticmethod
    async def get_agent_info(agent_name: str) -> Dict:
        """Get agent info filtered by agent name"""
        agent_info = await AgentDetailModel.load_agent_info(agent_name)
        return agent_info

    @staticmethod
    async def clean_alerts(start_time: datetime, end_time: datetime, agent_name: str, user_groups: Optional[List[str]] = None) -> Dict:
        """Get alerts filtered by agent name"""
        alerts = await AgentDetailModel.load_alerts(start_time, end_time, user_groups, agent_name)
        return alerts

    @staticmethod
    async def clean_tactic_linechart(start_time: datetime, end_time: datetime, agent_name: str, group_name: Optional[List[str]] = None) -> Dict:
        """Get tactic linechart filtered by agent name"""
        tactic_data = await AgentDetailModel.load_tactic_linechart(start_time, end_time, group_name, agent_name)
        return tactic_data

    @staticmethod
    async def clean_cve_barchart(start_time: datetime, end_time: datetime, agent_name: str, group_name: Optional[List[str]] = None) -> Dict:
        """Get CVE barchart filtered by agent name"""
        cve_data = await AgentDetailModel.load_cve_barchart(start_time, end_time, group_name, agent_name)
        return cve_data

    @staticmethod
    async def clean_malicious_file_barchart(start_time: datetime, end_time: datetime, agent_name: str, group_name: Optional[List[str]] = None) -> Dict:
        """Get malicious file barchart filtered by agent name"""
        malicious_file_data = await AgentDetailModel.load_malicious_file_barchart(start_time, end_time, group_name, agent_name)
        return malicious_file_data

    @staticmethod
    async def clean_authentication_piechart(start_time: datetime, end_time: datetime, agent_name: str, group_name: Optional[List[str]] = None) -> Dict:
        """Get authentication piechart filtered by agent name"""
        authentication_data = await AgentDetailModel.load_authentication_piechart(start_time, end_time, group_name, agent_name)
        return authentication_data

    @staticmethod
    async def clean_event_table(start_time: datetime, end_time: datetime, agent_name: str, group_name: Optional[List[str]] = None) -> Dict:
        """Get event table filtered by agent name"""
        event_data = await AgentDetailModel.load_event_table(start_time, end_time, group_name, agent_name)
        return event_data
