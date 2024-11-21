from datetime import datetime
from typing import Dict, List
from app.models.dashboard_db import DashboardModel

class DashboardController:
    @staticmethod
    async def clean_agent_summary(start_time: datetime, end_time: datetime, user_groups: List[str]=None):
        data = await DashboardModel.load_agent_summary(start_time, end_time, user_groups)
        return {
            "agent_summary": {
                "connected_agents": data.get("connected", 0),
                "disconnected_agents": data.get("disconnected", 0)
            }
        }

    @staticmethod
    async def clean_agent_os(start_time: datetime, end_time: datetime, user_groups: List[str]=None):
        """Get OS distribution of agents"""
        data = await DashboardModel.load_agent_os(start_time, end_time, user_groups)
        # 返回正確的嵌套結構
        return {
            "agent_os": [
                {
                    "os": item.get("os", "Unknown"),
                    "count": item.get("count", 0)
                }
                for item in data
            ]
        }

    @staticmethod
    async def clean_alerts(start_time: datetime, end_time: datetime, user_groups: List[str]=None):
        """Get alerts severity statistics"""
        data = await DashboardModel.load_alerts(start_time, end_time, user_groups)
        return {
            "alerts": {
                "critical_severity": data.get("critical_severity", 0),
                "high_severity": data.get("high_severity", 0),
                "medium_severity": data.get("medium_severity", 0),
                "low_severity": data.get("low_severity", 0)
            }
        }

    @staticmethod
    async def clean_cve_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get CVE statistics"""
        data = await DashboardModel.load_cve_barchart(start_time, end_time, group_name)
        return {
            "cve_barchart": [
                {
                    "cve_name": item["cve_name"],
                    "count": item["count"]
                }
                for item in data
            ]
        }

    @staticmethod
    async def clean_tactic_linechart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get tactic timeline data"""
        data = await DashboardModel.load_tactic_linechart(start_time, end_time, group_name)
        return {
            "tactic_linechart": data
        }

    @staticmethod
    async def clean_malicious_file_barchart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get malicious file statistics"""
        data = await DashboardModel.load_malicious_file_barchart(start_time, end_time, group_name)
        return {
            "malicious_file_barchart": [
                {
                    "name": item["malicious_file"],
                    "count": item["count"]
                }
                for item in data
            ]
        }

    @staticmethod
    async def clean_authentication_piechart(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get authentication statistics"""
        data = await DashboardModel.load_authentication_piechart(start_time, end_time, group_name)
        return {
            "authentication_piechart": [
                {
                    "tactic": item["tactic"],
                    "count": item["count"]
                }
                for item in data
            ]
        }

    @staticmethod
    async def clean_agent_name(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get agent event statistics"""
        data = await DashboardModel.load_agent_events(start_time, end_time, group_name)
        return {
            "agent_name": [
                {
                    "agent_name": item["agent_name"],
                    "event_count": item["event_count"]
                }
                for item in data
            ]
        }

    @staticmethod
    async def clean_event_table(start_time: datetime, end_time: datetime, group_name: List[str]=None) -> Dict:
        """Get event details"""
        data = await DashboardModel.load_event_table(start_time, end_time, group_name)
        return {
            "event_table": [
                {
                    "timestamp": item["timestamp"],
                    "agent_name": item["agent_name"],
                    "rule_description": item["rule_description"],
                    "rule_mitre_tactic": item["rule_mitre_tactic"],
                    "rule_mitre_id": item["rule_mitre_id"],
                    "rule_level": item["rule_level"]
                }
                for item in data
            ]
        }
