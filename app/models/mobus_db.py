from elasticsearch import Elasticsearch
import os
from logging import getLogger
from app.schemas.mobus import ModbusEventCreate, ModbusEventResponse
from datetime import datetime
from typing import Dict, List

logger = getLogger('app_logger')

class ModbusEventModel:
    def __init__(self):
        self.index_prefix = "modbus_events"
        es_host = os.getenv('ES_HOST', 'localhost')
        es_port = int(os.getenv('ES_PORT', 9200))
        es_scheme = os.getenv('ES_SCHEME', 'http')
        es_user = os.getenv('ES_USER')
        es_password = os.getenv('ES_PASSWORD')
        
        self.es = Elasticsearch(
            [{'host': es_host, 'port': es_port, 'scheme': es_scheme}],
            http_auth=(es_user, es_password) if es_user and es_password else None
        )

    def to_dict(self, event_data: ModbusEventCreate) -> Dict:
        return {
            "device_id": str(event_data.device_id),
            "timestamp": event_data.timestamp.isoformat(),
            "event_type": str(event_data.event_type),
            "source_ip": str(event_data.source_ip),
            "source_port": int(event_data.source_port),
            "destination_ip": str(event_data.destination_ip),
            "destination_port": int(event_data.destination_port),
            "modbus_function": int(event_data.modbus_function),
            "modbus_data": str(event_data.modbus_data),
            "alert": str(event_data.alert),
            "additional_info": event_data.additional_info
        }

    def create_event(self, event_data: ModbusEventCreate) -> str:
        index_name = f"{self.index_prefix}_{datetime.now().strftime('%Y%m').lower()}"
        document = self.to_dict(event_data)
        return self.save_to_elasticsearch(index_name, document)

    def save_to_elasticsearch(self, index_name: str, document: Dict) -> str:
        result = self.es.index(index=index_name, document=document)
        return result['_id']

    def get_events(self, start_time: datetime, end_time: datetime) -> List[ModbusEventResponse]:
        index_pattern = f"{self.index_prefix}_*"
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }
                }
            },
            "sort": [{"timestamp": "asc"}]
        }

        results = self.es.search(index=index_pattern, body=query, size=10000)
        events = []
        for hit in results['hits']['hits']:
            event_data = hit['_source']
            event_data['event_id'] = hit['_id']  # 使用 _id 作為 event_id
            events.append(ModbusEventResponse(**event_data))
        return events