from datetime import datetime
from typing import Optional, List, Dict
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError

from ..schemas.event import Event as EventSchema
from ..ext.error import ElasticsearchError, NotFoundUserError


class EventModel:

    def __init__(self, event: EventSchema):
        self.timestamp = event.timestamp
        self.event_type = event.event_type
        self.src_ip = event.src_ip
        self.dest_ip = event.dest_ip
        self.src_port = event.src_port
        self.dest_port = event.dest_port
        self.proto = event.proto
        self.app_proto = event.app_proto
        self.bytes_toserver = event.bytes_toserver
        self.bytes_toclient = event.bytes_toclient
        self.signature = event.signature
        self.severity = event.severity
        self.tags = event.tags.__dict__ or {}

    def to_dict(self) -> Dict:
        event_dict = {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "src_port": self.src_port,
            "dest_port": self.dest_port,
            "proto": self.proto,
            "app_proto": self.app_proto,
            "tags": self.tags
        }

        if self.event_type == "flow":
            event_dict.update({
                "bytes_toserver": self.bytes_toserver,
                "bytes_toclient": self.bytes_toclient
            })
        elif self.event_type == "alert":
            event_dict.update({
                "signature": self.signature,
                "severity": self.severity
            })

        return event_dict

    @staticmethod
    async def save_to_elasticsearch(event: 'EventModel', username: str):
        """Save an Event object to Elasticsearch."""
        es = Elasticsearch(
            [{'host': 'localhost', 'port': 9200, 'scheme': 'http'}],
            http_auth=('elastic', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        )
        index = f"{datetime.now().strftime('%Y_%m')}_events"

        try:
            # Save event to Elasticsearch with device_id as username
            event_data = event.to_dict()
            event_data["device_id"] = username  # Add device_id as username
            es.index(index=index, body=event_data)

        except Exception as e:
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)

    @staticmethod
    async def load_from_elasticsearch_with_time_range(username: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Load Events from Elasticsearch and return a list of event dictionaries."""
        es = Elasticsearch(
            [{'host': 'localhost', 'port': 9200, 'scheme': 'http'}],
            http_auth=('elastic', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        )
        index = f"{datetime.now().strftime('%Y_%m')}_events"
        result = []

        try:
            # Query Elasticsearch
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            },
                            {
                                "term": {
                                    "device_id": username  # Filter by device_id which is username
                                }
                            }
                        ]
                    }
                },
                "size": 10000
            }

            response = es.search(index=index, body=query)
            hits = response['hits']['hits']

            for hit in hits:
                result.append(hit['_source'])

            return result

        except Exception as e:
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)
