from datetime import datetime
from typing import Optional, List, Dict
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
import os
from dotenv import load_dotenv, find_dotenv
import logging

from ..schemas.event import Event as EventSchema
from ..ext.error import ElasticsearchError, UserNotFoundError

# Set up logging
logging.basicConfig(level=logging.DEBUG, filename='app_errors.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
try:
    load_dotenv(find_dotenv())
except Exception as e:
    logging.error(f"Error loading .env file: {str(e)}")
    raise

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
        try:
            es = Elasticsearch(
                [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
                http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
            )
            index = f"{datetime.now().strftime('%Y_%m')}_events"

            # Save event to Elasticsearch with device_id as username
            event_data = event.to_dict()
            event_data["device_id"] = username  # Add device_id as username
            es.index(index=index, body=event_data)

        except Exception as e:
            logging.error(f"Elasticsearch error while saving event: {str(e)}")
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)

    @staticmethod
    async def load_group_events_from_elasticsearch(group: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        try:
            es = Elasticsearch(
                [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
                http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
            )
            index = f"{datetime.now().strftime('%Y_%m')}_agents_data"
            result = []

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
                                    "group": group
                                }
                            },
                            {
                                "term": {
                                    "wazuh_data_type": "wazuh_events"
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
            logging.error(f"Elasticsearch error while loading group events: {str(e)}")
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)

