from datetime import datetime
from typing import Dict, List
from elasticsearch import Elasticsearch
from app.schemas.rds import RDSEvent, RDSDetectionRequest
from app.ext.error import ElasticsearchError
from logging import getLogger
from functools import wraps
import os
from dotenv import load_dotenv, find_dotenv

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables
try:
    load_dotenv(find_dotenv())
except Exception as e:
    logger.error(f"Error loading .env file: {str(e)}")
    raise

# Create Elasticsearch instance
es = Elasticsearch(
    [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
    http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
)

def get_index_name():
    """Get the index name for the current month."""
    return f"{datetime.now().strftime('%Y_%m')}_rds_data"

def create_index_with_mapping():
    """Create an Elasticsearch index with the appropriate mapping for RDS data."""
    index_name = get_index_name()
    if not es.indices.exists(index=index_name):
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "account": {"type": "keyword"},
                    "edge_name": {"type": "keyword"},
                    "edge_ip": {"type": "ip"},
                    "edge_mac": {"type": "keyword"},
                    "edge_os": {"type": "keyword"},
                    "edge_ssid": {"type": "keyword"},
                    "edge_dns_gateway": {"type": "ip"},
                    "tag_id": {"type": "keyword"},
                    "tag": {"type": "keyword"},
                    "file_hash": {"type": "keyword"},
                    "file_name": {"type": "keyword"},
                    "file_path": {"type": "keyword"},
                    "score": {"type": "keyword"},
                    "data_type": {"type": "keyword"}
                }
            }
        }
        try:
            es.indices.create(index=index_name, body=mapping)
        except Exception as e:
            logger.error(f"Error creating index {index_name}: {str(e)}")
            raise ElasticsearchError(f"Error creating index: {str(e)}")
    return index_name

def handle_es_exceptions(func):
    """Decorator to handle Elasticsearch exceptions."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Elasticsearch error in {func.__name__}: {str(e)}")
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}")
    return wrapper

class RDSModel:
    """Model for handling RDS detection data in Elasticsearch."""
    
    def __init__(self, detection: RDSDetectionRequest, event: RDSEvent):
        self.timestamp = event.timestamp
        self.account = detection.account
        self.edge_name = detection.edge_name
        self.edge_ip = detection.edge_ip
        self.edge_mac = detection.edge_mac
        self.edge_os = detection.edge_os
        self.edge_ssid = detection.edge_ssid
        self.edge_dns_gateway = detection.edge_dns_gateway
        self.tag_id = event.tag_id
        self.tag = event.tag
        self.file_hash = event.file_hash
        self.file_name = event.file_name
        self.file_path = event.file_path
        self.score = event.score
        self.data_type = "rds_detection"

    def to_dict(self) -> Dict:
        """Convert the model instance to a dictionary for Elasticsearch."""
        return {
            "timestamp": [self.timestamp.isoformat()],
            "account": [self.account],
            "edge_name": [self.edge_name],
            "edge_ip": [self.edge_ip],
            "edge_mac": [self.edge_mac],
            "edge_os": [self.edge_os],
            "edge_ssid": [self.edge_ssid],
            "edge_dns_gateway": [self.edge_dns_gateway],
            "tag_id": [self.tag_id],
            "tag": [self.tag],
            "file_hash": [self.file_hash],
            "file_name": [self.file_name],
            "file_path": [self.file_path],
            "score": [self.score],
            "data_type": [self.data_type]
        }

    @staticmethod
    def format_es_doc(doc: Dict) -> Dict:
        """Format Elasticsearch document by taking first value from arrays."""
        return {
            "timestamp": doc["timestamp"][0] if isinstance(doc["timestamp"], list) else doc["timestamp"],
            "account": doc["account"][0] if isinstance(doc["account"], list) else doc["account"],
            "edge_name": doc["edge_name"][0] if isinstance(doc["edge_name"], list) else doc["edge_name"],
            "edge_ip": doc["edge_ip"][0] if isinstance(doc["edge_ip"], list) else doc["edge_ip"],
            "edge_mac": doc["edge_mac"][0] if isinstance(doc["edge_mac"], list) else doc["edge_mac"],
            "edge_os": doc["edge_os"][0] if isinstance(doc["edge_os"], list) else doc["edge_os"],
            "edge_ssid": doc["edge_ssid"][0] if isinstance(doc["edge_ssid"], list) else doc["edge_ssid"],
            "edge_dns_gateway": doc["edge_dns_gateway"][0] if isinstance(doc["edge_dns_gateway"], list) else doc["edge_dns_gateway"],
            "tag_id": doc["tag_id"][0] if isinstance(doc["tag_id"], list) else doc["tag_id"],
            "tag": doc["tag"][0] if isinstance(doc["tag"], list) else doc["tag"],
            "file_hash": doc["file_hash"][0] if isinstance(doc["file_hash"], list) else doc["file_hash"],
            "file_name": doc["file_name"][0] if isinstance(doc["file_name"], list) else doc["file_name"],
            "file_path": doc["file_path"][0] if isinstance(doc["file_path"], list) else doc["file_path"],
            "score": doc["score"][0] if isinstance(doc["score"], list) else doc["score"],
            "data_type": doc["data_type"][0] if isinstance(doc["data_type"], list) else doc["data_type"]
        }

    @staticmethod
    @handle_es_exceptions
    async def save_detection(detection: RDSDetectionRequest) -> int:
        """Save RDS detection events to Elasticsearch."""
        index_name = create_index_with_mapping()
        events_saved = 0

        try:
            for event in detection.event:
                rds_model = RDSModel(detection, event)
                es.index(index=index_name, body=rds_model.to_dict())
                events_saved += 1
            
            logger.info(f"Successfully saved {events_saved} RDS detection events")
            return events_saved
        except Exception as e:
            logger.error(f"Error saving RDS detection events: {str(e)}")
            raise ElasticsearchError(f"Error saving events: {str(e)}")

    @staticmethod
    @handle_es_exceptions
    async def get_detections(start_time: datetime, end_time: datetime, account: str = None) -> List[Dict]:
        """Retrieve RDS detections within a time range, optionally filtered by account."""
        query = {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "data_type": ["rds_detection"]
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    }
                ]
            }
        }

        if account:
            query["bool"]["must"].append({
                "terms": {
                    "account": [account]
                }
            })

        try:
            result = es.search(
                index=get_index_name(),
                body={
                    "query": query,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": 10000
                }
            )
            # Format the documents to handle array values
            return [RDSModel.format_es_doc(hit["_source"]) for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error retrieving RDS detections: {str(e)}")
            raise ElasticsearchError(f"Error retrieving detections: {str(e)}")
