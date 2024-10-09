# from datetime import datetime
# from typing import Optional, List, Dict
# from elasticsearch import Elasticsearch
# from elasticsearch.exceptions import NotFoundError
# import os
# from dotenv import load_dotenv, find_dotenv
# import logging

# from ..schemas.event import Event as EventSchema
# from ..ext.error import ElasticsearchError, UserNotFoundError

# # Load environment variables
# try:
#     load_dotenv(find_dotenv())
# except Exception as e:
#     logging.error(f"Error loading .env file: {str(e)}")
#     raise

# class EventModel:

#     def __init__(self, event_data: Dict):
#         self.timestamp = event_data.get("@timestamp", [None])[0]
#         self.deviceid = event_data.get("deviceid", [None])[0]
#         self.source_ip = event_data.get("source_ip", [None])[0]
#         self.destination_ip = event_data.get("destination_ip", [None])[0]
#         self.source_port = event_data.get("source_port", [None])[0]
#         self.destination_port = event_data.get("destination_port", [None])[0]
#         self.signature = event_data.get("signature", [None])[0]
#         self.severity = event_data.get("severity", [None])[0]
#         self.event_name = event_data.get("event_name", [None])[0]

#     def to_dict(self) -> Dict:
#         return {
#             "timestamp": self.timestamp,
#             "deviceid": self.deviceid,
#             "source_ip": self.source_ip,
#             "destination_ip": self.destination_ip,
#             "source_port": self.source_port,
#             "destination_port": self.destination_port,
#             "signature": self.signature,
#             "severity": self.severity,
#             "event_name": self.event_name,
#         }

#     @staticmethod
#     async def load_events_from_elasticsearch(start_time: datetime, end_time: datetime) -> List[Dict]:
#         try:
#             es = Elasticsearch(
#                 [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
#                 http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
#             )
#             index = os.getenv('ES_FLOWRING_INDEX')
            
#             query = {
#                 "query": {
#                     "bool": {
#                         "must": [
#                             {
#                                 "range": {
#                                     "@timestamp": {
#                                         "gte": start_time.isoformat(),
#                                         "lte": end_time.isoformat()
#                                     }
#                                 }
#                             },
#                             {
#                                 "term": {
#                                     "type.keyword": "flowring"
#                                 }
#                             }
#                         ]
#                     }
#                 },
#                 "size": 10000
#             }

#             response = es.search(index=index, body=query)
#             hits = response['hits']['hits']

#             return [hit['_source'] for hit in hits]
        
#         except Exception as e:
#             logging.error(f"Elasticsearch error while loading flowring events: {str(e)}")
#             raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)





#     # @staticmethod
#     # async def save_to_elasticsearch(event: 'EventModel', username: str):
#     #     """Save an Event object to Elasticsearch."""
#     #     try:
#     #         es = Elasticsearch(
#     #             [{'host': os.getenv('ES_HOST'), 'port': int(os.getenv('ES_PORT')), 'scheme': os.getenv('ES_SCHEME')}],
#     #             http_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD'))
#     #         )
#     #         index = f"{datetime.now().strftime('%Y_%m')}_events"

#     #         # Save event to Elasticsearch with device_id as username
#     #         event_data = event.to_dict()
#     #         event_data["device_id"] = username  # Add device_id as username
#     #         es.index(index=index, body=event_data)

#     #     except Exception as e:
#     #         logging.error(f"Elasticsearch error while saving event: {str(e)}")
#     #         raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)
