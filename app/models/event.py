from datetime import datetime
from typing import Optional, List, Dict
import json
import os

from ..schemas.event import Event as EventSchema  # new
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
    async def save_to_json(event:'EventModel', user_id: str, filename="app/example_data2.json"):
        """Save an Event object to a JSON file, updating existing data."""
        try:
          # Read existing data
          with open(filename, 'r') as f:
              datas = json.load(f)
          
          # Update data
          if datas.get(user_id) is not None:
              print("user_account: ", datas[user_id]['user_account'])
              print("user data length: ", len(datas[user_id]['datas']))
              datas[user_id]['datas'].append(event.to_dict())
                  
          else:
              raise NotFoundUserError(f"User ID {user_id} not found in the data", 404)
          
          with open(filename, 'w') as f:
              json.dump(datas, f, indent=2)

        except NotFoundUserError as e:
            raise e
        except Exception as e:
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)


    @staticmethod
    async def load_from_json_with_time_range(user_id: str, start_time: datetime, end_time: datetime, filename="app/example_data2.json") -> List['Event']:
        """Load Events from a JSON file and return a list of Event objects."""
        
        try:
            # Replace with Elasticsearch
            with open(filename, 'r') as f:
                datas = json.load(f)

            result = []
            if datas.get(user_id) is not None:
              for data in datas[user_id]['datas']:
                timestamp_dt = datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z")
                formatted_timestamp = timestamp_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4]
                final_datetime = datetime.strptime(formatted_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
                  
                if final_datetime >= start_time and final_datetime <= end_time:
                    result.append(data)
            else:
              raise NotFoundUserError(f"User ID {user_id} not found in the data", 404)
                
            return result

        except NotFoundUserError as e:
            raise e
        except Exception as e:
            raise ElasticsearchError(f"Elasticsearch error: {str(e)}", 500)
