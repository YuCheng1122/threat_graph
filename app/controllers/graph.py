from app.models.event_db import EventModel
from datetime import datetime
from app.ext.error import GraphControllerError, ElasticsearchError

class GraphController:

    @staticmethod
    async def get_graph_data(start_time: datetime, end_time: datetime, username: str):
        try:
            datas = await EventModel.load_group_events_from_elasticsearch(group=username, start_time=start_time, end_time=end_time)

            stage_ip = {}
            nodes = []
            edges = []

            for data in datas:
                source = data['src_ip']
                target = data['dest_ip']
                
                if stage_ip.get(source) is None:
                    stage_ip[source] = True
                    nodes.append({
                        'id': source,
                        'attributes': data['tags']['src_ip']
                    })

                if stage_ip.get(target) is None:
                    stage_ip[target] = True
                    nodes.append({
                        'id': target,
                        'attributes': data['tags']['dest_ip']
                    })
                
                data.pop('tags', None)
                edges.append({
                    'source': source,
                    'target': target,
                    'attributes': data
                })

            result = {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'nodes': nodes,
                'edges': edges
            }

            return result
        
        except NotFoundUserError as e:
            raise e
        
        except ElasticsearchError as e:
            raise e
        
        except Exception as e:
            raise GraphControllerError(f"GraphController error: {str(e)}", 500)

    @staticmethod
    async def save_flow_data(event, device_id: str):
        # Validate event data
        if not event or not device_id:
            raise GraphControllerError("Missing event data or device ID", 400)

        try:
            event_model = EventModel(event)
            await EventModel.save_to_elasticsearch(event=event_model, username=device_id)
        
        except NotFoundUserError as e:
            raise e
        
        except ElasticsearchError as e:
            raise e
        
        except Exception as e:
            raise GraphControllerError(f"GraphController error: {str(e)}", 500)

    @staticmethod
    async def save_alert_data(event, device_id: str):
        # Validate event data
        if not event or not device_id:
            raise GraphControllerError("Missing event data or device ID", 400)
        
        try:
            event_model = EventModel(event)
            await EventModel.save_to_elasticsearch(event=event_model, username=device_id)
        
        except NotFoundUserError as e:
            raise e
        
        except ElasticsearchError as e:
            raise e
        
        except Exception as e:
            raise GraphControllerError(f"GraphController error: {str(e)}", 500)
