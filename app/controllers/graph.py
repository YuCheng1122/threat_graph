from app.models.event import EventModel
from datetime import datetime
from app.ext.error import GraphControllerError, NotFoundUserError, ElasticsearchError

class GraphController:

    @staticmethod
    async def get_graph_data(start_time: datetime, end_time: datetime, user_id: str):

      try:
        datas = await EventModel.load_from_json_with_time_range(user_id=user_id, start_time=start_time, end_time=end_time)

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
          'start_time': start_time,
          'end_time': end_time,
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
    async def save_flow_data(event, user_id: str):
      # processing data
      # save data to database
      try:
          event_model = EventModel(event)
          await EventModel.save_to_json(event=event_model, user_id=user_id)

      except NotFoundUserError as e:
        raise e
      
      except ElasticsearchError as e:
        raise e
      
      except Exception as e:
        raise GraphControllerError(f"GraphController error: {str(e)}", 500)
            

    @staticmethod
    async def save_alert_data(event, user_id: str):
      # processing data
      # save data to database
      try:
      
        event_model = EventModel(event)
        await EventModel.save_to_json(event=event_model, user_id=user_id)

      except NotFoundUserError as e:
        raise e
      
      except ElasticsearchError as e:
        raise e
      
      except Exception as e:
        raise GraphControllerError(f"GraphController error: {str(e)}", 500)
