from datetime import datetime
# from app.schemas.graph_data import GraphData, Node, Edge, NodeAttributes, EdgeAttributes
# from app.models.elasticsearch import ElasticsearchModel


class GraphController:
    @staticmethod
    async def get_graph_data(start_time: datetime, end_time: datetime, device_id: str):
        
        pass
        # es_data = await ElasticsearchModel.get_graph_data(start_time, end_time, device_id)
        
        # nodes = {}
        # edges = []

        # for item in es_data:
        #     source_ip = item['source_ip']
        #     dest_ip = item['dest_ip']

        #     if source_ip not in nodes:
        #         nodes[source_ip] = Node(
        #             id=source_ip,
        #             attributes=NodeAttributes(tags=item.get('source_tags', []))
        #         )

        #     if dest_ip not in nodes:
        #         nodes[dest_ip] = Node(
        #             id=dest_ip,
        #             attributes=NodeAttributes(tags=item.get('dest_tags', []))
        #         )

        #     edges.append(Edge(
        #         source=source_ip,
        #         target=dest_ip,
        #         attributes=EdgeAttributes(
        #             timestamp=item['timestamp'],
        #             source_ip=source_ip,
        #             dest_ip=dest_ip,
        #             source_port=item['source_port'],
        #             dest_port=item['dest_port'],
        #             count=item['count'],
        #             flow=item['flow'],
        #             event_type=item['event_type']
        #         )
        #     ))

        # return GraphData(nodes=list(nodes.values()), edges=edges)