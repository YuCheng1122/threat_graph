from pydantic import BaseModel, Field
from typing import Optional, List

class NodeAttributes(BaseModel):
    abnormal_score: Optional[int] = Field(None, description="Abnormal score of the node", example=85)
    symbol: Optional[str] = Field(None, description="Symbol type of the node", example="triangle")
    ip_type: str = Field(..., description="Type of the IP (internal/external)", example="external")
    os: Optional[str] = Field(None, description="Operating system information", example="No info")
    abnormal_count: Optional[str] = Field(None, description="Abnormal count information", example="No info")
    id_node: str = Field(..., description="Node ID", example="54adef7f2d5c")
    timestamp: str = Field(..., description="Timestamp of the node data", example="2024-07-22T06:04:53.613000")
    ip: str = Field(..., description="IP address of the node", example="142.251.42.246")

class Node(BaseModel):
    id: str = Field(..., description="Node ID", example="142.251.42.246")
    attributes: NodeAttributes = Field(..., description="Attributes of the node")

class EdgeAttributes(BaseModel):
    timestamp: str = Field(..., description="Timestamp of the edge data", example="2024-07-22T06:12:31.512000")
    source_ip: str = Field(..., description="Source IP address", example="192.168.65.137")
    dest_ip: str = Field(..., description="Destination IP address", example="142.251.42.246")
    source_port: int = Field(..., description="Source port number", example=52002)
    dest_port: int = Field(..., description="Destination port number", example=443)
    count: int = Field(..., description="Count of connections", example=5)
    flow_bytes_toclient: Optional[int] = Field(None, description="Bytes flow to client", example=7194)
    flow_bytes_toserver: Optional[int] = Field(None, description="Bytes flow to server", example=2004)

class Edge(BaseModel):
    source: str = Field(..., description="Source node ID", example="192.168.65.137")
    target: str = Field(..., description="Target node ID", example="142.251.42.246")
    attributes: EdgeAttributes = Field(..., description="Attributes of the edge")

class GraphData(BaseModel):
    nodes: List[Node] = Field(..., description="List of nodes", example=[
        {
            "id": "142.251.42.246",
            "attributes": {
                "abnormal_score": None,
                "symbol": None,
                "ip_type": "external",
                "os": "No info",
                "abnormal_count": "No info",
                "id_node": "54adef7f2d5c",
                "timestamp": "2024-07-22T06:04:53.613000",
                "ip": "142.251.42.246"
            }
        },
        {
            "id": "172.217.163.34",
            "attributes": {
                "abnormal_score": None,
                "symbol": None,
                "ip_type": "external",
                "os": "No info",
                "abnormal_count": "No info",
                "id_node": "54adef7f2d5c",
                "timestamp": "2024-07-22T06:05:00.230000",
                "ip": "172.217.163.34"
            }
        },
        {
            "id": "192.168.65.137",
            "attributes": {
                "abnormal_score": 85,
                "symbol": "triangle",
                "ip_type": "internal",
                "os": "Linux",
                "abnormal_count": 5,
                "id_node": "internal_node_01",
                "timestamp": "2024-07-22T06:04:00.000000",
                "ip": "192.168.65.137"
            }
        }
    ])
    edges: List[Edge] = Field(..., description="List of edges", example=[
        {
            "source": "192.168.65.137",
            "target": "142.251.42.246",
            "attributes": {
                "timestamp": "2024-07-22T06:12:31.512000",
                "source_ip": "192.168.65.137",
                "dest_ip": "142.251.42.246",
                "source_port": 52002,
                "dest_port": 443,
                "count": 5,
                "flow_bytes_toclient": 7194,
                "flow_bytes_toserver": 2004
            }
        },
        {
            "source": "192.168.65.137",
            "target": "172.217.163.34",
            "attributes": {
                "timestamp": "2024-07-22T06:12:38.206000",
                "source_ip": "192.168.65.137",
                "dest_ip": "172.217.163.34",
                "source_port": 51998,
                "dest_port": 443,
                "count": 6,
                "flow_bytes_toclient": 2899,
                "flow_bytes_toserver": 3658
            }
        }
    ])
