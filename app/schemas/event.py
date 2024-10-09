from pydantic import BaseModel
from typing import List, Dict

class NodeAttributes(BaseModel):
    tags: List[str]

class Node(BaseModel):
    id: str
    attributes: NodeAttributes

class EdgeAttributes(BaseModel):
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: float
    dest_port: float
    count: int
    flow: Dict[str, int]
    event_type: str

class Edge(BaseModel):
    source: str
    target: str
    attributes: EdgeAttributes

class GraphData(BaseModel):
    nodes: List[Node]
    edges: List[Edge]