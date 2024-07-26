from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from datetime import datetime
import logging

from app.schemas.node import Node as NodeSchema
from app.schemas.edge import Edge as EdgeSchema
from app.schemas.graphdata import GraphData
from app.models.node import Node
from app.models.edge import Edge
from app.utils.auth import get_current_active_user, User

from app.schemas.event import Event as EventSchema  # new
from app.controllers.graph import GraphController # new
from app.ext.error import RequestParamsError

router = APIRouter()

@router.get("/get_hourly_graphs", response_model=GraphData)
async def get_hourly_graphs(
    start_time: datetime, 
    end_time: datetime, 
    current_user: User = Depends(get_current_active_user)
):
    """Retrieve nodes and edges within the given time range."""
    nodes = Node.get_nodes_by_time_range(start_time, end_time)
    edges = Edge.get_edges_by_time_range(start_time, end_time)
    return {"nodes": nodes, "edges": edges}

@router.post("/node/", response_model=dict)
async def create_node(
    node: NodeSchema, 
    current_user: User = Depends(get_current_active_user)
):
    """Create a new node."""
    try:
        Node.save(node.dict())
        return {"status": "node created"}
    except Exception as e:
        logging.error(f"Error in create_node: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/edge/", response_model=dict)
async def create_edge(
    edge: EdgeSchema, 
    current_user: User = Depends(get_current_active_user)
):
    """Create a new edge."""
    try:
        Edge.save(edge.dict())
        return {"status": "edge created"}
    except Exception as e:
        logging.error(f"Error in create_edge: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

# Additional functions can be added here
@router.get("/nodes", response_model=list[NodeSchema])
async def get_all_nodes(current_user: User = Depends(get_current_active_user)):
    """Retrieve all nodes."""
    try:
        nodes = Node.get_all_nodes()
        return nodes
    except Exception as e:
        logging.error(f"Error in get_all_nodes: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/edges", response_model=list[EdgeSchema])
async def get_all_edges(current_user: User = Depends(get_current_active_user)):
    """Retrieve all edges."""
    try:
        edges = Edge.get_all_edges()
        return edges
    except Exception as e:
        logging.error(f"Error in get_all_edges: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

#----------------------------------------------------------------------------------------------------


@router.post("/data/")
async def receive_traffic_and_alert_date(event: EventSchema, current_user = {"user_id": "1", "user_account": "user1@example.com"}):
    '''
        Receives and stores alert or traffic event data.
    '''
    if event.event_type == "alert":
        await GraphController.save_alert_data(event=event, user_id=current_user['user_id'])
    elif event.event_type == "flow":
        await GraphController.save_flow_data(event=event, user_id=current_user['user_id'])
    return JSONResponse(success=True, status_code=200, content={"message": "Event stored successfully"})


@router.get("/graph_data")
async def get_traffic_data(start_time: datetime = Query(...), end_time: datetime = Query(...), current_user = {"user_id": "1", "user_account": "user1@example.com"}):
    '''
        Get graph data for a given time range.
    '''
    graph_data = await GraphController.get_graph_data(start_time=start_time, end_time=end_time, user_id=current_user['user_id'])
    return JSONResponse(success=True, status_code=200, content=graph_data)


