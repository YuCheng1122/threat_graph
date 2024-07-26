from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from datetime import datetime
import logging

from app.schemas.event import Event as EventSchema  
from app.controllers.graph import GraphController 
from app.ext.error import RequestParamsError
from app.controllers.auth import AuthController
from app.models.user import UserModel

router = APIRouter()


@router.post("/data/")
async def receive_traffic_and_alert_date(event: EventSchema, current_user: UserModel = Depends(AuthController.get_current_user)):
    '''
        Receives and stores alert or traffic event data.
    '''
    if event.event_type == "alert":
        await GraphController.save_alert_data(event=event, username=current_user.username)
    elif event.event_type == "flow":
        await GraphController.save_flow_data(event=event, username=current_user.username)
    return JSONResponse(status_code=200, content={'success': True, "message": "Event stored successfully"})


@router.get("/graph_data")
async def get_traffic_data(start_time: datetime = Query(...), end_time: datetime = Query(...), current_user: UserModel = Depends(AuthController.get_current_user)):
    '''
        Get graph data for a given time range.
    '''
    graph_data = await GraphController.get_graph_data(start_time=start_time, end_time=end_time, username=current_user.username)
    return JSONResponse(status_code=200, content={'success': True, 'content': graph_data})


