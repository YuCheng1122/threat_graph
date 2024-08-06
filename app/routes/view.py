from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from datetime import datetime
import logging
import traceback

from app.schemas.event import Event as EventSchema
from app.controllers.graph import GraphController 
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
router = APIRouter()


@router.post("/data")
async def receive_traffic_and_alert_date(
    request: Request,
    event: EventSchema, 
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    '''
        Receives and stores alert or traffic event data.
    '''
    device_id = current_user.username  
    if event.event_type == "alert":
        await GraphController.save_alert_data(event=event, device_id=device_id)
    elif event.event_type == "flow":
        await GraphController.save_flow_data(event=event, device_id=device_id)
    return JSONResponse(status_code=200, content={'success': True, "message": "Event stored successfully"})


@router.get("/graph_data")
async def get_traffic_data(
    request: Request,
    start_time: datetime = Query(...), 
    end_time: datetime = Query(...), 
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    '''
        Get graph data for a given time range.
    '''
    try:
        # Log the received parameters
        logging.debug(f"Received parameters - start_time: {start_time}, end_time: {end_time}, username: {current_user.username}")

        # Validate the parameters
        if start_time >= end_time:
            logging.error("Validation error: start_time must be before end_time")
            raise HTTPException(status_code=400, detail="start_time must be before end_time")

        # Fetch graph data
        graph_data = await GraphController.get_graph_data(start_time=start_time, end_time=end_time, username=current_user.username)

        return JSONResponse(status_code=200, content={'success': True, 'content': graph_data})
    
    except HTTPException as e:
        print(traceback.format_exc())
        logging.error(f"HTTPException: {str(e)}")
        raise e
    except Exception as e:
        print(traceback.format_exc())
        logging.error(f"Unhandled exception: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")



