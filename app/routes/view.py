from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime
from app.controllers.graph import GraphController
from app.controllers.auth import AuthController
from app.models.user_db import UserModel
from app.schemas.event import GraphData


router = APIRouter()


@router.get("/graph_data", response_model=GraphData)
async def get_graph_data(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    try:
        graph_data = await GraphController.get_graph_data(start_time, end_time, current_user.device_id)
        return graph_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# @router.post("/data")
# async def receive_traffic_and_alert_date(
#     request: Request,
#     event: EventSchema, 
#     current_user: UserModel = Depends(AuthController.get_current_user)
# ):
#     '''
#         Receives and stores alert or traffic event data.
#     '''
#     device_id = current_user.username  
#     if event.event_type == "alert":
#         await GraphController.save_alert_data(event=event, device_id=device_id)
#     elif event.event_type == "flow":
#         await GraphController.save_flow_data(event=event, device_id=device_id)
#     return JSONResponse(status_code=200, content={'success': True, "message": "Event stored successfully"})





