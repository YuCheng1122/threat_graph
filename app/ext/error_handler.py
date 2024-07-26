from fastapi import Request
from fastapi.responses import JSONResponse
from app.ext.error import GraphControllerError, NotFoundUserError, ElasticsearchError, RequestParamsError

async def graph_controller_error_handler(request: Request, exc: GraphControllerError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def not_found_user_error_handler(request: Request, exc: NotFoundUserError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def elasticsearch_error_handler(request: Request, exc: ElasticsearchError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def request_params_error_handler(request: Request, exc: RequestParamsError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

