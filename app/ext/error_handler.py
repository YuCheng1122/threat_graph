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


# -----------------------------------------------------------------------------------------------------------

from app.ext.error import UserNotFoundError, AuthControllerError, InvalidPasswordError, UserExistedError, UserDisabledError, InvalidTokenError


async def user_not_found_error_handler(request: Request, exc: UserNotFoundError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def auth_controller_error_handler(request: Request, exc: AuthControllerError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def invalid_password_error_handler(request: Request, exc: InvalidPasswordError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def user_existed_error_handler(request: Request, exc: UserExistedError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def user_disabled_error_handler(request: Request, exc: UserDisabledError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})

async def invalid_token_error_handler(request: Request, exc: InvalidTokenError):
    return JSONResponse(status_code=exc.status_code, content={"success": False, "message": exc.message})



