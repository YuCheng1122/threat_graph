from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from app.ext.error import (
    GraphControllerError, NotFoundUserError, ElasticsearchError, RequestParamsError,
    UserNotFoundError, AuthControllerError, InvalidPasswordError, UserExistedError,
    UserDisabledError, InvalidTokenError, UnauthorizedError, BaseCustomError
)

async def custom_error_handler(request: Request, exc: Exception):
    if isinstance(exc, (GraphControllerError, NotFoundUserError, ElasticsearchError, RequestParamsError,
                        UserNotFoundError, AuthControllerError, InvalidPasswordError, UserExistedError,
                        UserDisabledError, InvalidTokenError, UnauthorizedError, PermissionError)):
        return JSONResponse(
            status_code=exc.status_code,
            content={"success": False, "message": exc.message}
        )
    # General exception handler
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "An unexpected error occurred."}
    )

async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "An unexpected error occurred."}
    )

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


def add_error_handlers(app: FastAPI):
    app.add_exception_handler(GraphControllerError, graph_controller_error_handler)
    app.add_exception_handler(NotFoundUserError, not_found_user_error_handler)
    app.add_exception_handler(ElasticsearchError, elasticsearch_error_handler)
    app.add_exception_handler(RequestParamsError, request_params_error_handler)
    app.add_exception_handler(UserNotFoundError, user_not_found_error_handler)
    app.add_exception_handler(AuthControllerError, auth_controller_error_handler)
    app.add_exception_handler(InvalidPasswordError, invalid_password_error_handler)
    app.add_exception_handler(UserExistedError, user_existed_error_handler)
    app.add_exception_handler(UserDisabledError, user_disabled_error_handler)
    app.add_exception_handler(InvalidTokenError, invalid_token_error_handler)
    app.add_exception_handler(UnauthorizedError, unauthorized_error_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
# ----------------------------------------------------------------------------------------------------------- Wazuh 

async def unauthorized_error_handler(request: Request, exc: UnauthorizedError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "message": exc.message}
    )