from fastapi import Request, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from .error import * 
from typing import Union, Type

# Create a mapping of status codes to error classes
ERROR_CLASS_MAP: dict[int, Type[BaseCustomError]] = {
    400: BadRequestError,
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
    405: MethodNotAllowedError,
    409: ConflictError,
    415: UnsupportedMediaTypeError,
    422: UnprocessableEntityError,
    500: InternalServerError,
}

def get_error_class(status_code: int) -> Type[BaseCustomError]:
    return ERROR_CLASS_MAP.get(status_code, HTTPError)

async def custom_error_handler(request: Request, exc: Exception):
    if isinstance(exc, BaseCustomError):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict()
        )
    # General exception handler
    return JSONResponse(
        status_code=500,
        content=InternalServerError().to_dict()
    )

async def http_exception_handler(request: Request, exc: HTTPException):
    error_class = get_error_class(exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_class(str(exc.detail)).to_dict()
    )

async def validation_exception_handler(request: Request, exc: Union[RequestValidationError, ValidationError]):
    return JSONResponse(
        status_code=422,
        content=UnprocessableEntityError("Unprocessable Entity").to_dict()
    )

def add_error_handlers(app: FastAPI):
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, custom_error_handler)

    # Add specific handlers for custom error classes
    for error_class in BaseCustomError.__subclasses__():
        app.add_exception_handler(
            error_class,
            lambda request, exc: JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        )

    # Add handlers for specific status codes
    for status_code, error_class in ERROR_CLASS_MAP.items():
        app.add_exception_handler(
            status_code,
            lambda request, exc, sc=status_code: JSONResponse(
                status_code=sc,
                content=get_error_class(sc)().to_dict()
            )
        )