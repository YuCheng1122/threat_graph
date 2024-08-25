class BaseCustomError(Exception):
    """Base class for custom errors"""
    def __init__(self, message: str, status_code: int):
        self.message = message
        self.status_code = status_code
        self.success = False
        self.content = None
        super().__init__(self.message)

    def to_dict(self):
        return {
            "success": self.success,
            "content": self.content,
            "message": self.message
        }

class HTTPError(BaseCustomError):
    """Base class for HTTP errors"""
    pass

class BadRequestError(HTTPError):
    """400 Bad Request"""
    def __init__(self, message: str = "Bad Request"):
        super().__init__(message, 400)

class UnauthorizedError(HTTPError):
    """401 Unauthorized"""
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, 401)

class ForbiddenError(HTTPError):
    """403 Forbidden"""
    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, 403)

class NotFoundError(HTTPError):
    """404 Not Found"""
    def __init__(self, message: str = "Not Found"):
        super().__init__(message, 404)

class MethodNotAllowedError(HTTPError):
    """405 Method Not Allowed"""
    def __init__(self, message: str = "Method Not Allowed"):
        super().__init__(message, 405)

class ConflictError(HTTPError):
    """409 Conflict"""
    def __init__(self, message: str = "Conflict"):
        super().__init__(message, 409)

class UnsupportedMediaTypeError(HTTPError):
    """415 Unsupported Media Type"""
    def __init__(self, message: str = "Unsupported Media Type"):
        super().__init__(message, 415)

class UnprocessableEntityError(HTTPError):
    """422 Unprocessable Entity"""
    def __init__(self, message: str = "Unprocessable Entity"):
        super().__init__(message, 422)

class InternalServerError(HTTPError):
    """500 Internal Server Error"""
    def __init__(self, message: str = "Internal Server Error"):
        super().__init__(message, 500)
        
class CustomElasticsearchError(HTTPError):
    """500 Internal Server Error"""
    def __init__(self, message: str = "Elasticsearch error message here"):
        super().__init__(message, 500)

# Data Processing Errors

class GraphControllerError(BaseCustomError):
    """Raised when there's an error processing graph data"""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message, status_code)

class ElasticsearchError(BaseCustomError):
    """Raised when there's an error with Elasticsearch operations"""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message, status_code)

# User-related Errors

class UserNotFoundError(BaseCustomError):
    """Raised when a user cannot be found in Elasticsearch"""
    def __init__(self, message: str = "User not found", status_code: int = 404):
        super().__init__(message, status_code)

class UserExistedError(BaseCustomError):
    """Raised when attempting to create a user that already exists"""
    def __init__(self, message: str = "User already exists", status_code: int = 400):
        super().__init__(message, status_code)

class UserDisabledError(BaseCustomError):
    """Raised when a disabled user attempts to perform an action"""
    def __init__(self, message: str = "User account is disabled", status_code: int = 403):
        super().__init__(message, status_code)

# Request Errors

class GraphDataRequestParamsError(BaseCustomError):
    """Raised when there's an error with request parameters for graph data"""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message, status_code)

class RequestParamsError(BaseCustomError):
    """Raised when there's a general error with request parameters"""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message, status_code)

# Authentication and Authorization Errors

class AuthControllerError(BaseCustomError):
    """Raised when there's an error processing authentication data"""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message, status_code)

class InvalidPasswordError(BaseCustomError):
    """Raised when an invalid password is provided"""
    def __init__(self, message: str = "Invalid password", status_code: int = 401):
        super().__init__(message, status_code)

class InvalidTokenError(BaseCustomError):
    """Raised when an invalid token is provided"""
    def __init__(self, message: str = "Invalid token", status_code: int = 401):
        super().__init__(message, status_code)

class PermissionError(BaseCustomError):
    """Raised when a user doesn't have permission to perform an action"""
    def __init__(self, message: str = "Permission denied", status_code: int = 403):
        super().__init__(message, status_code)

class UnauthorizedError(BaseCustomError):
    """Raised when a user attempts to access or modify data they're not authorized for"""
    def __init__(self, message: str = "Unauthorized access", status_code: int = 403):
        super().__init__(message, status_code)