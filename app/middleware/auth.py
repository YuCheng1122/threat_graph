from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request, HTTPException, status
from jose import JWTError, jwt
import os
from dotenv import load_dotenv
import logging
from app.models.user_db import UserModel

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
handler = logging.handlers.RotatingFileHandler(
    'user_activity.log', maxBytes=10000, backupCount=3
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
activity_logger = logging.getLogger("user_activity")
activity_logger.addHandler(handler)

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.secret_key = os.getenv("SECRET_KEY")
        self.algorithm = "HS256"

    async def dispatch(self, request: Request, call_next):
        excluded_paths = ["/api/auth/", "/", "/static"]
        if any(request.url.path.startswith(path) for path in excluded_paths):
            activity_logger.info(f"Anonymous access to path: {request.url.path}")
            return await call_next(request)

        token = request.headers.get("Authorization")
        if token is None:
            activity_logger.warning(f"Unauthorized access attempt to {request.url.path}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated")

        try:
            payload = jwt.decode(token.split(" ")[1], self.secret_key, algorithms=[self.algorithm])
            user_id = payload.get("sub")
            username = payload.get("username")
            user_role = payload.get("role")
            disabled = payload.get("disabled", False)
            
            if not user_id or not username:
                logging.error(f"Invalid token payload: {payload}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")

            user = UserModel(id=user_id, username=username, user_role=user_role, disabled=disabled)
            print(f"DEBUG: User in AuthMiddleware - ID: {user.id}, Username: {user.username}, Role: {user.user_role}, Disabled: {user.disabled}")

            if user.disabled:
                logging.error(f"User is disabled: {username}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")

            logging.info(f"User authenticated: {username}, ID: {user_id}, Role: {user.user_role}")
            request.state.user = user
        except JWTError as e:
            logging.error(f"JWT Error: {str(e)}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")

        return await call_next(request)