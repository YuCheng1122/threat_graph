from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import FastAPI, Request, HTTPException, status
from jose import JWTError, jwt
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.secret_key = os.getenv("SECRET_KEY")
        self.algorithm = "HS256"

    async def dispatch(self, request: Request, call_next):
        excluded_paths = ["/api/auth/", "/", "/static"]
        if any(request.url.path.startswith(path) for path in excluded_paths):
            logging.info(f"Excluding path: {request.url.path}")
            return await call_next(request)

        token = request.headers.get("Authorization")
        if token is None:
            logging.info("No Authorization header found")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated")

        try:
            payload = jwt.decode(token.split(" ")[1], self.secret_key, algorithms=[self.algorithm])
            request.state.user = payload.get("sub")
        except JWTError as e:
            logging.error(f"JWT error: {e}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials")

        return await call_next(request)
