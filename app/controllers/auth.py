import os
from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from app.models.user_db import UserModel as DBUserModel
from app.ext.error import UserNotFoundError, AuthControllerError, InvalidPasswordError, UserExistedError, UserDisabledError, InvalidTokenError, PermissionError
from logging import getLogger

# Get the centralized logger
logger = getLogger('app_logger')

class AuthController:
    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return cls.pwd_context.hash(password)

    @classmethod    
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        result = cls.pwd_context.verify(plain_password, hashed_password)
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return cls.pwd_context.hash(password)

    @classmethod
    def create_access_token(cls, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, cls.SECRET_KEY, algorithm=cls.ALGORITHM)

    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Dict:
        try:
            user = DBUserModel.get_user_by_username(username)
            if not user:
                raise UserNotFoundError("User not found")
            if user.disabled == 1:
                raise UserDisabledError("User is disabled")
            if not cls.verify_password(password, user.password):
                raise InvalidPasswordError("Incorrect password")
            access_token = cls.create_access_token(data={"sub": user.username})
            return {"access_token": access_token, "token_type": "bearer"}
        except (UserNotFoundError, InvalidPasswordError, UserDisabledError):
            raise
        except Exception as e:
            raise

    @classmethod
    async def get_current_user(cls, token: str = Depends(oauth2_scheme)) -> DBUserModel:
        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise InvalidTokenError()
            user = DBUserModel.get_user_by_username(username)
            if user is None or user.disabled == 1:
                raise InvalidTokenError()
            return user
        except JWTError:
            raise InvalidTokenError()
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise AuthControllerError(f"Token validation error: {str(e)}")

    @classmethod
    def create_user_signup(cls, username: str, password: str, email: str, company_name: str) -> None:
        try:
            existing_active_user = DBUserModel.get_active_user(username, email)
            if existing_active_user:
                raise UserExistedError("An active user with this username or email already exists")

            existing_any_user = DBUserModel.get_any_user(username, email)
            if existing_any_user:
                raise UserExistedError("A user with this username or email already exists but is not active")

            hashed_password = cls.get_password_hash(password)
            new_user = {
                'username': username,
                'password': hashed_password,
                'email': email,
                'company_name': company_name,
                'disabled': 1  
            }
            DBUserModel.create_user_signup(**new_user)
        except UserExistedError:
            raise
        except Exception as e:
            logger.error(f"User creation error: {str(e)}")
            raise AuthControllerError(f"Error creating user: {str(e)}")

    @staticmethod
    async def check_user_permission(user: DBUserModel, group_name: str) -> None:
        if user.disabled == 1:
            raise PermissionError("User account is disabled")
        if user.user_role == 'admin':
            return
        has_permission = DBUserModel.check_user_group(user.id, group_name)
        if not has_permission:
            raise PermissionError("Permission denied")