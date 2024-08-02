from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import logging

from app.models.user_db import UserModel
from app.ext.error import UserNotFoundError, AuthControllerError, InvalidPasswordError, UserExistedError, UserDisabledError, InvalidTokenError

# Load environment variables
load_dotenv()

# Initialize logging
logging.basicConfig(level=logging.INFO)

class AuthController:
    # Secret key for JWT encoding/decoding
    SECRET_KEY = os.getenv("SECRET_KEY")
    # Algorithm used for JWT encoding/decoding
    ALGORITHM = "HS256"
    # Token expiration time in minutes
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    # Password hashing context
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # OAuth2 scheme for token authentication
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """Verify the provided plain password against the hashed password."""
        logging.info(f"Verifying password for {plain_password}")
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        """Hash the provided password."""
        logging.info(f"Hashing password for {password}")
        return cls.pwd_context.hash(password)

    @classmethod
    def create_access_token(cls, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.
        
        Args:
            data (dict): Payload data for the token
            expires_delta (Optional[timedelta]): Token expiration time

        Returns:
            str: Encoded JWT token
        """
        logging.info(f"Creating access token for {data}")
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, cls.SECRET_KEY, algorithm=cls.ALGORITHM)

    @classmethod
    def create_user(cls, username: str, password: str):
        """
        Create a user in the database.
        """
        try:
            user = UserModel.get_user(username)
            if user:
                raise UserExistedError(f"User {username} already exists")
            else:
                hashed_password = cls.get_password_hash(password)
                UserModel.create_user(username, hashed_password)

        except UserExistedError as e:
            raise e
        except Exception as e:
            raise AuthControllerError(f"An error occurred: {e}")

    @classmethod
    def authenticate_user(cls, username: str, password: str):
        try:
            user = UserModel.get_user(username)

            if not user:
                print(f"DEBUG: User not found in DB: {username}")
                raise UserNotFoundError(f"User {username} not found")

            if not cls.verify_password(password, user.password):
                raise InvalidPasswordError(f"Invalid password for user {username}")
            
            if user.disabled:
                raise UserDisabledError(f"User {username} is disabled")

            access_token = cls.create_access_token(data={"sub": user.username})
            return {"access_token": access_token, "token_type": "bearer"}
           
        except UserNotFoundError as e:
            logging.error(f"User not found: {e}")
            raise e  
        except InvalidPasswordError as e:
            logging.error(f"Invalid password: {e}")
            raise e
        except UserDisabledError as e:
            raise e
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise AuthControllerError(f"An error occurred: {e}")

    @classmethod
    async def get_current_user(cls, token: str = Depends(oauth2_scheme)) -> 'UserModel':
        """Get the current user from the provided JWT token."""
        logging.info(f"Getting current user from token")

        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            username = payload.get("sub")

            if username is None:
                raise InvalidTokenError()

            user = UserModel.get_user(username)
            if user is None or user.disabled:
                raise InvalidTokenError()
            return user

        except JWTError:
            raise InvalidTokenError()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            raise AuthControllerError(f"An error occurred: {e}")
