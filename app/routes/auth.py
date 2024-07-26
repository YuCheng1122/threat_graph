from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import logging
import os

from ..utils.auth import Token, AuthManager, get_current_user, get_current_active_user, User


router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    logging.info(f"Attempting to login user: {form_data.username}")
    user = AuthManager.authenticate_user(AuthManager.fake_users_db, form_data.username, form_data.password)
    if not user:
        logging.error("Authentication failed for user: %s", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = AuthManager.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logging.info(f"Access token created for user: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    logging.info(f"Reading user: {current_user.username}")
    return current_user
