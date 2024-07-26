from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.controllers.auth import AuthController
from app.schemas.user import UserRegister

router = APIRouter()

# 暫時使用 user name 作為 unique key
@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    jwt_token = AuthController.authenticate_user(form_data.username, form_data.password)
    return JSONResponse(status_code=200, content={"success": True, "content": jwt_token, "message": "Login successfully"})


@router.post("/register")
async def register_user(user: UserRegister):
    AuthController.create_user(user.username, user.password)
    return JSONResponse(status_code=200, content={"success": True, "message": "User registered successfully"})
