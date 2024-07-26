from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.controllers.auth import AuthController, Token, User, get_current_user
from app.schemas.user import UserRegister

router = APIRouter()

# 暫時使用 user name 作為 unique key
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    jwt_token = AuthController.authenticate_user(form_data.username, form_data.password)
    return JSONResponse(status_code=200, content={"success": True, "content": jwt_token, "message": "Login successfully"})


@router.post("/register", response_model=Token)
async def register_user(user: UserRegister):
    AuthController.create_user(user.username, user.password)
    return JSONResponse(status_code=200, content={"success": True, "message": "User registered successfully"})



#@router.get("/users/me/", response_model=User)
#async def read_users_me(current_user: User = Depends(get_current_active_user)):
 #   logging.info(f"Reading user: {current_user.username}")
  #  return current_user
