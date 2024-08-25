from fastapi import Depends, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from app.controllers.auth import AuthController
from app.schemas.user import UserRegister
from app.ext.error import UserExistedError, UserNotFoundError, InvalidPasswordError, UserDisabledError, AuthControllerError

router = APIRouter()

@router.post("/login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        jwt_token = AuthController.authenticate_user(form_data.username, form_data.password)
        return {
            "success": True,
            "content": jwt_token,
            "message": "Login successfully"
        }
    except(UserNotFoundError, InvalidPasswordError, UserDisabledError):
        raise UserNotFoundError("Incorrect username or password")
    except AuthControllerError as e:
        raise 

@router.post("/register")
async def register_user(user: UserRegister):
    try:
        AuthController.create_user(user.username, user.password)
        return {
            "success": True,
            "content": None,
            "message": "User registered successfully"
        }
    except UserExistedError:
        raise
    except AuthControllerError as e:
        raise