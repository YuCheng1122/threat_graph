from fastapi import Depends, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from app.controllers.auth import AuthController
from app.schemas.user import UserSignup
from app.ext.error import UserExistedError, UserNotFoundError, InvalidPasswordError, UserDisabledError, AuthControllerError
from logging import getLogger

# Get the centralized logger
logger = getLogger('app_logger')


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
  
@router.post("/signup")
async def signup_user(user: UserSignup):
    """
    Register a new user
    Request body:
    - username: str (required) - 使用者帳號
    - password: str (required) - 使用者密碼
    - email: str (required) - 聯絡信箱
    - company_name: str (required) - 公司名稱
    - license_amount: int (required) - 預期申請的憑證數量
    Response body:
    - success: bool
    - content: None
    - message: str
    """
    try:
        AuthController.create_user_signup(
            user.username,
            user.password,
            user.email,
            user.company_name,
            user.license_amount
        )
        return {
            "success": True,
            "content": None,
            "message": "User signup successfully"
        }
    except UserExistedError as e:
        raise
    except AuthControllerError as e:
        raise
    except Exception as e:
        raise