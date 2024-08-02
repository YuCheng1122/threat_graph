from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from app.controllers.auth import AuthController
from app.schemas.user import UserRegister
from app.ext.error import UserExistedError, UserNotFoundError, InvalidPasswordError, UserDisabledError, InvalidTokenError, AuthControllerError

router = APIRouter()

@router.post("/login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        print(f"DEBUG: form_data - Username: {form_data.username}, Password: {form_data.password}")
        jwt_token = AuthController.authenticate_user(form_data.username, form_data.password)
        return JSONResponse(status_code=200, content={"success": True, "content": jwt_token, "message": "Login successfully"})
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    except InvalidPasswordError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    except UserDisabledError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")
    except AuthControllerError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.post("/register")
async def register_user(user: UserRegister):
    try:
        AuthController.create_user(user.username, user.password)
        return JSONResponse(status_code=200, content={"success": True, "message": "User registered successfully"})
    except UserExistedError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    except AuthControllerError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
