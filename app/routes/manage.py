from fastapi import APIRouter, Depends
from app.models.user_db import UserModel
from app.controllers.manage import ManageController
from api_web_dev.app.schemas.manage import GroupListResponse, GroupEmailMap, ApproveUserRequest, UpdateLicenseRequest
from api_web_dev.app.ext.error import UnauthorizedError, InternalServerError
from app.controllers.auth import AuthController
from logging import getLogger

logger = getLogger('app_logger')

router = APIRouter()

async def admin_required(user: UserModel = Depends(AuthController.get_current_user)):
    await AuthController.check_user_permission(user, "admin")
    return user

@router.get("/group")
async def get_group(user: UserModel = Depends(admin_required)):
    """Use for script to crawl the group and email from mysql"""
    try:
        group_email_map = ManageController.get_group_email_map(user)
        return GroupListResponse(success=True, content=GroupEmailMap(root=group_email_map))
    except UnauthorizedError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in {get_group.__name__}: {e}")
        raise InternalServerError()
    
@router.put("/approve")
async def approve_email(request: ApproveUserRequest, user: UserModel = Depends(admin_required)):
    """Approve a user by changing their disabled status to False"""
    try:
        success = ManageController.approve_user(request.user_id)
        if success:
            return {"message": "User approved successfully"}
    except UnauthorizedError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in {approve_email.__name__}: {e}")
        raise InternalServerError()

@router.put("/license")
async def update_license(request: UpdateLicenseRequest, user: UserModel = Depends(admin_required)):
    """Update a user's license amount"""
    try:
        success = ManageController.update_user_license(request.user_id, request.license_amount)
        if success:
            return {"message": "License updated successfully"}
    except UnauthorizedError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in {update_license.__name__}: {e}")
        raise InternalServerError()
