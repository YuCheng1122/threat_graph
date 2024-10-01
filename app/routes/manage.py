from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.models.user_db import UserModel
from app.controllers.manage import ManageController
from api_web_dev.app.schemas.manage import GroupListResponse, GroupEmailMap, ApproveUserRequest, UpdateLicenseRequest
from api_web_dev.app.ext.error import UnauthorizedError, InternalServerError
from app.controllers.auth import AuthController
from logging import getLogger
from app.models.user_db import UserModel
from app.schemas.manage import TotalAgentsAndLicenseResponse, UserListResponse, UserInfo
from app.schemas.user import UserSignup
from app.models.manage_db import SessionLocal

logger = getLogger('app_logger')

router = APIRouter()

async def admin_required(user: UserModel = Depends(AuthController.get_current_user)):
    await AuthController.check_user_permission(user, "admin")
    return user

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

@router.get("/total-agents-and-license", response_model=TotalAgentsAndLicenseResponse)
async def get_total_agents_and_license(user: UserSignup = Depends(AuthController.get_current_user)):
    """Get the total number of agents and the total license amount"""
    try:

        if user.user_role == 'admin':
            group_names = None
        else:
            group_names = UserModel.get_user_groups(user.id)
            logger.info(f"User groups: {group_names}")
            if not group_names:
                logger.warning(f"No groups found for user {user.id}")
                return TotalAgentsAndLicenseResponse(total_agents=0, total_license=0)

        total_agents = await ManageController.get_total_agents(group_names)
        total_license = ManageController.get_total_license(user.id if user.user_role != 'admin' else None)
        logger.info(f"Total agents: {total_agents}, Total license: {total_license}")

        return TotalAgentsAndLicenseResponse(total_agents=total_agents, total_license=total_license)
    except UnauthorizedError as ue:
        logger.error(f"Unauthorized error for user {user.id}: {str(ue)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in {get_total_agents_and_license.__name__} for user {user.id}: {e}")
        raise InternalServerError()

@router.get("/users", response_model=UserListResponse)
async def read_users(
    _: UserSignup = Depends(admin_required),
    db: Session = Depends(get_db)
):
    users = ManageController.get_users(db)
    return UserListResponse(users=users)


