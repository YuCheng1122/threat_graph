from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.controllers.manage import ManageController
from app.ext.error import UnauthorizedError, InternalServerError, PermissionError
from app.controllers.auth import AuthController
from logging import getLogger
from app.models.user_db import UserModel
from app.schemas.manage import TotalAgentsAndLicenseResponse, UserListResponse, ToggleUserStatusRequest, UpdateLicenseRequest, GroupListResponse, GroupEmailMap, NextAgentNameResponse
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
    
@router.put("/toggle-user-status")
async def toggle_user_status(request: ToggleUserStatusRequest, user: UserModel = Depends(admin_required)):
    """Toggle a user's disabled status between True and False"""
    try:
        new_status = ManageController.toggle_user_status(request.user_id)
        return {"message": f"User status updated successfully. New status: {'disabled' if new_status else 'enabled'}"}
    except UnauthorizedError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in {toggle_user_status.__name__}: {e}")
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
    """Get all users
    Request:
        - user: UserSignup: The current user
        - db: Session: The database session
    Returns:
        - UserListResponse: A list of all users
    """
    users = ManageController.get_users(db)
    return UserListResponse(users=users)


@router.get("/next-agent-name", response_model=NextAgentNameResponse)
async def get_next_agent_name(
    current_user: UserModel = Depends(AuthController.get_current_user)
):
    """
    Endpoint to get the next available agent name

    Request:
    curl -X 'GET' \
      'https://flask.aixsoar.com/api/manage/next-agent-name' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer [Token]'

    Response:
    {
      "next_agent_name": "username_001"
    }
    """
    try:
        next_name = ManageController.get_next_agent_name(current_user)
        return NextAgentNameResponse(next_agent_name=next_name)
    except UnauthorizedError:
        raise UnauthorizedError("Authentication required")
    except PermissionError:
        raise PermissionError("User does not have permission to access this resource")
    except Exception as e:
        logger.error(f"Error in get_next_agent_name endpoint: {e}")
        raise InternalServerError()