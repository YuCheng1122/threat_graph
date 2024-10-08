from pydantic import BaseModel, RootModel, EmailStr
from typing import Dict, Optional
from datetime import datetime

class GroupEmailMap(RootModel):
    root: Dict[str, str]

class GroupListResponse(BaseModel):
    success: bool
    content: GroupEmailMap

class ApproveUserRequest(BaseModel):
    user_id: int

class UpdateLicenseRequest(BaseModel):
    user_id: int
    license_amount: int

class TotalAgentsAndLicenseResponse(BaseModel):
    total_agents: int
    total_license: int

class UserInfo(BaseModel):
    id: int
    username: str
    email: EmailStr
    license_amount: int
    disabled: bool
    company_name: str

class UserListResponse(BaseModel):
    users: list[UserInfo]