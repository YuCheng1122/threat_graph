from pydantic import BaseModel, RootModel, EmailStr
from typing import Dict, Optional
from datetime import datetime

class GroupEmailMap(RootModel):
    root: Dict[str, str]

class GroupListResponse(BaseModel):
    success: bool
    content: GroupEmailMap

class ToggleUserStatusRequest(BaseModel):
    user_id: int

class UpdateLicenseRequest(BaseModel):
    user_id: int
    license_amount: int

class TotalAgentsAndLicenseResponse(BaseModel):
    total_agents: int
    total_license: int

class UserInfo(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    license_amount: int
    disabled: bool
    company_name: str

class UserListResponse(BaseModel):
    users: list[UserInfo]

class NextAgentNameResponse(BaseModel):
    next_agent_name: str