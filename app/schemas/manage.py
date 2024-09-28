from pydantic import BaseModel, RootModel
from typing import Dict

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