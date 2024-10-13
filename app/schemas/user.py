from datetime import datetime
from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    name: str
    email: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    name: str
    email: str
    password: str
    
class UserSignup(BaseModel):
    username: str
    password: str
    email: EmailStr
    company_name: str
    user_role: str = "user"
    license_amount: int = 0 
    disabled: bool = True
    create_date: Optional[datetime] = None
    update_date: Optional[datetime] = None

  



