from pydantic import BaseModel

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
  



