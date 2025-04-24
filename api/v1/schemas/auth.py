from typing import Optional
from pydantic import BaseModel, EmailStr
import datetime as dt


class CreateUser(BaseModel):
    
    email: EmailStr
    password: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_country_code: Optional[str] = None
    profile_picture: Optional[str] = None
    phone_number: Optional[str] = None
    is_superuser: Optional[bool] = False

class LoginSchema(BaseModel):
    
    email: EmailStr
    password: str

class MagicLoginRequest(BaseModel):
    
    email: EmailStr
    
class ResetPasswordRequest(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    password: str
    
class GoogleAuth(BaseModel):
    id_token: str
