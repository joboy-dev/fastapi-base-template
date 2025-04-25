from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, EmailStr
import datetime as dt
from api.v1.models.user import User


class CreateUser(BaseModel):
    
    email: EmailStr
    password: Optional[str] = None
    first_name: str
    last_name: str
    phone_country_code: Optional[str] = None
    profile_picture: Optional[str] = None
    phone_number: Optional[str] = None
    username: Optional[str] = None
    bio: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    address: Optional[str] = None
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
    