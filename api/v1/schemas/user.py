from typing import Optional
from pydantic import BaseModel, EmailStr
import datetime as dt

    
class UpdateUser(BaseModel):
    
    email: Optional[EmailStr] = None
    old_password: Optional[str] = None
    password: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_country_code: Optional[str] = None
    profile_picture: Optional[str] = None
    phone_number: Optional[str] = None
    username: Optional[str] = None
    bio: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    address: Optional[str] = None
    
    
class AccountReactivationRequest(BaseModel):
    
    email: EmailStr
