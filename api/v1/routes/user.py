from datetime import timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.database import get_db
from api.utils import paginator
from api.utils.responses import success_response
from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.services.auth import AuthService
from api.v1.services.user import UserService
from api.v1.schemas import user as user_schemas
from api.utils.loggers import create_logger
from api.utils.telex_notification import TelexNotification


user_router = APIRouter(prefix='/users', tags=['User'])
logger = create_logger(__name__)

@user_router.get('/', status_code=200)
async def get_all_users(
    search: str = None,
    page: int = 1,
    per_page: int = 10,
    sort_by: str = 'created_at',
    order: str = 'desc',
    db: Session=Depends(get_db), 
    user: User=Depends(AuthService.get_current_superuser)
):
    """Endpoint to get the current user

    Args:
        db (Session, optional): Database session. Defaults to Depends(get_db).
        user (User, optional): Current user. Defaults to Depends(AuthService.get_current_superuser).
    """
    
    users, count = User.all(
        db, 
        sort_by=sort_by,
        order=order.lower(),
        page=page,
        per_page=per_page
    )
    
    if search:
        users, count = User.search(
            db, 
            search_fields={
                'email': search,
            },
            sort_by=sort_by,
            order=order.lower(),
            page=page,
            per_page=per_page
        )
    
    return paginator.build_paginated_response(
        items=[
            {
                **user.to_dict(excludes=['password', 'is_superuser']),
                "profile": user.profile.to_dict()
            } for user in users
        ],
        endpoint='/users',
        page=page,
        size=per_page,
        total=count,
    )
        
    # return paginator.build_model_paginated_response(
    #     db,
    #     model=User,
    #     endpoint='/users',
    #     page=page,
    #     size=per_page,
    #     order=order,
    #     sort_by=sort_by,
    #     search_fields={
    #         'email': search,
    #     },
    #     excludes=['password', 'is_superuser']
    # )

@user_router.get('/me', status_code=200, response_model=success_response)
async def get_current_user(db: Session=Depends(get_db), user: User=Depends(AuthService.get_current_user)):
    """Endpoint to get the current user

    Args:
        db (Session, optional): Database session. Defaults to Depends(get_db).
        user (User, optional): Current user. Defaults to Depends(AuthService.get_current_user).
    """
    
    return success_response(
        status_code=200,
        message='User fetched successfully',
        data={
            **user.to_dict(excludes=['password', 'is_superuser']),
            'profile': user.profile.to_dict()
        }
    )
    
@user_router.get('/{user_id}', status_code=200, response_model=success_response)
async def get_user_by_id(
    user_id: str,
    db: Session=Depends(get_db), 
    current_user: User=Depends(AuthService.get_current_superuser)
):
    """Endpoint to get a user by id

    Args:
        user_id (str): ID of the user to be fetched
        db (Session, optional): Database session. Defaults to Depends(get_db).
        current_user (User, optional): Current user. Defaults to Depends(AuthService.get_current_user).
    """
    
    user = User.fetch_by_id(db, user_id)
    
    return success_response(
        status_code=200,
        message='User fetched successfully',
        data={
            **user.to_dict(excludes=['password', 'is_superuser']),
            'profile': user.profile.to_dict()
        }
    )

@user_router.patch('/me', status_code=200, response_model=success_response)
async def update_user_details(
    payload: user_schemas.UpdateUser,
    db: Session=Depends(get_db), 
    current_user: User=Depends(AuthService.get_current_user)
):
    if payload.password and payload.old_password:
        user = UserService.change_password(db, payload) 
    
    if payload.email and payload.email != current_user.email:
        user = UserService.change_email(db, payload, current_user.id)
            
    return success_response(
        status_code=200,
        message='Password changed successfully',
        data={
            **user.to_dict(excludes=['password', 'is_superuser']),
            'profile': user.profile.to_dict()
        }
    )

@user_router.post('/deactivate-account', status_code=200, response_model=success_response)
async def deactivate_account(
    db: Session=Depends(get_db), 
    current_user: User=Depends(AuthService.get_current_user)
):
    User.update(db, current_user.id, is_active=False)
    
    return success_response(
        status_code=200,
        message='Account deactivated'
    )
    
@user_router.post('/reactivate-account/request', status_code=200, response_model=success_response)
async def reactivate_account_request(
    payload: user_schemas.AccountReactivationRequest,
    db: Session=Depends(get_db),
):
    token = await UserService.send_account_reactivation_token(db, payload.email)
    
    return success_response(
        status_code=200,
        message='Account reactivation token sent',
        data={
            'token': token
        }
    )
    
@user_router.post('/reactivate-account', status_code=200, response_model=success_response)
async def reactivate_account(
    token: str,
    db: Session=Depends(get_db),
):
    user_id = UserService.verify_account_reactivation_token(db, token)
    
    User.update(db, user_id, is_active=True)
    
    return success_response(
        status_code=200,
        message='Account reactivated successfully'
    )

@user_router.delete('/delete-account', status_code=200, response_model=success_response)
async def delete_account(
    db: Session=Depends(get_db), 
    current_user: User=Depends(AuthService.get_current_user)
):
    User.soft_delete(db, current_user.id)
    
    return success_response(
        status_code=200,
        message='Account deleted'
    )

@user_router.delete('/{user_id}', status_code=200, response_model=success_response)
async def delete_user(
    user_id: str,
    db: Session=Depends(get_db), 
    current_user: User=Depends(AuthService.get_current_superuser)
):
    User.soft_delete(db, user_id)
    
    return success_response(
        status_code=200,
        message='User deleted'
    )
