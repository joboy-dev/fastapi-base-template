from fastapi import APIRouter

from api.v1.routes.auth import auth_router
from api.v1.routes.user import user_router

v1_router = APIRouter(prefix='/api/v1')

# Register all routes
v1_router.include_router(auth_router)
v1_router.include_router(user_router)
