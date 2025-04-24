from fastapi import APIRouter

from api.v1.routes.auth import auth_router
from api.v1.routes.user import user_router
from api.v1.routes.user_profile import user_profile_router
from api.v1.routes.file import file_router
from api.v1.routes.form import form_router

v1_router = APIRouter(prefix='/api/v1')

# Register all routes
v1_router.include_router(auth_router)
v1_router.include_router(user_router)
v1_router.include_router(user_profile_router)
v1_router.include_router(file_router)
v1_router.include_router(form_router)
