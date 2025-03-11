from fastapi import APIRouter
from .auth import router as auth_router
from .project import router as project_router
from .task import router as task_router
from .user import router as user_router
from .section import router as section_router

router = APIRouter(prefix="/api")
router.include_router(auth_router, prefix="/auth", tags=["Auth"])
router.include_router(project_router, prefix="/project", tags=["Project"])
router.include_router(task_router, prefix="/task", tags=["Task"])
router.include_router(user_router, prefix="/user", tags=["User"])
router.include_router(section_router, prefix="/sections", tags=["Sections"])
