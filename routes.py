from fastapi import APIRouter

# from ebds.admin import admin_routes
from ebds.authentication import auth_routes
from ebds.workspace import workspace_routes

router = APIRouter()


@router.get('/')
def initialization():
    """
    Initialization Endpoint.
    """
    return "The server is running."


# router.include_router(admin_routes.router)
router.include_router(auth_routes.router)
router.include_router(workspace_routes.router)
