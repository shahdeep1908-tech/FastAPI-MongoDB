"""
This module contains all the constant values used in the project.
"""
PROJECT_NAME: str = "EBDS"
DOCS_URL_PATH: str = "/docs"
REDOC_URL_PATH: str = "/redoc"

# Authentication Routes Constants
REGISTER_SUMMARY = "User Registration API"
LOGIN_SUMMARY = "User Login API"
NEW_ACCESS_TOKEN_SUMMARY = "Create New Tokens API"
CHANGE_PASS_SUMMARY = "Change Password API"
SET_PASS_SUMMARY = "Set Password API"
FORGOT_PASS_SUMMARY = "Forgot Password API"
RESET_PASS_SUMMARY = "Reset Password API"
VERIFY_EMAIL_SUMMARY = "Verify Email API"
LOGOUT_SUMMARY = "User Logout API"
GET_USER_PROFILE_SUMMARY = "GET User Profile API"
CHANGE_PROFILE_SUMMARY = "UPDATE User Profile API"
EMAIL_REGEX = r"^[a-z0-9]+[\._+]?[a-z0-9]+[@]([\w]+\.)+[\w]{2,4}+$"
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!#%*?&])[A-Za-z\d@$!#%*?&]{8,16}$"
DEFAULT_DATE_TIME_FORMAT_REGEX = "%Y-%m-%d %H:%M:%S"

# Roles Routes Constants
ROLES_SUMMARY = "GET Roles list API"

# Workspace Routes Constants
WORKSPACE_REGISTER = "Workspace registration API"
LIST_WORKSPACE = "Workspaces list API"
GET_WORKSPACE = "GET Workspace API"
GET_WORKSPACE_DETAILS = "GET Workspace Details API"
DELETE_WORKSPACE = "Delete Workspaces API"
UPDATE_WORKSPACE = "Update Workspaces API"
WORKSPACE_INVITE_MEMBER = "Workspace Invite member API"
WORKSPACE_REMOVE_MEMBER = "Workspace Remove member API"
WORKSPACE_DELETE_INVITATION = "Workspace Delete Invitation API"
WORKSPACE_VERIFY_EMAIL = "Verify Invited member API"
WORKSPACE_MEMBERS = "Get Workspace Members API"

# Page Routes Constants
LIST_PAGE = "Page list API"
GET_PAGE = "GET Page API"
DELETE_PAGE = "Delete Page API"
UPDATE_PAGE = "Update Page API"

# Workspace Lists Constants
RETRIEVE_WORKSPACE_LIST = "Workspace lists API"
GET_WORKSPACE_LIST = "GET Workspace List API"
DELETE_WORKSPACE_LIST = "Delete Workspace List API"
UPDATE_WORKSPACE_LIST = "Update Workspace List API"
GET_WORKSPACE_LIST_CONTENT = "GET Workspace List Content API"
