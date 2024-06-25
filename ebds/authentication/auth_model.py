from adapter.database import db

user_authentication_models = ['roles', 'user', 'blacklisttokens']


async def create_auth_collection():
    # Create collections for new models
    collection_names = await db.list_collection_names()
    for auth_model in user_authentication_models:
        if auth_model not in collection_names:
            await db.create_collection(auth_model)


Roles = db.get_collection("roles")
User = db.get_collection("user")
BlackListTokens = db.get_collection("blacklisttokens")
