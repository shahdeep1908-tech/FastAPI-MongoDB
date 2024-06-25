import motor.motor_asyncio
from config import app_config

client = motor.motor_asyncio.AsyncIOMotorClient(app_config.DATABASE_URL)
db = client.get_database(app_config.DB_NAME)
