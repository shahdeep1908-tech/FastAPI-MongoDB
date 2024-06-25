from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import DESCENDING

DataObject = Dict[str, Any]


def to_dict(obj) -> Dict[str, Any]:
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


class DBInterface:
    """
    DBInterface is an abstract class that defines the methods for interacting with a database.
    This class provides a blueprint for defining the methods for adding, updating and retrieving data from a database.
    The concrete implementations of this class should define the actual database operations.
    """

    def __init__(self, collection: AsyncIOMotorCollection):
        self.collection = collection

    async def read_by_id(self, id: str) -> DataObject:
        item = await self.collection.find_one({"id": id})
        return item

    async def read_all(self) -> List[DataObject]:
        items = []
        async for item in self.collection.find():
            item["_id"] = str(item["_id"])
            items.append(item)
        return items

    async def read_all_by_pagination(self, page_params, filters: Optional[Dict] = None) -> Any:
        query = filters if filters else {}
        cursor = self.collection.find(query).sort("created_at", DESCENDING)

        # Pagination parameters
        offset = (page_params.page - 1) * page_params.size
        cursor = cursor.skip(offset).limit(page_params.size)

        # Fetch items
        items = []
        async for item in cursor:
            item["_id"] = str(item["_id"])
            items.append(item)

        # Count total items
        total_items = await self.collection.count_documents(query)
        return items, total_items

    async def create(self, data: DataObject) -> Any:
        result = await self.collection.insert_one(data)
        return result

    async def update(self, id: str, data: DataObject) -> Any:
        result = await self.collection.update_one(
            {"id": id},
            {"$set": data}
        )
        if result.matched_count == 0:
            return None
        updated_item = await self.read_by_id(id)
        return updated_item

    async def delete(self, id: str) -> DataObject:
        item = await self.read_by_id(id)
        if item:
            await self.collection.delete_one({"id": id})
        return item

    async def delete_all_by_filter(self, fields: tuple) -> Any:
        filter_query = {field[0]: field[1] for field in fields}
        result = await self.collection.delete_many(filter_query)
        return result.deleted_count

    async def get_single_item_by_filters(self, fields: dict) -> Any:
        item = await self.collection.find_one(fields)
        if item and isinstance(item, dict):
            item['_id'] = str(item['_id'])
        return item

    async def get_multiple_items_by_filters(self, fields: tuple) -> Any:
        filter_query = {field[0]: field[1] for field in fields}
        cursor = self.collection.find(filter_query).sort("created_at", DESCENDING)
        items = []
        async for item in cursor:
            item["_id"] = str(item["_id"])
            items.append(item)
        return items

    async def get_paginated_multiple_items_by_filters(self, fields: tuple, page_params) -> Any:
        filter_query = {field[0]: field[1] for field in fields}
        cursor = self.collection.find(filter_query).sort("created_at", DESCENDING)

        # Apply pagination
        offset = (page_params.page - 1) * page_params.size
        cursor = cursor.skip(offset).limit(page_params.size)

        items = []
        async for item in cursor:
            item["_id"] = str(item["_id"])
            items.append(item)

        # Count total items
        total_items = await self.collection.count_documents(filter_query)
        return items, total_items

    async def create_with_uuid(self, data: DataObject) -> DataObject:
        data["id"] = str(uuid.uuid4())
        data["created_at"] = datetime.now(timezone.utc)
        data["updated_at"] = datetime.now(timezone.utc)
        result = await self.collection.insert_one(data)
        data["_id"] = str(result.inserted_id)
        return data

    async def upsert(self, data: DataObject) -> DataObject:
        result = await self.collection.update_one(
            {"id": data["id"]},
            {"$set": data},
            upsert=True
        )
        if result.upserted_id:
            data["_id"] = str(result.upserted_id)
        return data
