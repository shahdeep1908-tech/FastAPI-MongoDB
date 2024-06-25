from typing import Any, Protocol, Dict, List

DataObject = Dict[str, Any]


class DataInterfaceImpl(Protocol):
    """
    This is for demo purpose only.

    This class is an abstract class that defines the methods for interacting with the database.
    This class provides the blue-prints of all the methods that are used to perform operations on database.
    """

    def read_by_id(self, id: str) -> DataObject:
        """
        Used to read any specific data from database, filter by id.
        :param id: Takes parameter id for filtering the query.
        :return: Object if data found from database else return None.
        """
        ...

    def read_all(self) -> List[DataObject]:
        """
        Used to read all the data from database.
        :return: List of objects if data found else return None.
        """
        ...

    def read_all_by_pagination(self, page_params, filters) -> Any:
        """
        Used to read all the data from database.
        :return: List of paginated objects if data found else return None.
        """
        ...

    def create(self, data: DataObject) -> Any:
        """
        Used to create and save data into database.
        :param data: Takes data as parameter defining fields and values to store it in database.
        :return: Data as a dictionary after saving it into database.
        """
        ...

    def update(self, id: str, data: DataObject) -> Any:
        """
        Used to update the existing data into database, filter by id.
        :param id: Takes id as parameter to filter the query.
        :param data: Takes data as an object containing the field and values that are need to be updated.
        :return: Updated data as dictionary.
        """
        ...

    def get_single_item_by_filters(self, fields: tuple) -> Any:
        """
        Used to read specific data from database, filter by  fields.
        :param fields: Takes field as parameter to filter the query.
        :return: Object of data, whichever is found first else return None.
        """
        ...

    def get_multiple_items_by_filters(self, fields: tuple) -> Any:
        """
        Used to read all the data from database, filter by  field.
        :param fields: Takes field as parameter to filter the query
        :return: List of objects from database if found else return None
        """
        ...

    def get_paginated_multiple_items_by_filters(self, fields: tuple, page_params) -> Any:
        """
        Used to read all the data from database, filter by  field.
        :param fields: Takes field as parameter to filter the query
        :return: List of objects from database if found else return None
        """
        ...

    def create_with_uuid(self, data: DataObject) -> DataObject:
        """
        Used to create and store data into database replacing id with uuid.
        :param data: Takes data as parameter defining fields and values to store it in database.
        :return: Data as dictionary after storing in database.
        """
        ...

    def delete(self, id: str) -> DataObject:
        """
        Used to delete the existing data from the database.
        :param id: Takes id as parameter to filter the query.
        :return: Deleted data if found else return None.
        """
        ...

    def delete_all_by_filter(self, fields: tuple) -> Any:
        """
        Used to delete the existing data from the database.
        :param fields: Takes field as parameter to filter the query
        :return: Deleted data if found else return None.
        """
        ...

    def upsert(self, data: DataObject) -> DataObject:
        ...
