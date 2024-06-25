from datetime import datetime

from fastapi.encoders import jsonable_encoder
from jinja2 import FileSystemLoader, Environment
from common.constants import DEFAULT_DATE_TIME_FORMAT_REGEX


def convert_data_into_json(request_data):
    """
    convert_data_into_json is a function that converts the request data into a JSON object.

    :param request_data: Request data to be converted into a JSON object.
    :return: dict: The converted JSON object.
    """
    return jsonable_encoder(request_data)


def generate_pdf_template(path: str, context_data: dict):
    # Load the invoice template
    temp_env = Environment(loader=FileSystemLoader('templates'))
    pdf_template = temp_env.get_template(path)
    # Render the template with the data
    return pdf_template.render(**context_data)


def convert_unix_timestamp_to_desired_formate(unix_timestamp: float):
    """
    Converts a UNIX timestamp to a datetime object.

    :param unix_timestamp: An unis timestamp.
    :return: A datetime object representing the same time as the UTC timestamp.
    """
    utc_datetime_for_sub_created = datetime.utcfromtimestamp(unix_timestamp)
    return utc_datetime_for_sub_created.strftime(DEFAULT_DATE_TIME_FORMAT_REGEX)


def convert_unix_timestamp_to_string_format(date_string: str):
    """
    Converts a UNIX timestamp to a datetime object.

    :param date_string: A Unix timestamp.
    :return: A datetime object representing the same time as the UTC timestamp.
    """
    dt_obj = datetime.strptime(date_string, '%a %b %d %Y %H:%M:%S GMT%z')
    return dt_obj.strftime('%d' + 'th' + ' %B, %Y').replace('0th', '').replace('1th', '1st').replace('2th', '2nd').replace('3th', '3rd')

