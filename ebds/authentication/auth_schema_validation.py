import re

from common import constants


def password_validation(password):
    """
    Validate the strength of a user's password.
    This function is used to validate the strength of a user's password, ensuring that it meets minimum security
    requirements. The password should be at least 8 characters long and contain a mixture of upper and
    lowercase letters, numbers, and special characters.

    :param password: The password to be validated.
    :return: validated password.
    :raises: ValueError: If the password does not meet the minimum security requirements.
    """

    if re.fullmatch(constants.PASSWORD_REGEX, password):
        return True
    return False
