from passlib.context import CryptContext


class Hasher:
    """
    Hasher is a class that provides methods for hashing and verifying passwords.
    """
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify if the given plain password matches the given hashed password.

        :param plain_password: The plain password to verify.
        :param hashed_password: The hashed password to compare against.
        :return: True if the passwords match, False otherwise.
        """
        return Hasher.pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        This function generates a hash for the given password using a strong bcrypt hash function.
        :param password: A string representing the plain password to be hashed.
        :return: A string representing the hashed password.
        """
        return Hasher.pwd_context.hash(password)
