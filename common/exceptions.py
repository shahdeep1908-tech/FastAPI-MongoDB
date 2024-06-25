class BadRequestException(Exception):
    def __init__(self, msg):
        self.msg = msg


class NotFoundException(Exception):
    def __init__(self, msg):
        self.msg = msg


class HTTPException(Exception):
    def __init__(self, msg):
        self.msg = msg


class ForbiddenException(Exception):
    def __init__(self, msg):
        self.msg = msg


class ConflictException(Exception):
    def __init__(self, msg):
        self.msg = msg


class TokenExpiryException(Exception):
    def __init__(self, msg):
        self.msg = msg
