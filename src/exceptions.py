from typing import Any
from fastapi import HTTPException, status


class BookreviewException(HTTPException):
    STATUS_CODE = status.HTTP_500_INTERNAL_SERVER_ERROR
    DETAIL = "Internal server error"

    def __init__(self, **kwargs: dict[str, Any]) -> None:
        super().__init__(status_code=self.STATUS_CODE, detail=self.DETAIL, **kwargs)


class BadRequest(BookreviewException):
    STATUS_CODE = status.HTTP_400_BAD_REQUEST
    DETAIL = "Bad Request"


class Conflict(BookreviewException):
    STATUS_CODE = status.HTTP_409_CONFLICT
    DETAIL = "Conflict"


class Unauthorized(BookreviewException):
    STATUS_CODE = status.HTTP_401_UNAUTHORIZED


class NotFound(BookreviewException):
    STATUS_CODE = status.HTTP_404_NOT_FOUND
    DETAIL = "Not Found"
