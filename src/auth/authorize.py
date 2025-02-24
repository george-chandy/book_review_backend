from typing import List
from fastapi import Depends
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from src.auth.exceptions import (
    AccessTokenExpiredException,
    AccessTokenRequiredException,
    InvalidAccessTokenException,
    JwtTokenExpiredException,
)
from src.auth.schemas import TokenType, UserRole
from src.auth.utils import validate_and_decode_token


security = HTTPBearer()


def auth_user_id(auth: HTTPAuthorizationCredentials = Depends(security)):
    if not auth or not auth.credentials:
        raise AccessTokenRequiredException()

    try:
        tokenData = validate_and_decode_token(auth.credentials, TokenType.ACCESS)
    except JwtTokenExpiredException:
        raise AccessTokenExpiredException()

    if not tokenData:
        raise InvalidAccessTokenException()
    return tokenData.user_id


def auth_user_id_by_roles(
    allowed_roles: List[UserRole],
):
    def authorize_and_get_user_id_by_roles(
        auth: HTTPAuthorizationCredentials = Depends(security),
    ):
        if not auth or not auth.credentials:
            raise AccessTokenRequiredException()

        try:
            tokenData = validate_and_decode_token(auth.credentials, TokenType.ACCESS)
        except JwtTokenExpiredException:
            raise AccessTokenExpiredException()

        if not tokenData:
            raise InvalidAccessTokenException()

        if tokenData.user_role not in allowed_roles:
            raise InvalidAccessTokenException()
        return tokenData.user_id

    return authorize_and_get_user_id_by_roles
