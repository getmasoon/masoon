"""Integrate Masoon sessions and authorization with FastAPI.

Requires the optional ``fastapi`` extra: ``pip install 'masoon[fastapi]'``.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyCookie, HTTPAuthorizationCredentials, HTTPBearer

from masoon.authn.sessions import SessionManager
from masoon.authz.rbac import Authorizer
from masoon.errors import InvalidSessionError, PermissionDeniedError
from masoon.types import Identity

_FORBIDDEN_DETAIL = "Forbidden"


def _not_authenticated() -> HTTPException:
    """Return the 401 error used for every authentication failure."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


@dataclass(frozen=True, slots=True)
class _Session:
    """Hold the validated session token and identity of a request."""

    token: str
    identity: Identity


class MasoonFastAPI:
    """Provide FastAPI dependencies that authenticate and authorize requests.

    Create one instance for your application and use its dependencies in your routes:

    - ``current_identity`` returns the identity of the logged-in user, or responds
      with 401 if the session token is missing, invalid, expired, or revoked.
    - ``current_token`` returns the validated session token of the request, for
      example to revoke it when the user logs out. It responds with 401 in the same
      cases as ``current_identity``.
    - ``require_permission(permission)`` also responds with 403 unless the user has
      the permission.

    The session token is read from the ``Authorization: Bearer <token>`` header, or
    from a cookie if the header is not present. The token is validated only once per
    request, even if a route uses several of these dependencies.
    """

    def __init__(
        self,
        sessions: SessionManager,
        authorizer: Authorizer | None = None,
        *,
        cookie_name: str = "session",
    ) -> None:
        """Initialize the integration.

        Args:
            sessions: The session manager used to validate session tokens.
            authorizer: The authorizer used by ``require_permission``. Only needed
                if your routes check permissions.
            cookie_name: The name of the cookie that holds the session token.

        """
        self._authorizer = authorizer
        self._cookie_name = cookie_name

        bearer = HTTPBearer(auto_error=False)
        cookie = APIKeyCookie(name=cookie_name, auto_error=False)

        def current_session(
            credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
            cookie_token: Annotated[str | None, Depends(cookie)],
        ) -> _Session:
            """Return the validated session of the request.

            Raises:
                HTTPException: 401 if the session token is missing or not valid.

            """
            token = credentials.credentials if credentials is not None else cookie_token
            if not token:
                raise _not_authenticated()

            try:
                identity = sessions.validate(token)
            except InvalidSessionError:
                raise _not_authenticated() from None

            return _Session(token=token, identity=identity)

        def current_identity(
            session: Annotated[_Session, Depends(current_session)],
        ) -> Identity:
            """Return the identity of the user who sent the request.

            Raises:
                HTTPException: 401 if the session token is missing or not valid.

            """
            return session.identity

        def current_token(
            session: Annotated[_Session, Depends(current_session)],
        ) -> str:
            """Return the validated session token of the request.

            Raises:
                HTTPException: 401 if the session token is missing or not valid.

            """
            return session.token

        self.current_identity: Callable[..., Identity] = current_identity
        self.current_token: Callable[..., str] = current_token

    @property
    def cookie_name(self) -> str:
        """Return the name of the cookie that holds the session token."""
        return self._cookie_name

    def require_permission(self, permission: str) -> Callable[..., Identity]:
        """Return a dependency that requires the user to have a permission.

        The dependency authenticates the request first, then checks the
        permission, and returns the identity of the user.

        Raises:
            ValueError: If no authorizer was given to ``MasoonFastAPI``. This
                happens when the route is defined, not during a request.

        """
        if self._authorizer is None:
            msg = "require_permission needs an Authorizer. Pass one to MasoonFastAPI."
            raise ValueError(msg)

        authorizer = self._authorizer

        def permission_dependency(
            identity: Annotated[Identity, Depends(self.current_identity)],
        ) -> Identity:
            """Return the identity if it has the permission.

            Raises:
                HTTPException: 403 if the identity does not have the permission.

            """
            try:
                authorizer.require(identity, permission)
            except PermissionDeniedError:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=_FORBIDDEN_DETAIL,
                ) from None

            return identity

        return permission_dependency


async def _permission_denied_handler(_request: Request, _exc: Exception) -> JSONResponse:
    """Return the 403 response used when a permission or policy check fails."""
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": _FORBIDDEN_DETAIL},
    )


def add_exception_handlers(app: FastAPI) -> None:
    """Register handlers that turn Masoon errors raised in routes into HTTP responses.

    Call this once after creating your application. Afterwards, a
    ``PermissionDeniedError`` raised inside a route, for example by ``enforce``,
    returns 403 with ``{"detail": "Forbidden"}``, the same response as
    ``require_permission``. Without the handler, FastAPI returns 500.

    The response does not reveal which permission or policy rule failed.
    """
    app.add_exception_handler(PermissionDeniedError, _permission_denied_handler)
