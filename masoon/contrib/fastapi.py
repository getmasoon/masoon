"""Integrate Masoon sessions and authorization with FastAPI.

Requires the optional ``fastapi`` extra: ``pip install 'masoon[fastapi]'``.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, HTTPAuthorizationCredentials, HTTPBearer

from masoon.authn.sessions import SessionManager
from masoon.authz.rbac import Authorizer
from masoon.errors import InvalidSessionError, PermissionDeniedError
from masoon.types import Identity


def _not_authenticated() -> HTTPException:
    """Return the 401 error used for every authentication failure."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


class MasoonFastAPI:
    """Provide FastAPI dependencies that authenticate and authorize requests.

    Create one instance for your application and use its dependencies in your routes:

    - ``current_identity`` returns the identity of the logged-in user, or responds
      with 401 if the session token is missing, invalid, expired, or revoked.
    - ``require_permission(permission)`` also responds with 403 unless the user has
      the permission.

    The session token is read from the ``Authorization: Bearer <token>`` header, or
    from a cookie if the header is not present.
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

        bearer = HTTPBearer(auto_error=False)
        cookie = APIKeyCookie(name=cookie_name, auto_error=False)

        def current_identity(
            credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
            cookie_token: Annotated[str | None, Depends(cookie)],
        ) -> Identity:
            """Return the identity of the user who sent the request.

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

            return identity

        self.current_identity: Callable[..., Identity] = current_identity

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
                    detail="Forbidden",
                ) from None

            return identity

        return permission_dependency
