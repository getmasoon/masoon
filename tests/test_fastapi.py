import importlib
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Response, status
from fastapi.testclient import TestClient

from masoon import (
    Authorizer,
    Identity,
    InMemoryRoleAssignmentStore,
    InMemorySessionStore,
    Role,
    SessionManager,
)
from masoon.contrib.fastapi import MasoonFastAPI

COOKIE_NAME = "sid"
NOT_AUTHENTICATED = {"detail": "Not authenticated"}


class FakeTime:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 18, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@dataclass(frozen=True)
class App:
    client: TestClient
    sessions: SessionManager
    masoon: MasoonFastAPI
    clock: FakeTime
    editor_token: str
    viewer_token: str


@pytest.fixture
def app() -> App:
    clock = FakeTime()
    sessions = SessionManager(
        store=InMemorySessionStore(),
        validity=timedelta(hours=1),
        clock=clock,
    )

    assignments = InMemoryRoleAssignmentStore()
    assignments.assign(user_id="1", role_name="editor")
    authorizer = Authorizer(
        roles=[Role(name="editor", permissions=frozenset({"posts:edit"}))],
        assignments=assignments,
    )

    masoon = MasoonFastAPI(sessions, authorizer, cookie_name=COOKIE_NAME)
    fastapi_app = FastAPI()

    @fastapi_app.get("/me")
    def me(identity: Annotated[Identity, Depends(masoon.current_identity)]) -> dict[str, str]:
        return {"id": identity.id, "username": identity.username}

    @fastapi_app.get("/posts/edit")
    def edit_post(
        identity: Annotated[Identity, Depends(masoon.require_permission("posts:edit"))],
    ) -> dict[str, str]:
        return {"id": identity.id}

    @fastapi_app.get("/posts/delete")
    def delete_post(
        identity: Annotated[Identity, Depends(masoon.require_permission("posts:delete"))],
    ) -> dict[str, str]:
        return {"id": identity.id}

    @fastapi_app.get("/token")
    def token(session_token: Annotated[str, Depends(masoon.current_token)]) -> dict[str, str]:
        return {"token": session_token}

    @fastapi_app.get("/both")
    def both(
        identity: Annotated[Identity, Depends(masoon.current_identity)],
        session_token: Annotated[str, Depends(masoon.current_token)],
    ) -> dict[str, str]:
        return {"id": identity.id, "token": session_token}

    @fastapi_app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(
        session_token: Annotated[str, Depends(masoon.current_token)],
        response: Response,
    ) -> None:
        sessions.revoke(session_token)
        response.delete_cookie(masoon.cookie_name)

    return App(
        client=TestClient(fastapi_app),
        sessions=sessions,
        masoon=masoon,
        clock=clock,
        editor_token=sessions.create(Identity(id="1", username="alice")),
        viewer_token=sessions.create(Identity(id="2", username="bob")),
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def assert_not_authenticated(status_code: int, body: object, www_authenticate: str | None) -> None:
    assert status_code == 401
    assert body == NOT_AUTHENTICATED
    assert www_authenticate == "Bearer"


# Authentication


def test_bearer_token_authenticates(app: App) -> None:
    response = app.client.get("/me", headers=bearer(app.editor_token))

    assert response.status_code == 200
    assert response.json() == {"id": "1", "username": "alice"}


def test_cookie_token_authenticates(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.get("/me")

    assert response.status_code == 200
    assert response.json() == {"id": "2", "username": "bob"}


def test_bearer_header_takes_priority_over_cookie(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.get("/me", headers=bearer(app.editor_token))

    assert response.json()["id"] == "1"


def test_invalid_bearer_header_does_not_fall_back_to_cookie(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.get("/me", headers=bearer("not-a-real-token"))

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_non_bearer_header_falls_back_to_cookie(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.get("/me", headers={"Authorization": "Basic Zm9vOmJhcg=="})

    assert response.status_code == 200
    assert response.json()["id"] == "2"


def test_bearer_scheme_is_case_insensitive(app: App) -> None:
    response = app.client.get("/me", headers={"Authorization": f"bearer {app.editor_token}"})

    assert response.status_code == 200


def test_missing_token_returns_401(app: App) -> None:
    response = app.client.get("/me")

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_invalid_token_returns_401(app: App) -> None:
    response = app.client.get("/me", headers=bearer("not-a-real-token"))

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_empty_bearer_token_returns_401(app: App) -> None:
    response = app.client.get("/me", headers={"Authorization": "Bearer "})

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_expired_token_returns_401(app: App) -> None:
    app.clock.now += timedelta(hours=2)

    response = app.client.get("/me", headers=bearer(app.editor_token))

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_revoked_token_returns_401(app: App) -> None:
    app.sessions.revoke(app.editor_token)

    response = app.client.get("/me", headers=bearer(app.editor_token))

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_every_authentication_failure_looks_the_same(app: App) -> None:
    missing = app.client.get("/me")
    invalid = app.client.get("/me", headers=bearer("not-a-real-token"))
    app.sessions.revoke(app.viewer_token)
    revoked = app.client.get("/me", headers=bearer(app.viewer_token))
    app.clock.now += timedelta(hours=2)
    expired = app.client.get("/me", headers=bearer(app.editor_token))

    responses = [missing, invalid, revoked, expired]

    assert {response.status_code for response in responses} == {401}
    assert {response.text for response in responses} == {missing.text}
    assert {response.headers.get("WWW-Authenticate") for response in responses} == {"Bearer"}


# Authorization


def test_user_with_permission_is_allowed(app: App) -> None:
    response = app.client.get("/posts/edit", headers=bearer(app.editor_token))

    assert response.status_code == 200
    assert response.json() == {"id": "1"}


def test_user_without_permission_gets_403(app: App) -> None:
    response = app.client.get("/posts/edit", headers=bearer(app.viewer_token))

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_403_does_not_reveal_the_permission(app: App) -> None:
    response = app.client.get("/posts/delete", headers=bearer(app.editor_token))

    assert response.status_code == 403
    assert "posts:delete" not in response.text


def test_permission_route_without_token_returns_401(app: App) -> None:
    response = app.client.get("/posts/edit")

    assert_not_authenticated(
        response.status_code,
        response.json(),
        response.headers.get("WWW-Authenticate"),
    )


def test_require_permission_without_authorizer_fails_at_setup() -> None:
    sessions = SessionManager(store=InMemorySessionStore(), validity=timedelta(hours=1))
    masoon = MasoonFastAPI(sessions)

    with pytest.raises(ValueError, match="Authorizer"):
        masoon.require_permission("posts:edit")


# OpenAPI and optional dependency


def test_openapi_documents_both_token_locations(app: App) -> None:
    schema = app.client.get("/openapi.json").json()

    schemes = schema["components"]["securitySchemes"]

    assert schemes["HTTPBearer"]["type"] == "http"
    assert schemes["APIKeyCookie"] == {"type": "apiKey", "in": "cookie", "name": COOKIE_NAME}


def test_import_works_without_fastapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "fastapi", None)
    for module_name in list(sys.modules):
        if module_name == "masoon" or module_name.startswith("masoon."):
            monkeypatch.delitem(sys.modules, module_name)

    package = importlib.import_module("masoon")

    assert package.SessionManager is not None
    with pytest.raises(ImportError):
        importlib.import_module("masoon.contrib.fastapi")


# Session token and logout


def test_current_token_from_bearer_header(app: App) -> None:
    response = app.client.get("/token", headers=bearer(app.editor_token))

    assert response.status_code == 200
    assert response.json() == {"token": app.editor_token}


def test_current_token_from_cookie(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.get("/token")

    assert response.status_code == 200
    assert response.json() == {"token": app.viewer_token}


def test_current_token_requires_a_valid_session(app: App) -> None:
    missing = app.client.get("/token")
    invalid = app.client.get("/token", headers=bearer("not-a-real-token"))

    assert_not_authenticated(
        missing.status_code, missing.json(), missing.headers.get("www-authenticate")
    )
    assert_not_authenticated(
        invalid.status_code, invalid.json(), invalid.headers.get("www-authenticate")
    )


def test_current_identity_and_token_belong_to_the_same_session(app: App) -> None:
    response = app.client.get("/both", headers=bearer(app.editor_token))

    assert response.json() == {"id": "1", "token": app.editor_token}


def test_token_is_validated_once_per_request(app: App, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    validate = app.sessions.validate

    def counting_validate(token: str) -> Identity:
        calls.append(token)
        return validate(token)

    monkeypatch.setattr(app.sessions, "validate", counting_validate)

    app.client.get("/both", headers=bearer(app.editor_token))

    assert calls == [app.editor_token]


def test_logout_with_bearer_header_revokes_the_session(app: App) -> None:
    response = app.client.post("/logout", headers=bearer(app.editor_token))
    after = app.client.get("/me", headers=bearer(app.editor_token))

    assert response.status_code == 204
    assert after.status_code == 401


def test_logout_with_cookie_revokes_the_session_and_clears_the_cookie(app: App) -> None:
    app.client.cookies.set(COOKIE_NAME, app.viewer_token)

    response = app.client.post("/logout")

    assert response.status_code == 204
    assert f'{COOKIE_NAME}=""' in response.headers["set-cookie"]

    app.client.cookies.set(COOKIE_NAME, app.viewer_token)
    after = app.client.get("/me")

    assert after.status_code == 401


def test_logout_without_session_returns_401(app: App) -> None:
    response = app.client.post("/logout")

    assert_not_authenticated(
        response.status_code, response.json(), response.headers.get("www-authenticate")
    )


def test_cookie_name_is_exposed(app: App) -> None:
    assert app.masoon.cookie_name == COOKIE_NAME
