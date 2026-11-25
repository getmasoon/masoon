# Masoon

Framework-agnostic authentication and authorization for Python.

> **Status: pre-alpha.** Masoon is in early development. The API will change
> and it is not ready for production use.

## Features

**Available now**

- **Username and password login** with a single `Authenticator`.
- **Session tokens**: keep users logged in, with expiry and logout. Only a hash of each
  token is stored.
- **Role-based access control**: define roles in code, assign them to users, and check
  permissions. Access is denied by default.
- **Authorization policies**: combine rules such as "editors, or the post's author" for
  decisions that depend on the resource being accessed.
- **Argon2 password hashing** with secure defaults (optional extra).
- **FastAPI integration**: protect routes with a login or a permission check in one line
  (optional extra).
- **Bring your own storage**: plug in any database or ORM by implementing a small protocol.
- **Safe failures**: a wrong password and an unknown username raise the same error and take
  about the same time, so attackers cannot discover which usernames exist.
- **Typed**: fully type-hinted and checked with ty.
- **Minimal core**: no required dependencies.

**Planned**

- Integrations for Django and Flask.

## Installation

Masoon requires Python 3.12 or newer. Install it with the `argon2` extra to get the
built-in password hasher:

```bash
pip install 'masoon[argon2]'
```

Or with uv:

```bash
uv add 'masoon[argon2]'
```

Installing plain `masoon` gives you the core only. You then need to provide your own
password hasher.

To use the FastAPI integration, add the `fastapi` extra. You can install several extras at
once:

```bash
pip install 'masoon[argon2,fastapi]'
```

## Quick start

```python
from masoon import (
    Argon2PasswordHasher,
    Authenticator,
    InMemoryUserStore,
    InvalidCredentialsError,
    StoredUser,
)

hasher = Argon2PasswordHasher()

# Register a user. Always store the hash, never the password itself.
store = InMemoryUserStore()
store.add(
    StoredUser(
        id="1",
        username="alice",
        hashed_password=hasher.hash_password(password="correct horse battery staple"),
    ),
)

authenticator = Authenticator(store=store, hasher=hasher)

# A successful login returns the user's identity.
identity = authenticator.authenticate(
    username="alice",
    password="correct horse battery staple",
)
print(identity)  # Identity(id='1', username='alice')

# A failed login raises InvalidCredentialsError.
try:
    authenticator.authenticate(username="alice", password="wrong password")
except InvalidCredentialsError as error:
    print(error)  # Invalid username or password.
```

`InMemoryUserStore` is meant for tests and examples. In a real application, connect your
own database as shown below.

## Sessions

After a successful login, create a session so the user stays logged in. `SessionManager`
returns a random token that your application sends to the client, for example in a
cookie. On later requests, validate the token to get the user's identity back.

```python
from datetime import timedelta

from masoon import InMemorySessionStore, InvalidSessionError, SessionManager

sessions = SessionManager(store=InMemorySessionStore(), validity=timedelta(days=1))

# Log in, then create a session for the identity.
token = sessions.create(identity)

# On each later request, validate the token sent by the client.
identity = sessions.validate(token)
print(identity)  # Identity(id='1', username='alice')

# On logout, revoke the session. The token stops working immediately.
sessions.revoke(token)

try:
    sessions.validate(token)
except InvalidSessionError as error:
    print(error)  # Invalid session.
```

How sessions work:

- **The token is returned only once**, by `create`. Masoon stores a SHA-256 hash of it,
  never the token itself, so a leaked session database cannot be used to log in.
- **Sessions expire** after the `validity` you choose. Validating an expired token raises
  `InvalidSessionError` and removes the session from the store.
- **One error for every failure.** Unknown, expired, and revoked tokens all raise the same
  `InvalidSessionError`, so the error never reveals why a token was rejected.
- **Revoking is safe to repeat.** Revoking a token that does not exist does nothing.

`InMemorySessionStore` loses all sessions when your application restarts. In a real
application, store sessions in your own database as shown below.

## Authorization

Masoon uses role-based access control. Define roles in your code, each with a set of
permissions, then record which roles each user has. `Authorizer` answers whether an
identity is allowed to do something.

```python
from masoon import (
    Authorizer,
    Identity,
    InMemoryRoleAssignmentStore,
    PermissionDeniedError,
    Role,
)

# Define roles in code. Permissions are plain strings.
viewer = Role(name="viewer", permissions=frozenset({"posts:read"}))
editor = Role(name="editor", permissions=frozenset({"posts:read", "posts:edit"}))

# Record which roles each user has.
assignments = InMemoryRoleAssignmentStore()
assignments.assign(user_id="1", role_name="editor")

authorizer = Authorizer(roles=[viewer, editor], assignments=assignments)
alice = Identity(id="1", username="alice")

print(authorizer.has_permission(alice, "posts:edit"))  # True
print(authorizer.has_permission(alice, "posts:delete"))  # False

# In a request handler, use require. It raises if the permission is missing.
try:
    authorizer.require(alice, "posts:delete")
except PermissionDeniedError as error:
    print(error)  # Permission denied: posts:delete
```

How authorization works:

- **Access is denied by default.** A user with no roles has no permissions.
- **Undefined roles grant nothing.** If a user is assigned a role name that your code does
  not define, for example one you removed, it is ignored.
- **Permissions match exactly.** `posts:edit` does not match `Posts:Edit` or `posts:*`.
- **There is no built-in admin.** To give a user every permission, define a role that
  lists them explicitly.
- **Permissions from several roles combine.** A user with two roles has the permissions
  of both.
- **Roles cannot change after they are created.** Their permissions are always stored as
  a `frozenset`, and two roles with the same name raise `ValueError`.

`InMemoryRoleAssignmentStore` is meant for tests and examples. In a real application,
store role assignments in your own database as shown below.

## Policies

Roles answer "can editors edit posts?". Policies answer "can this user edit this post?",
for rules that depend on the resource being accessed.

A policy is any function that takes an `Identity` and a resource and returns `True` or
`False`. Combine policies with `all_of`, `any_of`, and `not_`, then call `enforce` in your
request handler.

```python
from dataclasses import dataclass

from masoon import (
    Authorizer,
    Identity,
    InMemoryRoleAssignmentStore,
    PermissionDeniedError,
    Policy,
    Role,
    any_of,
    enforce,
    has_permission,
    is_owner,
)


@dataclass(frozen=True)
class Post:
    id: int
    author_id: str
    published: bool


assignments = InMemoryRoleAssignmentStore()
assignments.assign(user_id="9", role_name="editor")
authorizer = Authorizer(
    roles=[Role(name="editor", permissions=frozenset({"posts:edit"}))],
    assignments=assignments,
)

# Editors can edit any post. Authors can edit their own posts.
can_edit: Policy[Post] = any_of(
    has_permission(authorizer, "posts:edit"),
    is_owner(lambda post: post.author_id),
)

alice = Identity(id="1", username="alice")
bob = Identity(id="2", username="bob")
editor = Identity(id="9", username="eve")
post = Post(id=7, author_id="1", published=True)

enforce(can_edit, alice, post)  # Allowed: Alice wrote the post.
enforce(can_edit, editor, post)  # Allowed: Eve is an editor.

try:
    enforce(can_edit, bob, post)
except PermissionDeniedError as error:
    print(error)  # Permission denied.
```

Write your own policies as plain functions, and combine them with the built-in ones:

```python
def is_published(identity: Identity, post: Post) -> bool:
    return post.published


# Anyone can read published posts. Authors can also read their own drafts.
can_read: Policy[Post] = any_of(is_published, is_owner(lambda post: post.author_id))
```

The building blocks:

| Function | Allows access when |
|---|---|
| `all_of(*policies)` | Every policy allows it. Checking stops at the first denial. |
| `any_of(*policies)` | At least one policy allows it. Checking stops at the first approval. |
| `not_(policy)` | The policy denies it. |
| `has_permission(authorizer, permission)` | The identity has the permission through its roles. |
| `is_owner(get_owner_id)` | `get_owner_id(resource)` equals the identity's ID. |

How policies work:

- **`enforce` raises `PermissionDeniedError`** when the policy denies access. The message
  is always `Permission denied.`, so it does not reveal which rule failed.
- **Policies must return a `bool`.** A policy that returns anything else, such as a string
  or `None`, raises `TypeError` instead of being treated as allowed. This catches mistakes
  like `return post.author_id` where `return post.author_id == identity.id` was meant.
- **`all_of()` and `any_of()` need at least one policy.** Calling them with none raises
  `ValueError`, because an empty `all_of` would allow everything.
- **Ownerless resources are denied.** If `get_owner_id` returns `None` or an empty
  string, `is_owner` denies access. An identity with an empty ID owns nothing, so an empty
  value never matches another empty value. Integer owner IDs are converted to strings
  before they are compared, and `bool` owner IDs raise `TypeError`.
- **Errors are not hidden.** If a policy raises an exception, it propagates to your code.

In a FastAPI application, call `add_exception_handlers(app)` once so that a
`PermissionDeniedError` raised by `enforce` returns 403 instead of 500. See
[Policies in FastAPI routes](#policies-in-fastapi-routes).

## FastAPI

The `fastapi` extra adds `MasoonFastAPI`, which provides FastAPI dependencies for
authentication and authorization. Create it once with your `SessionManager` and, if your
routes check permissions, your `Authorizer`.

```python
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel

from masoon import (
    Argon2PasswordHasher,
    Authenticator,
    Authorizer,
    Identity,
    InMemoryRoleAssignmentStore,
    InMemorySessionStore,
    InMemoryUserStore,
    InvalidCredentialsError,
    Role,
    SessionManager,
    StoredUser,
)
from masoon.contrib.fastapi import MasoonFastAPI, add_exception_handlers

hasher = Argon2PasswordHasher()
users = InMemoryUserStore()
users.add(
    StoredUser(
        id="1",
        username="alice",
        hashed_password=hasher.hash_password(password="correct horse battery staple"),
    ),
)

assignments = InMemoryRoleAssignmentStore()
assignments.assign(user_id="1", role_name="editor")

authenticator = Authenticator(store=users, hasher=hasher)
sessions = SessionManager(store=InMemorySessionStore(), validity=timedelta(days=1))
authorizer = Authorizer(
    roles=[Role(name="editor", permissions=frozenset({"posts:read", "posts:edit"}))],
    assignments=assignments,
)

masoon = MasoonFastAPI(sessions, authorizer)
app = FastAPI()
add_exception_handlers(app)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(credentials: LoginRequest) -> dict[str, str]:
    try:
        identity = authenticator.authenticate(
            username=credentials.username,
            password=credentials.password,
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        ) from None
    return {"access_token": sessions.create(identity), "token_type": "bearer"}


# Works whether the token was sent in the header or in the cookie.
@app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    token: Annotated[str, Depends(masoon.current_token)],
    response: Response,
) -> None:
    sessions.revoke(token)
    response.delete_cookie(masoon.cookie_name)


# Any logged-in user.
@app.get("/me")
def me(identity: Annotated[Identity, Depends(masoon.current_identity)]) -> dict[str, str]:
    return {"id": identity.id, "username": identity.username}


# Only users with the posts:edit permission.
@app.put("/posts/{post_id}")
def edit_post(
    post_id: int,
    identity: Annotated[Identity, Depends(masoon.require_permission("posts:edit"))],
) -> dict[str, str]:
    return {"edited": str(post_id), "by": identity.username}
```

Clients send the token from `/login` in the `Authorization` header:

```text
Authorization: Bearer <access_token>
```

How the integration works:

- **Where the token comes from.** The token is read from the `Authorization: Bearer`
  header. If there is no bearer header, it is read from a cookie named `session`. Change
  the name with `MasoonFastAPI(sessions, authorizer, cookie_name="...")`. If a bearer
  header is present but invalid, the request is rejected; the cookie is not used instead.
- **401 Unauthorized.** A missing, invalid, expired, or revoked token always returns the
  same response, `{"detail": "Not authenticated"}`, with a `WWW-Authenticate: Bearer`
  header. The client cannot tell why the token was rejected.
- **403 Forbidden.** A logged-in user without the required permission gets
  `{"detail": "Forbidden"}`. The response does not name the missing permission.
- **Logging out.** `current_token` returns the validated session token of the request,
  from the header or the cookie, so a logout route can revoke it. It responds with 401 in
  the same cases as `current_identity`. `masoon.cookie_name` gives the cookie name, so the
  route can also clear the cookie.
- **One check per request.** The token is validated only once, even if a route uses
  `current_identity`, `current_token`, and `require_permission` together.
- **Setup errors.** Calling `require_permission` without passing an `Authorizer` raises
  `ValueError` when your routes are defined, not during a request.
- **API docs.** Both token locations appear in FastAPI's `/docs` page, so you can test
  protected routes with the **Authorize** button.

### Policies in FastAPI routes

Policies usually depend on a resource that the route loads first, so call `enforce` inside
the route. `add_exception_handlers(app)` turns the `PermissionDeniedError` it raises into
the same 403 response that `require_permission` returns:

```python
from dataclasses import dataclass

from masoon import Policy, enforce, is_owner


@dataclass(frozen=True)
class Post:
    id: int
    author_id: str


POSTS = {1: Post(id=1, author_id="1"), 2: Post(id=2, author_id="2")}
can_delete: Policy[Post] = is_owner(lambda post: post.author_id)


@app.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_post(
    post_id: int,
    identity: Annotated[Identity, Depends(masoon.current_identity)],
) -> None:
    post = POSTS.get(post_id)
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    enforce(can_delete, identity, post)  # 403 if the user is not the author.
    del POSTS[post_id]
```

Without `add_exception_handlers`, FastAPI treats the error as a bug and returns
`500 Internal Server Error`. The handler only changes `PermissionDeniedError`; other
exceptions behave as before.

Define the login route with `def`, not `async def`. Argon2 is deliberately slow, and FastAPI
runs `def` routes in a thread pool so that hashing does not block other requests.

If you store the token in a cookie instead of returning it, set the cookie with
`httponly=True`, `secure=True`, and `samesite="lax"` so that scripts cannot read it and it
is only sent over HTTPS.

`MasoonFastAPI` is imported from `masoon.contrib.fastapi`, not from `masoon`, so that
`import masoon` keeps working without FastAPI installed.

## Using your own database

`Authenticator` accepts any object that matches the `UserStore` protocol. There is no
base class to inherit from: your store only needs a `get_by_username` method that returns
a user record, or `None` if the user does not exist.

A user record needs three readable attributes, all strings: `id`, `username`, and
`hashed_password`. If your database uses another type for IDs, such as integers, convert
them to strings in your store.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class UserRow:
    id: str
    username: str
    hashed_password: str


class DatabaseUserStore:
    def __init__(self, connection) -> None:
        self._connection = connection

    def get_by_username(self, username: str) -> UserRow | None:
        row = self._connection.execute(
            "SELECT id, username, hashed_password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return UserRow(id=str(row[0]), username=row[1], hashed_password=row[2])
```

Pass it to the authenticator like any other store:

```python
authenticator = Authenticator(store=DatabaseUserStore(connection), hasher=hasher)
```

### Sessions in your own database

`SessionManager` accepts any object that matches the `SessionStore` protocol. Your store
needs three methods, all working with token hashes:

| Method | What it does |
|---|---|
| `add(session)` | Save a new session. |
| `get_by_token_hash(token_hash)` | Return the session, or `None` if it does not exist. |
| `delete(token_hash)` | Delete the session. Do nothing if it does not exist. |

A session record has five readable attributes: `token_hash`, `user_id`, and `username`
are strings, and `created_at` and `expires_at` are timezone-aware `datetime` values in UTC.
Masoon passes a `StoredSession` to `add`, which you can store as it is.

```python
from datetime import datetime

from masoon import SessionRecord, StoredSession


class DatabaseSessionStore:
    def __init__(self, connection) -> None:
        self._connection = connection

    def add(self, session: SessionRecord) -> None:
        self._connection.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
            (
                session.token_hash,
                session.user_id,
                session.username,
                session.created_at.isoformat(),
                session.expires_at.isoformat(),
            ),
        )

    def get_by_token_hash(self, token_hash: str) -> SessionRecord | None:
        row = self._connection.execute(
            "SELECT token_hash, user_id, username, created_at, expires_at"
            " FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return StoredSession(
            token_hash=row[0],
            user_id=row[1],
            username=row[2],
            created_at=datetime.fromisoformat(row[3]),
            expires_at=datetime.fromisoformat(row[4]),
        )

    def delete(self, token_hash: str) -> None:
        self._connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
```

### Role assignments in your own database

`Authorizer` accepts any object that matches the `RoleAssignmentStore` protocol. Your
store needs one method, `get_roles(user_id)`, which returns the names of the user's roles
as a `frozenset` of strings, or an empty `frozenset` if the user has none. Roles
themselves stay in your code; the database only records role names.

```python
class DatabaseRoleAssignmentStore:
    def __init__(self, connection) -> None:
        self._connection = connection

    def get_roles(self, user_id: str) -> frozenset[str]:
        rows = self._connection.execute(
            "SELECT role_name FROM user_roles WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        return frozenset(row[0] for row in rows)
```

## Errors

All exceptions raised by Masoon inherit from `MasoonError`.

| Exception | Raised when |
|---|---|
| `InvalidCredentialsError` | The username does not exist or the password is wrong. |
| `InvalidSessionError` | A session token is unknown, expired, or revoked. |
| `PermissionDeniedError` | An identity does not have a required permission, or a policy denies access. For permissions, the error names the permission. |
| `UserAlreadyExistsError` | A user is added to `InMemoryUserStore` with a username that is already taken. |
| `AuthenticationError` | Base class for all authentication errors. |
| `AuthorizationError` | Base class for all authorization errors. |
| `MasoonError` | Base class for every Masoon error. |

## License

Licensed under the [Apache License 2.0](LICENSE).
