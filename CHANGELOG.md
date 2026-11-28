# Changelog

All notable changes to Masoon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While Masoon
is below 1.0.0, minor releases may include breaking changes.

## [Unreleased]

## [0.5.1] - 2026-11-28

### Fixed

- `add_exception_handlers(app)` in `masoon.contrib.fastapi` now also turns an
  `InvalidSessionError` raised inside a route, for example when the route calls
  `SessionManager.validate` itself, into the standard 401 response with
  `{"detail": "Not authenticated"}` and a `WWW-Authenticate: Bearer` header. Previously,
  FastAPI returned a 500 error.

## [0.5.0] - 2026-11-26

### Added

- Composable authorization policies in `masoon.authz.policies`, for decisions that depend
  on the resource being accessed:
  - `Policy[R]` type for any function that takes an identity and a resource and returns
    a `bool`.
  - `all_of`, `any_of`, and `not_` to combine policies. Checking stops as soon as the
    result is known.
  - `has_permission` to use role-based permissions inside a policy.
  - `is_owner` to allow access to the owner of a resource. Resources whose owner ID is
    `None` or an empty string are denied, as are identities with an empty ID. Integer
    owner IDs are converted to strings, and `bool` owner IDs raise `TypeError`.
  - `enforce` to raise `PermissionDeniedError` when a policy denies access.
- `add_exception_handlers(app)` in `masoon.contrib.fastapi`, which turns a
  `PermissionDeniedError` raised inside a route, for example by `enforce`, into a 403
  response with `{"detail": "Forbidden"}` instead of a 500 error.
- Policies that return anything other than a `bool` raise `TypeError` instead of being
  treated as allowed.
- `all_of()` and `any_of()` without policies raise `ValueError`.
- Python 3.12, 3.13, and 3.14 classifiers.

### Changed

- `PermissionDeniedError` can be raised without a permission name. Its message is then
  `Permission denied.`.
- `.gitignore` covers tool caches, coverage files, environment files, and macOS files.
- CI now runs the test suite on Python 3.12, 3.13, and 3.14, with both the highest and the
  lowest supported versions of every dependency.
- Dependabot keeps GitHub Actions and `uv.lock` up to date monthly, without raising the
  minimum supported dependency versions.

## [0.4.0] - 2026-11-19

### Added

- FastAPI integration in `masoon.contrib.fastapi`, available with the `fastapi` extra:
  `pip install 'masoon[fastapi]'`.
- `MasoonFastAPI` with three dependencies:
  - `current_identity` returns the identity of the logged-in user.
  - `current_token` returns the validated session token, for logout routes.
  - `require_permission(permission)` requires the user to have a permission.
- Session tokens are read from the `Authorization: Bearer` header, or from a cookie when no
  bearer header is present. The cookie name is configurable.
- Every authentication failure returns the same 401 response with a
  `WWW-Authenticate: Bearer` header. A missing permission returns 403 without naming the
  permission.

## [0.3.0] - 2026-11-13

### Added

- Role-based access control with `Authorizer`, which provides `has_permission`, `require`,
  and `permissions_for`.
- `Role` type with a name and a set of permissions. Permissions are always stored as a
  `frozenset`, so a role cannot change after it is created.
- `RoleAssignmentStore` protocol for storing which roles each user has, and
  `InMemoryRoleAssignmentStore` for tests and examples.
- `AuthorizationError` and `PermissionDeniedError`.
- Access is denied by default, role names that are not defined in code grant nothing, and
  permissions match exactly.

## [0.2.0] - 2026-11-11

### Added

- Session tokens with `SessionManager`, which creates, validates, and revokes sessions.
- Sessions expire after a configurable validity period. Expired sessions are deleted when
  they are validated.
- Only SHA-256 hashes of session tokens are stored, never the tokens themselves.
- `SessionRecord` and `SessionStore` protocols for storing sessions in any database, and
  `InMemorySessionStore` for tests and examples.
- `InvalidSessionError` for unknown, expired, and revoked tokens.

## [0.1.0] - 2026-11-08

### Added

- Username and password authentication with `Authenticator`.
- `PasswordHasher` protocol and `Argon2PasswordHasher`, available with the `argon2` extra:
  `pip install 'masoon[argon2]'`.
- `UserRecord` and `UserStore` protocols for using any database, and `InMemoryUserStore`
  for tests and examples.
- `Identity` type for authenticated users.
- Error hierarchy: `MasoonError`, `AuthenticationError`, `InvalidCredentialsError`, and
  `UserAlreadyExistsError`.
- A wrong password and an unknown username raise the same error and take about the same
  time, so attackers cannot discover which usernames exist.

[Unreleased]: https://github.com/getmasoon/masoon/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/getmasoon/masoon/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/getmasoon/masoon/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/getmasoon/masoon/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/getmasoon/masoon/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/getmasoon/masoon/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/getmasoon/masoon/releases/tag/v0.1.0
