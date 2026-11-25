"""Combine authorization rules that depend on the resource being accessed.

A policy is a function that takes an identity and a resource and returns ``True`` if the
identity is allowed to access the resource. Roles answer "can editors edit posts?";
policies answer "can this user edit this post?".
"""

from collections.abc import Callable

from masoon.authz.rbac import Authorizer
from masoon.errors import PermissionDeniedError
from masoon.types import Identity

type Policy[R] = Callable[[Identity, R], bool]
"""A function that returns whether an identity may access a resource of type ``R``."""


def _check[R](policy: Policy[R], identity: Identity, resource: R) -> bool:
    """Call a policy and return its result, which must be exactly ``True`` or ``False``.

    A policy that returns anything else, such as a string or ``None``, has a bug. Treating
    a non-empty string as "allowed" would grant access by mistake, so it is rejected.

    Raises:
        TypeError: If the policy does not return a ``bool``.

    """
    result = policy(identity, resource)
    if not isinstance(result, bool):
        name = getattr(policy, "__qualname__", repr(policy))
        msg = f"Policy {name} returned {type(result).__name__}, expected bool."
        raise TypeError(msg)
    return result


def all_of[R](*policies: Policy[R]) -> Policy[R]:
    """Return a policy that allows access only if every given policy allows it.

    The policies are checked in order, and checking stops at the first one that denies
    access.

    Raises:
        ValueError: If no policies are given. An empty ``all_of`` would allow everything.

    """
    if not policies:
        msg = "all_of() requires at least one policy."
        raise ValueError(msg)

    def combined(identity: Identity, resource: R) -> bool:
        return all(_check(policy, identity, resource) for policy in policies)

    return combined


def any_of[R](*policies: Policy[R]) -> Policy[R]:
    """Return a policy that allows access if at least one given policy allows it.

    The policies are checked in order, and checking stops at the first one that allows
    access.

    Raises:
        ValueError: If no policies are given.

    """
    if not policies:
        msg = "any_of() requires at least one policy."
        raise ValueError(msg)

    def combined(identity: Identity, resource: R) -> bool:
        return any(_check(policy, identity, resource) for policy in policies)

    return combined


def not_[R](policy: Policy[R]) -> Policy[R]:
    """Return a policy that allows access exactly when the given policy denies it."""

    def negated(identity: Identity, resource: R) -> bool:
        return not _check(policy, identity, resource)

    return negated


def has_permission(authorizer: Authorizer, permission: str) -> Policy[object]:
    """Return a policy that allows access if the identity has a permission through its roles.

    The resource is ignored, so this policy can be combined with policies for any resource
    type.
    """

    def check(identity: Identity, _resource: object) -> bool:
        return authorizer.has_permission(identity, permission)

    return check


def is_owner[R](get_owner_id: Callable[[R], str | int | None]) -> Policy[R]:
    """Return a policy that allows access if the identity owns the resource.

    ``get_owner_id`` returns the ID of the resource's owner. Integer IDs are converted to
    strings before they are compared with ``identity.id``.

    A resource whose owner ID is ``None`` or an empty string is not owned by anyone, and an
    identity with an empty ID owns nothing, so access is denied in both cases. This keeps
    an empty value in the database from ever matching another empty value.

    Raises:
        TypeError: If ``get_owner_id`` returns a ``bool``. ``True`` and ``False`` are not
            valid IDs, even though Python treats them as integers.

    """

    def owned_by(identity: Identity, resource: R) -> bool:
        owner_id = get_owner_id(resource)
        if isinstance(owner_id, bool):
            msg = f"Owner ID must be a str or int, not bool (got {owner_id!r})."
            raise TypeError(msg)
        if owner_id is None or owner_id == "" or identity.id == "":
            return False
        return str(owner_id) == identity.id

    return owned_by


def enforce[R](policy: Policy[R], identity: Identity, resource: R) -> None:
    """Raise if the policy denies the identity access to the resource.

    Raises:
        PermissionDeniedError: If the policy denies access. The error does not say which
            part of the policy failed.
        TypeError: If the policy does not return a ``bool``.

    """
    if not _check(policy, identity, resource):
        raise PermissionDeniedError
