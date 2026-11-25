from collections.abc import Callable
from dataclasses import dataclass

import pytest

from masoon import (
    Authorizer,
    Identity,
    InMemoryRoleAssignmentStore,
    PermissionDeniedError,
    Policy,
    Role,
    all_of,
    any_of,
    enforce,
    has_permission,
    is_owner,
    not_,
)


@dataclass(frozen=True, slots=True)
class Post:
    author_id: str | None


ALICE = Identity(id="1", username="alice")
BOB = Identity(id="2", username="bob")
EDITOR = Identity(id="9", username="editor")

ALICES_POST = Post(author_id="1")
ORPHAN_POST = Post(author_id=None)


def allow(_identity: Identity, _resource: Post) -> bool:
    return True


def deny(_identity: Identity, _resource: Post) -> bool:
    return False


def must_not_be_called(_identity: Identity, _resource: Post) -> bool:
    pytest.fail("This policy should not have been checked.")


def returns_string(_identity: Identity, resource: Post):  # noqa: ANN201
    return resource.author_id


@pytest.fixture
def authorizer() -> Authorizer:
    assignments = InMemoryRoleAssignmentStore()
    assignments.assign(user_id=EDITOR.id, role_name="editor")
    return Authorizer(
        roles=[Role(name="editor", permissions=frozenset({"posts:edit"}))],
        assignments=assignments,
    )


# all_of


def test_all_of_allows_if_every_policy_allows() -> None:
    assert all_of(allow, allow)(ALICE, ALICES_POST) is True


def test_all_of_denies_if_any_policy_denies() -> None:
    assert all_of(allow, deny)(ALICE, ALICES_POST) is False


def test_all_of_stops_at_first_denial() -> None:
    assert all_of(deny, must_not_be_called)(ALICE, ALICES_POST) is False


def test_all_of_without_policies_raises() -> None:
    with pytest.raises(ValueError, match="at least one policy"):
        all_of()


# any_of


def test_any_of_allows_if_one_policy_allows() -> None:
    assert any_of(deny, allow)(ALICE, ALICES_POST) is True


def test_any_of_denies_if_every_policy_denies() -> None:
    assert any_of(deny, deny)(ALICE, ALICES_POST) is False


def test_any_of_stops_at_first_approval() -> None:
    assert any_of(allow, must_not_be_called)(ALICE, ALICES_POST) is True


def test_any_of_without_policies_raises() -> None:
    with pytest.raises(ValueError, match="at least one policy"):
        any_of()


# not_


def test_not_flips_allow_to_deny() -> None:
    assert not_(allow)(ALICE, ALICES_POST) is False


def test_not_flips_deny_to_allow() -> None:
    assert not_(deny)(ALICE, ALICES_POST) is True


# has_permission


def test_has_permission_allows_identity_with_permission(authorizer: Authorizer) -> None:
    assert has_permission(authorizer, "posts:edit")(EDITOR, ALICES_POST) is True


def test_has_permission_denies_identity_without_permission(authorizer: Authorizer) -> None:
    assert has_permission(authorizer, "posts:edit")(BOB, ALICES_POST) is False


# is_owner


def test_is_owner_allows_owner() -> None:
    assert is_owner(lambda post: post.author_id)(ALICE, ALICES_POST) is True


def test_is_owner_denies_other_user() -> None:
    assert is_owner(lambda post: post.author_id)(BOB, ALICES_POST) is False


def test_is_owner_denies_resource_without_owner() -> None:
    assert is_owner(lambda post: post.author_id)(ALICE, ORPHAN_POST) is False


def test_is_owner_does_not_treat_none_as_a_user_id() -> None:
    user_named_none = Identity(id="None", username="none")

    assert is_owner(lambda post: post.author_id)(user_named_none, ORPHAN_POST) is False


def test_is_owner_accepts_integer_owner_ids() -> None:
    assert is_owner(lambda _post: 1)(ALICE, ALICES_POST) is True


def test_is_owner_denies_empty_owner_id() -> None:
    user_with_empty_id = Identity(id="", username="empty")

    assert is_owner(lambda _post: "")(ALICE, ALICES_POST) is False
    assert is_owner(lambda _post: "")(user_with_empty_id, ALICES_POST) is False


def test_is_owner_denies_identity_with_empty_id() -> None:
    user_with_empty_id = Identity(id="", username="empty")

    assert is_owner(lambda post: post.author_id)(user_with_empty_id, ALICES_POST) is False


@pytest.mark.parametrize("owner_id", [True, False])
def test_is_owner_rejects_bool_owner_ids(owner_id: bool) -> None:  # noqa: FBT001
    user_named_true = Identity(id=str(owner_id), username="bool")
    policy = is_owner(lambda _post: owner_id)

    with pytest.raises(TypeError, match="not bool"):
        policy(user_named_true, ALICES_POST)


# enforce


def test_enforce_allows_without_raising() -> None:
    enforce(allow, ALICE, ALICES_POST)


def test_enforce_raises_generic_error_when_denied() -> None:
    with pytest.raises(PermissionDeniedError) as error:
        enforce(deny, ALICE, ALICES_POST)

    assert str(error.value) == "Permission denied."
    assert error.value.permission_name is None


# Policies that return something other than a bool


def test_enforce_rejects_non_bool_result() -> None:
    with pytest.raises(TypeError, match="returns_string returned str, expected bool"):
        enforce(returns_string, BOB, ALICES_POST)


@pytest.mark.parametrize("combinator", [all_of, any_of, not_])
def test_combinators_reject_non_bool_result(
    combinator: Callable[..., Callable[[Identity, Post], object]],
) -> None:
    policy = combinator(returns_string)

    with pytest.raises(TypeError, match="expected bool"):
        policy(BOB, ALICES_POST)


# Errors inside policies


def test_exception_in_policy_propagates() -> None:
    def broken(_identity: Identity, _resource: Post) -> bool:
        msg = "database unavailable"
        raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="database unavailable"):
        enforce(any_of(deny, broken), ALICE, ALICES_POST)


# Combining roles and ownership


def test_editors_and_authors_can_edit_but_others_cannot(authorizer: Authorizer) -> None:
    can_edit: Policy[Post] = any_of(
        has_permission(authorizer, "posts:edit"),
        is_owner(lambda post: post.author_id),
    )

    enforce(can_edit, ALICE, ALICES_POST)
    enforce(can_edit, EDITOR, ALICES_POST)
    with pytest.raises(PermissionDeniedError):
        enforce(can_edit, BOB, ALICES_POST)
