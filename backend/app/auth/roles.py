"""
VisionOS-AI
Enterprise Role Registry

This module defines all built-in system roles and helper utilities.

The database stores roles dynamically, but these constants represent
the default system roles that are automatically seeded and protected.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class SystemRole(str, Enum):
    """
    Built-in system roles.

    These roles are seeded into the database during initialization
    and should never be deleted.
    """

    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"

    SECURITY_ADMIN = "security_admin"

    AI_ENGINEER = "ai_engineer"

    DOCUMENT_MANAGER = "document_manager"

    OCR_OPERATOR = "ocr_operator"

    USER = "user"


# ---------------------------------------------------------
# Role Hierarchy
# ---------------------------------------------------------

ROLE_HIERARCHY: dict[SystemRole, int] = {
    SystemRole.SUPER_ADMIN: 100,
    SystemRole.ADMIN: 90,
    SystemRole.SECURITY_ADMIN: 80,
    SystemRole.AI_ENGINEER: 70,
    SystemRole.DOCUMENT_MANAGER: 60,
    SystemRole.OCR_OPERATOR: 50,
    SystemRole.USER: 10,
}


# ---------------------------------------------------------
# Default Roles
# ---------------------------------------------------------

DEFAULT_SYSTEM_ROLES = [
    {
        "name": SystemRole.SUPER_ADMIN.value,
        "display_name": "Super Administrator",
        "description": "Full unrestricted access.",
        "is_system": True,
    },
    {
        "name": SystemRole.ADMIN.value,
        "display_name": "Administrator",
        "description": "Administrative access.",
        "is_system": True,
    },
    {
        "name": SystemRole.SECURITY_ADMIN.value,
        "display_name": "Security Administrator",
        "description": "Security and authentication management.",
        "is_system": True,
    },
    {
        "name": SystemRole.AI_ENGINEER.value,
        "display_name": "AI Engineer",
        "description": "Manage AI models and inference.",
        "is_system": True,
    },
    {
        "name": SystemRole.DOCUMENT_MANAGER.value,
        "display_name": "Document Manager",
        "description": "Manage uploaded documents.",
        "is_system": True,
    },
    {
        "name": SystemRole.OCR_OPERATOR.value,
        "display_name": "OCR Operator",
        "description": "Execute OCR jobs.",
        "is_system": True,
    },
    {
        "name": SystemRole.USER.value,
        "display_name": "User",
        "description": "Standard application user.",
        "is_system": True,
    },
]


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def get_default_roles() -> list[dict]:
    """
    Returns all default system roles.
    """
    return DEFAULT_SYSTEM_ROLES.copy()


def get_role_names() -> list[str]:
    """
    Returns every role name.
    """
    return [role.value for role in SystemRole]


def role_exists(role: str) -> bool:
    """
    Checks whether a role exists.
    """
    return role in get_role_names()


def is_system_role(role: str | SystemRole) -> bool:
    """
    Returns True if the role is one of the built-in system roles.
    """
    value = role.value if isinstance(role, SystemRole) else role
    return value in get_role_names()


def is_admin(role: str | SystemRole) -> bool:
    """
    Returns True if role has administrator privileges.
    """
    value = role.value if isinstance(role, SystemRole) else role

    return value in {
        SystemRole.SUPER_ADMIN.value,
        SystemRole.ADMIN.value,
    }


def is_super_admin(role: str | SystemRole) -> bool:
    """
    Returns True if role is Super Administrator.
    """
    value = role.value if isinstance(role, SystemRole) else role
    return value == SystemRole.SUPER_ADMIN.value


def is_privileged(role: str | SystemRole) -> bool:
    """
    Returns True if the role is considered privileged.
    """
    value = role.value if isinstance(role, SystemRole) else role

    return value in {
        SystemRole.SUPER_ADMIN.value,
        SystemRole.ADMIN.value,
        SystemRole.SECURITY_ADMIN.value,
    }


def hierarchy_level(role: str | SystemRole) -> int:
    """
    Returns hierarchy level of a role.

    Unknown roles return zero.
    """
    value = role.value if isinstance(role, SystemRole) else role

    try:
        return ROLE_HIERARCHY[SystemRole(value)]
    except Exception:
        return 0


def can_manage_role(
    actor: str | SystemRole,
    target: str | SystemRole,
) -> bool:
    """
    Determines whether one role can manage another.

    Rules
    -----
    Higher hierarchy can manage lower hierarchy.

    Same hierarchy cannot manage itself.

    Lower hierarchy cannot manage higher hierarchy.
    """

    actor_level = hierarchy_level(actor)
    target_level = hierarchy_level(target)

    return actor_level > target_level


def highest_role(
    roles: Iterable[str],
) -> str | None:
    """
    Returns the highest privilege role from a collection.

    Example
    -------
    ["user", "admin"]

    returns

    "admin"
    """

    highest = None
    highest_value = -1

    for role in roles:
        level = hierarchy_level(role)

        if level > highest_value:
            highest = role
            highest_value = level

    return highest


def sort_roles(
    roles: Iterable[str],
) -> list[str]:
    """
    Returns roles sorted by privilege.

    Highest privilege first.
    """

    return sorted(
        roles,
        key=hierarchy_level,
        reverse=True,
    )
