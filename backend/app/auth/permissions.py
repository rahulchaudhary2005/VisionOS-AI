"""
VisionOS-AI
Enterprise Permission Registry

This module defines all built-in permissions used by the
authorization system.

Permissions are grouped by resource and follow the convention:

resource.action

Examples
--------
users.create
users.read
documents.upload
ocr.run
ai.chat
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class Permission(str, Enum):
    # ==========================================================
    # User Management
    # ==========================================================

    USERS_CREATE = "users.create"
    USERS_READ = "users.read"
    USERS_UPDATE = "users.update"
    USERS_DELETE = "users.delete"

    # ==========================================================
    # Role Management
    # ==========================================================

    ROLES_CREATE = "roles.create"
    ROLES_READ = "roles.read"
    ROLES_UPDATE = "roles.update"
    ROLES_DELETE = "roles.delete"

    # ==========================================================
    # Permission Management
    # ==========================================================

    PERMISSIONS_CREATE = "permissions.create"
    PERMISSIONS_READ = "permissions.read"
    PERMISSIONS_ASSIGN = "permissions.assign"
    PERMISSIONS_REVOKE = "permissions.revoke"

    # ==========================================================
    # Document Intelligence
    # ==========================================================

    DOCUMENT_UPLOAD = "documents.upload"
    DOCUMENT_READ = "documents.read"
    DOCUMENT_UPDATE = "documents.update"
    DOCUMENT_DELETE = "documents.delete"
    DOCUMENT_DOWNLOAD = "documents.download"

    # ==========================================================
    # OCR
    # ==========================================================

    OCR_RUN = "ocr.run"

    # ==========================================================
    # Embeddings
    # ==========================================================

    EMBEDDING_CREATE = "embedding.create"
    EMBEDDING_DELETE = "embedding.delete"

    # ==========================================================
    # Vector Database
    # ==========================================================

    VECTOR_SEARCH = "vector.search"
    VECTOR_DELETE = "vector.delete"

    # ==========================================================
    # RAG
    # ==========================================================

    RAG_QUERY = "rag.query"

    # ==========================================================
    # AI
    # ==========================================================

    AI_CHAT = "ai.chat"
    AI_INFERENCE = "ai.inference"
    AI_TRAIN = "ai.training"

    # ==========================================================
    # Storage
    # ==========================================================

    STORAGE_READ = "storage.read"
    STORAGE_WRITE = "storage.write"
    STORAGE_DELETE = "storage.delete"

    # ==========================================================
    # Audit
    # ==========================================================

    AUDIT_READ = "audit.read"
    AUDIT_EXPORT = "audit.export"

    # ==========================================================
    # Settings
    # ==========================================================

    SETTINGS_READ = "settings.read"
    SETTINGS_UPDATE = "settings.update"

    # ==========================================================
    # System
    # ==========================================================

    SYSTEM_MONITOR = "system.monitor"
    SYSTEM_SHUTDOWN = "system.shutdown"


# ==========================================================
# Permission Groups
# ==========================================================

USER_PERMISSIONS = [
    Permission.USERS_CREATE,
    Permission.USERS_READ,
    Permission.USERS_UPDATE,
    Permission.USERS_DELETE,
]

ROLE_PERMISSIONS = [
    Permission.ROLES_CREATE,
    Permission.ROLES_READ,
    Permission.ROLES_UPDATE,
    Permission.ROLES_DELETE,
]

PERMISSION_PERMISSIONS = [
    Permission.PERMISSIONS_CREATE,
    Permission.PERMISSIONS_READ,
    Permission.PERMISSIONS_ASSIGN,
    Permission.PERMISSIONS_REVOKE,
]

DOCUMENT_PERMISSIONS = [
    Permission.DOCUMENT_UPLOAD,
    Permission.DOCUMENT_READ,
    Permission.DOCUMENT_UPDATE,
    Permission.DOCUMENT_DELETE,
    Permission.DOCUMENT_DOWNLOAD,
]

OCR_PERMISSIONS = [
    Permission.OCR_RUN,
]

AI_PERMISSIONS = [
    Permission.AI_CHAT,
    Permission.AI_INFERENCE,
    Permission.AI_TRAIN,
]

VECTOR_PERMISSIONS = [
    Permission.VECTOR_SEARCH,
    Permission.VECTOR_DELETE,
]

EMBEDDING_PERMISSIONS = [
    Permission.EMBEDDING_CREATE,
    Permission.EMBEDDING_DELETE,
]

STORAGE_PERMISSIONS = [
    Permission.STORAGE_READ,
    Permission.STORAGE_WRITE,
    Permission.STORAGE_DELETE,
]

AUDIT_PERMISSIONS = [
    Permission.AUDIT_READ,
    Permission.AUDIT_EXPORT,
]

SETTINGS_PERMISSIONS = [
    Permission.SETTINGS_READ,
    Permission.SETTINGS_UPDATE,
]

SYSTEM_PERMISSIONS = [
    Permission.SYSTEM_MONITOR,
    Permission.SYSTEM_SHUTDOWN,
]


# ==========================================================
# Registry
# ==========================================================

PERMISSION_GROUPS: dict[str, list[Permission]] = {
    "users": USER_PERMISSIONS,
    "roles": ROLE_PERMISSIONS,
    "permissions": PERMISSION_PERMISSIONS,
    "documents": DOCUMENT_PERMISSIONS,
    "ocr": OCR_PERMISSIONS,
    "ai": AI_PERMISSIONS,
    "vector": VECTOR_PERMISSIONS,
    "embedding": EMBEDDING_PERMISSIONS,
    "storage": STORAGE_PERMISSIONS,
    "audit": AUDIT_PERMISSIONS,
    "settings": SETTINGS_PERMISSIONS,
    "system": SYSTEM_PERMISSIONS,
}


# ==========================================================
# Helper Functions
# ==========================================================

def get_all_permissions() -> list[str]:
    """
    Returns every permission string.
    """
    return [permission.value for permission in Permission]


def permission_exists(permission: str) -> bool:
    """
    Returns True if the permission exists.
    """
    return permission in get_all_permissions()


def get_group(name: str) -> list[str]:
    """
    Returns all permissions belonging to a group.

    Example
    -------
    get_group("documents")
    """

    permissions = PERMISSION_GROUPS.get(name.lower(), [])

    return [permission.value for permission in permissions]


def get_groups() -> dict[str, list[str]]:
    """
    Returns all permission groups.
    """

    return {
        group: [permission.value for permission in permissions]
        for group, permissions in PERMISSION_GROUPS.items()
    }


def validate_permissions(
    permissions: Iterable[str],
) -> bool:
    """
    Returns True if all permissions exist.
    """

    valid = set(get_all_permissions())

    return all(permission in valid for permission in permissions)
