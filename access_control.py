"""Access control service for Secure Vault."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from metadata_manager import MetadataManager, PermissionLevel


class PermissionDeniedError(Exception):
    """Raised when a user attempts an operation without sufficient permissions."""


@dataclass
class AccessDecision:
    """Represents the outcome of a permission check."""

    user_id: int
    file_id: str
    permission: PermissionLevel
    allowed: bool


class AccessControl:
    """Service responsible for evaluating and managing file permissions."""

    def __init__(self, metadata_manager: Optional[MetadataManager] = None) -> None:
        self._metadata_manager = metadata_manager or MetadataManager()

    @property
    def metadata_manager(self) -> MetadataManager:
        """Expose the underlying metadata manager."""

        return self._metadata_manager

    def register_owner(self, file_id: str, owner_user_id: int) -> None:
        """Ensure the owner has full control of the file."""

        for permission in PermissionLevel:
            self._metadata_manager.grant_permission(
                file_id=file_id,
                user_id=owner_user_id,
                permission=permission,
                granted_by=owner_user_id,
            )

    def grant_access(
        self,
        grantor_user_id: int,
        target_user_id: int,
        file_id: str,
        permission: PermissionLevel,
    ) -> None:
        """Grant a specific permission to another user."""

        self.require_access(grantor_user_id, file_id, PermissionLevel.MANAGE)
        if not self._metadata_manager.grant_permission(
            file_id=file_id,
            user_id=target_user_id,
            permission=permission,
            granted_by=grantor_user_id,
        ):
            raise PermissionDeniedError("Failed to persist permission grant")

    def revoke_access(
        self,
        grantor_user_id: int,
        target_user_id: int,
        file_id: str,
        permissions: Optional[Sequence[PermissionLevel]] = None,
    ) -> None:
        """Revoke one or multiple permissions from a user."""

        self.require_access(grantor_user_id, file_id, PermissionLevel.MANAGE)

        if permissions is None:
            # Revoke all permissions
            self._metadata_manager.revoke_permission(file_id, target_user_id, None)
            return

        for permission in permissions:
            self._metadata_manager.revoke_permission(file_id, target_user_id, permission)

    def has_access(self, user_id: int, file_id: str, permission: PermissionLevel) -> bool:
        """Check whether a user has the requested permission."""

        return self._metadata_manager.has_permission(file_id, user_id, permission)

    def require_access(self, user_id: int, file_id: str, permission: PermissionLevel) -> None:
        """Ensure the user possesses the required permission."""

        if not self.has_access(user_id, file_id, permission):
            raise PermissionDeniedError(
                f"User {user_id} lacks {permission.value} access to file {file_id}"
            )

    def evaluate(
        self, user_id: int, file_id: str, permission: PermissionLevel
    ) -> AccessDecision:
        """Return a structured decision object for auditing or logging."""

        allowed = self.has_access(user_id, file_id, permission)
        return AccessDecision(
            user_id=user_id, file_id=file_id, permission=permission, allowed=allowed
        )

    def list_authorized_users(self, file_id: str) -> Iterable[int]:
        """Yield user IDs with active permissions for the given file."""

        permissions = self._metadata_manager.list_permissions(file_id)
        for permission in permissions:
            yield permission.user_id
