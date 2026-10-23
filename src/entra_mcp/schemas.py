"""Tool argument schemas. extra="forbid" everywhere; a UPN is validated by regex AND against the tenant
domain; numbers are bounded. Nothing here can carry a path, URL or query fragment.

The tenant domain is injected once at startup (set_domain) so the UPN validator is a pure function.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_DOMAIN = {"value": ""}
# local part: letters, digits, dot, underscore, hyphen; no consecutive dots, no leading/trailing dot
_UPN_RE = re.compile(r"^(?!\.)(?!.*\.\.)[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9.\-]{3,253}$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$")
_REASON_RE = re.compile(r"^[A-Za-z0-9 ,.;:#()/_'\-]{5,200}$")
_APPROVAL_RE = re.compile(r"^apr_[a-f0-9]{16}$")


def validate_group_name(v: str) -> str:
    if not isinstance(v, str) or not _GROUP_RE.fullmatch(v):
        raise ValueError("group must be a display name of letters, digits, spaces, '.', '_' or '-' (max 64), or a GUID")
    return v


def set_domain(domain: str) -> None:
    _DOMAIN["value"] = domain.lower()


def validate_upn(v: str) -> str:
    v = v.strip() if isinstance(v, str) else v
    if not isinstance(v, str) or not _UPN_RE.fullmatch(v) or len(v) > 256:
        raise ValueError("userPrincipalName must look like name@domain with letters, digits, '.', '_' or '-' only")
    local, _, domain = v.rpartition("@")
    if local.endswith(".") or local.startswith("."):
        raise ValueError("userPrincipalName local part cannot start or end with '.'")
    if _DOMAIN["value"] and domain.lower() != _DOMAIN["value"]:
        raise ValueError(f"userPrincipalName must be in the tenant domain {_DOMAIN['value']}")
    return v


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=False)


class UserArgs(_Args):
    upn: str = Field(description="User principal name, e.g. alice.test@contoso.onmicrosoft.com")

    @field_validator("upn")
    @classmethod
    def _upn(cls, v: str) -> str:
        return validate_upn(v)


class GetUserArgs(UserArgs):
    pass


class GetLastSignInArgs(UserArgs):
    pass


class ListUserGroupsArgs(UserArgs):
    pass


class ListAuthMethodsArgs(UserArgs):
    pass


class GetSignInLogsArgs(UserArgs):
    days: int = Field(default=7, ge=1, le=30, description="Look back this many days (1-30; P1 retains 30)")
    top: int = Field(default=20, ge=1, le=50, description="Maximum entries to return (1-50)")


class ListDevicesArgs(_Args):
    upn: str | None = Field(default=None, description="Only devices whose primary user is this UPN; omit for all")
    top: int = Field(default=20, ge=1, le=50, description="Maximum devices to return (1-50)")

    @field_validator("upn")
    @classmethod
    def _upn(cls, v: str | None) -> str | None:
        return validate_upn(v) if v is not None else None


class GetDeviceArgs(_Args):
    device_id: str = Field(description="Intune managed device id (GUID) from list_devices")

    @field_validator("device_id")
    @classmethod
    def _guid(cls, v: str) -> str:
        if not _GUID_RE.fullmatch(v.strip()):
            raise ValueError("device_id must be a GUID")
        return v.strip().lower()


# ---------------------------------------------------------------- write path (approval-gated)
class _WriteArgs(UserArgs):
    reason: str = Field(description="Ticket number or one-line justification; recorded in the approval and the audit log")

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        if not _REASON_RE.fullmatch(v):
            raise ValueError("reason must be 5-200 plain characters (letters, digits, spaces, basic punctuation)")
        return v


class DisableAccountArgs(_WriteArgs):
    pass


class EnableAccountArgs(_WriteArgs):
    pass


class ResetPasswordArgs(_WriteArgs):
    pass


class CreateTapArgs(_WriteArgs):
    lifetime_minutes: int = Field(default=60, ge=60, le=480, description="Validity of the pass, 60-480 minutes (the "
                                  "tenant TAP policy's default range; observed live: 10 was rejected with HTTP 400)")
    one_time_use: bool = Field(default=True, description="Pass can be used once (recommended)")


class RevokeSessionsArgs(_WriteArgs):
    pass


class GroupMembershipArgs(_WriteArgs):
    group: str = Field(description="Security group: exact display name (e.g. sg-vpn-users) or group id (GUID)")

    @field_validator("group")
    @classmethod
    def _group(cls, v: str) -> str:
        v = v.strip()
        if _GUID_RE.fullmatch(v):
            return v.lower()
        return validate_group_name(v)


class AddToGroupArgs(GroupMembershipArgs):
    pass


class RemoveFromGroupArgs(GroupMembershipArgs):
    pass


class _DeviceWriteArgs(_Args):
    device_id: str = Field(description="Intune managed device id (GUID); must be in the server's test_device_ids list")
    reason: str = Field(description="Ticket number or one-line justification")

    @field_validator("device_id")
    @classmethod
    def _guid(cls, v: str) -> str:
        if not _GUID_RE.fullmatch(v.strip()):
            raise ValueError("device_id must be a GUID")
        return v.strip().lower()

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        if not _REASON_RE.fullmatch(v):
            raise ValueError("reason must be 5-200 plain characters")
        return v


class SyncDeviceArgs(_DeviceWriteArgs):
    pass


class RebootDeviceArgs(_DeviceWriteArgs):
    pass


class ApproveArgs(_Args):
    approval_id: str = Field(description="Approval id returned by a write tool, e.g. apr_1a2b3c4d5e6f7a8b")

    @field_validator("approval_id")
    @classmethod
    def _aid(cls, v: str) -> str:
        if not _APPROVAL_RE.fullmatch(v):
            raise ValueError("approval_id must look like apr_ followed by 16 hex characters")
        return v


class ListPendingApprovalsArgs(_Args):
    pass


READ_TOOLS = ("get_user", "get_last_sign_in", "list_user_groups", "list_auth_methods", "get_sign_in_logs",
              "list_devices", "get_device")
WRITE_SCHEMAS: dict[str, type[_Args]] = {
    "disable_account": DisableAccountArgs,
    "enable_account": EnableAccountArgs,
    "reset_password": ResetPasswordArgs,
    "create_temporary_access_pass": CreateTapArgs,
    "revoke_sessions": RevokeSessionsArgs,
    "add_to_group": AddToGroupArgs,
    "remove_from_group": RemoveFromGroupArgs,
    "sync_device": SyncDeviceArgs,
    "reboot_device": RebootDeviceArgs,
}
APPROVAL_SCHEMAS: dict[str, type[_Args]] = {
    "approve": ApproveArgs,
    "list_pending_approvals": ListPendingApprovalsArgs,
}

SCHEMAS: dict[str, type[_Args]] = {
    "get_user": GetUserArgs,
    "get_last_sign_in": GetLastSignInArgs,
    "list_user_groups": ListUserGroupsArgs,
    "list_auth_methods": ListAuthMethodsArgs,
    "get_sign_in_logs": GetSignInLogsArgs,
    "list_devices": ListDevicesArgs,
    "get_device": GetDeviceArgs,
}

DESCRIPTIONS: dict[str, str] = {
    "get_user": "Read one user's profile from Entra ID: enabled state, display name, job title, department, "
                "created date, last password change. There is no 'locked out' flag in Microsoft Graph: smart lockout "
                "clears itself (60 s, growing) and cannot be read or cleared by API; use get_sign_in_logs to see "
                "failed sign-ins instead.",
    "get_last_sign_in": "Read a user's last interactive and non-interactive sign-in timestamps (Entra ID P1 "
                        "signInActivity). Microsoft documents this property as updating up to 24 hours late, so it returns "
                        "status=unknown when Graph has no value; for anything recent use get_sign_in_logs.",
    "list_user_groups": "List the groups and directory roles a user is a direct member of.",
    "list_auth_methods": "List a user's registered authentication methods (password, Authenticator, phone, FIDO2, "
                         "TAP). Phone numbers are masked.",
    "get_sign_in_logs": "Return a user's recent sign-in events (success or failure with the Entra error code), "
                        "newest first, from the last 1-30 days. Entra ID P1 keeps 30 days.",
    "list_devices": "List Intune-managed devices, optionally only those whose primary user is a given UPN: name, "
                    "OS, compliance state, last check-in. Never shows serial numbers.",
    "get_device": "Read one Intune-managed device by id: OS and version, compliance state, enrollment and last "
                  "sync times, management agent.",
    # writes: every one of these only CREATES A PROPOSAL. Nothing changes until a human approves it in Terminal
    # (entra-mcp approve <id>) and then the approve tool is called. Admin accounts are never valid targets.
    "disable_account": "PROPOSE disabling a user's sign-in (accountEnabled=false). Returns an approval id; the change "
                       "runs only after a human approves it. Reversible with enable_account.",
    "enable_account": "PROPOSE re-enabling a disabled user (accountEnabled=true). Approval required.",
    "reset_password": "PROPOSE an admin password reset. A strong temporary password is generated server-side and "
                      "returned ONCE after approval; it is never logged. Note: this also clears Entra smart lockout, "
                      "which has no API of its own. Approval required.",
    "create_temporary_access_pass": "PROPOSE a Temporary Access Pass (time-limited passcode for MFA recovery or "
                                    "onboarding). The pass is returned ONCE after approval and never logged. Approval required.",
    "revoke_sessions": "PROPOSE revoking all refresh tokens and sessions for a user (forces re-sign-in). Takes effect "
                       "within minutes, not instantly. Approval required.",
    "add_to_group": "PROPOSE adding a user to a security group by name or id. Role-assignable groups are refused. Approval required.",
    "remove_from_group": "PROPOSE removing a user from a security group. Approval required.",
    "sync_device": "PROPOSE an Intune check-in (sync) for a device in the server's test-device list. Approval required.",
    "reboot_device": "PROPOSE an immediate Intune reboot of a device in the server's test-device list. Disruptive; the "
                     "everyday computer is never in that list. Approval required.",
    "approve": "EXECUTE a proposal that a human has already approved in Terminal with 'entra-mcp approve <id>'. "
               "Returns 'not approved by a human yet' otherwise. Single use; proposals expire after 10 minutes.",
    "list_pending_approvals": "List proposals waiting for human approval, with what each would do.",
}
