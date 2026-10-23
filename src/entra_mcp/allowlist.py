"""The policy gate's allowlist: the only Graph requests this server can ever build.

Each entry is (method, path template, fixed query). Placeholders are filled from typed, validated values and
URL-encoded with no safe characters, so a value can never add a path segment or a query operator. There is no
function in this module, or anywhere else, that accepts a free-form path or URL.

Reads (milestone 1): seven tool endpoints plus two internal guard lookups, all GET.
Writes (milestones 3-4): each write tool maps to exactly one non-GET template, executed only by the write client
after a human approval. There is deliberately no template for wipe, retire, delete or password-profile edits.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

GRAPH = "https://graph.microsoft.com/v1.0"
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

USER_SELECT = "id,userPrincipalName,displayName,accountEnabled,jobTitle,department,createdDateTime," \
              "lastPasswordChangeDateTime,onPremisesSyncEnabled,usageLocation"
SIGNIN_SELECT = "id,createdDateTime,appDisplayName,clientAppUsed,status,deviceDetail,location,isInteractive," \
                "conditionalAccessStatus,riskLevelAggregated"
DEVICE_SELECT = "id,deviceName,operatingSystem,osVersion,complianceState,managementAgent,managementState," \
                "enrolledDateTime,lastSyncDateTime,userPrincipalName,deviceEnrollmentType,isEncrypted,model,manufacturer"


@dataclass(frozen=True)
class Template:
    name: str
    method: str
    path: str                 # with {placeholders}
    query: tuple[tuple[str, str], ...]   # fixed query, placeholders allowed in values
    placeholder_kinds: tuple[tuple[str, str], ...]   # (placeholder, kind) kind in upn|guid|iso|int


TEMPLATES: dict[str, Template] = {t.name: t for t in (
    Template("user_by_upn", "GET", "/users/{upn}", (("$select", USER_SELECT),), (("upn", "upn"),)),
    Template("user_sign_in_activity", "GET", "/users/{id}", (("$select", "id,signInActivity"),), (("id", "guid"),)),
    # documented cross-check: the list form of the same query (a 204 on the single-user form is not treated as proof)
    Template("users_sign_in_activity_list", "GET", "/users",
             (("$filter", "id eq '{id}'"), ("$select", "id,signInActivity")), (("id", "guid"),)),
    Template("user_member_of", "GET", "/users/{id}/memberOf",
             (("$select", "id,displayName,securityEnabled,isAssignableToRole,groupTypes,roleTemplateId"), ("$top", "{top}")),
             (("id", "guid"), ("top", "int"))),
    Template("user_auth_methods", "GET", "/users/{id}/authentication/methods", (), (("id", "guid"),)),
    Template("sign_in_logs", "GET", "/auditLogs/signIns",
             # no $orderby: Graph returns sign-ins newest first by default, and $orderby with $filter on this
             # endpoint was observed to hang (30 s+) on the trial tenant
             (("$filter", "userId eq '{id}' and createdDateTime ge {since}"), ("$top", "{top}"), ("$select", SIGNIN_SELECT)),
             (("id", "guid"), ("since", "iso"), ("top", "int"))),
    Template("managed_devices", "GET", "/deviceManagement/managedDevices",
             (("$select", DEVICE_SELECT), ("$top", "{top}")), (("top", "int"),)),
    Template("managed_devices_by_user", "GET", "/deviceManagement/managedDevices",
             (("$filter", "userPrincipalName eq '{upn}'"), ("$select", DEVICE_SELECT), ("$top", "{top}")),
             (("upn", "upn"), ("top", "int"))),
    Template("managed_device", "GET", "/deviceManagement/managedDevices/{id}", (("$select", DEVICE_SELECT),),
             (("id", "guid"),)),
    # internal, used only by the target guard
    Template("guard_directory_roles", "GET", "/users/{id}/transitiveMemberOf/microsoft.graph.directoryRole",
             (("$select", "id,displayName"),), (("id", "guid"),)),
    Template("guard_role_assignments", "GET", "/roleManagement/directory/roleAssignments",
             (("$filter", "principalId eq '{id}'"), ("$select", "id,roleDefinitionId")), (("id", "guid"),)),
    # ---- write path (milestones 3-4). Delegated token only; see writes.py
    Template("group_by_id", "GET", "/groups/{id}",
             (("$select", "id,displayName,securityEnabled,isAssignableToRole,groupTypes,mailEnabled"),), (("id", "guid"),)),
    Template("group_by_name", "GET", "/groups",
             (("$filter", "displayName eq '{name}'"), ("$select", "id,displayName,securityEnabled,isAssignableToRole,groupTypes,mailEnabled")),
             (("name", "groupname"),)),
    Template("user_password_methods", "GET", "/users/{id}/authentication/passwordMethods", (), (("id", "guid"),)),
    Template("user_set_account_enabled", "PATCH", "/users/{id}", (), (("id", "guid"),)),
    Template("user_revoke_sessions", "POST", "/users/{id}/revokeSignInSessions", (), (("id", "guid"),)),
    Template("user_reset_password", "POST", "/users/{id}/authentication/methods/{mid}/resetPassword", (),
             (("id", "guid"), ("mid", "guid"))),
    Template("user_create_tap", "POST", "/users/{id}/authentication/temporaryAccessPassMethods", (), (("id", "guid"),)),
    Template("group_add_member", "POST", "/groups/{gid}/members/$ref", (), (("gid", "guid"),)),
    Template("group_remove_member", "DELETE", "/groups/{gid}/members/{id}/$ref", (), (("gid", "guid"), ("id", "guid"))),
    Template("device_sync", "POST", "/deviceManagement/managedDevices/{id}/syncDevice", (), (("id", "guid"),)),
    Template("device_reboot", "POST", "/deviceManagement/managedDevices/{id}/rebootNow", (), (("id", "guid"),)),
)}
READ_TEMPLATES = frozenset(n for n, t in TEMPLATES.items() if t.method == "GET")
WRITE_TEMPLATES = frozenset(n for n, t in TEMPLATES.items() if t.method != "GET")

TOOL_TEMPLATES: dict[str, tuple[str, ...]] = {
    "get_user": ("user_by_upn",),
    "get_last_sign_in": ("user_by_upn", "user_sign_in_activity", "users_sign_in_activity_list"),
    "list_user_groups": ("user_by_upn", "user_member_of"),
    "list_auth_methods": ("user_by_upn", "user_auth_methods"),
    "get_sign_in_logs": ("user_by_upn", "sign_in_logs"),
    "list_devices": ("managed_devices", "managed_devices_by_user"),
    "get_device": ("managed_device",),
}
GUARD_TEMPLATES = ("user_by_upn", "guard_directory_roles", "guard_role_assignments", "user_member_of")
WRITE_TOOL_TEMPLATES: dict[str, str] = {          # one write template per write tool, nothing else
    "disable_account": "user_set_account_enabled",
    "enable_account": "user_set_account_enabled",
    "reset_password": "user_reset_password",
    "create_temporary_access_pass": "user_create_tap",
    "revoke_sessions": "user_revoke_sessions",
    "add_to_group": "group_add_member",
    "remove_from_group": "group_remove_member",
    "sync_device": "device_sync",
    "reboot_device": "device_reboot",
}


class AllowlistError(ValueError):
    pass


def _check(kind: str, value: object) -> str:
    if kind == "guid":
        v = str(value).lower()
        if not _GUID.fullmatch(v):
            raise AllowlistError("placeholder expected a GUID")
        return v
    if kind == "iso":
        v = str(value)
        if not _ISO.fullmatch(v):
            raise AllowlistError("placeholder expected an ISO-8601 UTC timestamp")
        return v
    if kind == "int":
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 50:
            raise AllowlistError("placeholder expected an int in 1..50")
        return str(value)
    if kind == "upn":
        from .schemas import validate_upn       # the same validator the tool schemas use
        return validate_upn(str(value))
    if kind == "groupname":
        from .schemas import validate_group_name
        return validate_group_name(str(value))
    raise AllowlistError(f"unknown placeholder kind {kind}")


def build_url(template_name: str, **values: object) -> str:
    """The only URL builder. Raises if the template is unknown, a placeholder is missing, or a value fails its kind."""
    t = TEMPLATES.get(template_name)
    if t is None:
        raise AllowlistError(f"template {template_name!r} is not allowlisted")
    kinds = dict(t.placeholder_kinds)
    if set(values) != set(kinds):
        raise AllowlistError(f"template {template_name} expects exactly {sorted(kinds)}")
    checked = {k: _check(kinds[k], v) for k, v in values.items()}
    path = t.path
    for k, v in checked.items():
        path = path.replace("{" + k + "}", quote(v, safe=""))
    query = []
    for key, val in t.query:
        for k, v in checked.items():
            # inside $filter the value sits in OData quotes; a single quote in v is impossible after _check
            val = val.replace("{" + k + "}", v)
        query.append(f"{key}={quote(val, safe='$,=() ')}".replace(" ", "%20"))
    return GRAPH + path + ("?" + "&".join(query) if query else "")
