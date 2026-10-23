"""Target guard: who a tool may be pointed at.

Order, fail closed:
  1. deny list from config (protected UPNs), checked before any Graph call
  2. resolve the user (user_by_upn): a 404 is reported as not found, anything else refuses
  3. GET transitiveMemberOf/microsoft.graph.directoryRole must be empty
  4. GET roleManagement/directory/roleAssignments?$filter=principalId eq '{id}' must be empty
     (catches scoped and PIM-activated roles; Directory.Read.All is sufficient, verified live 2026-10-22)
  5. memberOf must contain no group with isAssignableToRole == true
Any non-200 in 3-5 refuses. Decisions are cached per user id for guard.cache_seconds.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .config import Config
from .graph import GraphClient, GraphError


class Refused(Exception):
    """The gate refused the call. Message is safe for the client."""

    def __init__(self, reason: str, code: str = "refused"):
        self.code = code
        super().__init__(reason)


@dataclass
class Target:
    id: str
    upn: str
    user: dict
    member_of: list[dict]


class TargetGuard:
    def __init__(self, cfg: Config, graph: GraphClient, now=time.time):
        self.cfg, self.graph, self._now = cfg, graph, now
        self._cache: dict[str, tuple[float, Target]] = {}
        self.calls = 0

    def resolve(self, upn: str) -> Target:
        """Resolve a UPN to a guarded Target or raise Refused / GraphError(404)."""
        key = upn.lower()
        if key in self.cfg.protected_upns:
            raise Refused("this account is protected by the server's deny list; no tool may target it", "protected")
        hit = self._cache.get(key)
        if hit and self._now() - hit[0] < self.cfg.guard_cache_seconds:
            return hit[1]
        user = self.graph.get("user_by_upn", upn=upn)          # 404 -> GraphError, surfaced as not found
        if not isinstance(user, dict) or not user.get("id"):
            raise Refused("Graph returned no user object; refusing (fail closed)", "guard_error")
        uid = str(user["id"]).lower()
        try:
            roles = self.graph.get("guard_directory_roles", id=uid)
            role_names = [r.get("displayName", "?") for r in (roles.get("value", []) if isinstance(roles, dict) else [])]
            if role_names:
                raise Refused(f"target holds directory role(s) {role_names}; admin accounts are never a target",
                              "admin_target")
            assignments = self.graph.get("guard_role_assignments", id=uid)
            if isinstance(assignments, dict) and assignments.get("value"):
                raise Refused("target has a directory role assignment (scoped or PIM); admin accounts are never a "
                              "target", "admin_target")
            member_of = self.graph.get("user_member_of", id=uid, top=50)
        except GraphError as e:
            why = "got no response within the tool deadline" if e.status in (0, -1) else f"failed (HTTP {e.status})"
            raise Refused(f"guard lookup {why}; refusing (fail closed): the server cannot confirm the target is not "
                          f"an admin, so it does nothing", "guard_error") from None
        groups = member_of.get("value", []) if isinstance(member_of, dict) else []
        if any(g.get("isAssignableToRole") is True for g in groups):
            raise Refused("target is in a role-assignable group; refusing", "admin_target")
        if any(g.get("@odata.type", "").endswith("directoryRole") for g in groups):
            raise Refused("target is a direct member of a directory role; refusing", "admin_target")
        t = Target(uid, str(user.get("userPrincipalName", upn)), user, groups)
        self._cache[key] = (self._now(), t)
        return t
