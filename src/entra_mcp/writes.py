"""Write path (milestones 2-4): propose -> human approves in Terminal -> approve tool executes.

Every write tool call goes: validate (schemas) -> target guard with the READ client (deny list, admin roles,
role-assignable groups; devices: config test_device_ids) -> proposal stored -> returned to the model.
Nothing touches Graph with a write method until `approve` claims a human-approved proposal, and that execution
uses the delegated WriteGraphClient with exactly one allowlisted write template per tool.

Secrets produced by writes (generated passwords, Temporary Access Passes) are returned once in the tool result
and never written to the audit log, the approval store, or any error.
"""
from __future__ import annotations

import secrets
import string
import time
from typing import Any, Callable

from .allowlist import WRITE_TOOL_TEMPLATES, TEMPLATES
from .approvals import Approval, ApprovalError, ApprovalStore
from .audit import AuditLog
from .auth import NotSignedIn, ensure_delegated, token_claims
from .config import Config
from .graph import GraphClient, GraphError, WriteGraphClient
from .guard import Refused, TargetGuard
from .tools import ToolError

WRITE_TOOLS = tuple(WRITE_TOOL_TEMPLATES)
IDENTITY_WRITES = ("disable_account", "enable_account", "reset_password", "create_temporary_access_pass",
                   "revoke_sessions", "add_to_group", "remove_from_group")
DEVICE_WRITES = ("sync_device", "reboot_device")


def _strong_password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+-=?@"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in "!#%+-=?@" for c in pw)):
            return pw


class WriteEngine:
    def __init__(self, cfg: Config, read_graph: GraphClient, guard: TargetGuard, audit: AuditLog,
                 store: ApprovalStore, write_token_provider: Callable[[], str] | None,
                 write_client_factory: Callable[[Callable[[], str]], WriteGraphClient] | None = None):
        self.cfg, self.read, self.guard, self.audit, self.store = cfg, read_graph, guard, audit, store
        self._wtp = write_token_provider
        self._factory = write_client_factory or (lambda tp: WriteGraphClient(cfg, tp))


    # ------------------------------------------------------------------ proposals
    def propose(self, tool: str, args, raw_args: dict | None) -> dict[str, Any]:
        """Guard the target, then store a proposal. Zero write requests happen here."""
        if tool in DEVICE_WRITES:
            if args.device_id not in {d.lower() for d in self.cfg.test_device_ids}:
                raise Refused(f"device {args.device_id[:8]}… is not in the server's test_device_ids list; device "
                              "actions are allowed only on dedicated test devices", "device_not_allowed")
            target, summary, call = args.device_id, f"{tool} on test device {args.device_id[:8]}…", \
                f"POST {TEMPLATES[WRITE_TOOL_TEMPLATES[tool]].path}"
        else:
            t = self.guard.resolve(args.upn)          # deny list + admin checks, fail closed
            target = t.upn
            if tool in ("add_to_group", "remove_from_group"):
                g = self._resolve_group(args.group)
                summary = f"{tool.replace('_', ' ')} {g['displayName']} for {t.upn}"
                call = f"{TEMPLATES[WRITE_TOOL_TEMPLATES[tool]].method} {TEMPLATES[WRITE_TOOL_TEMPLATES[tool]].path} (group {g['id'][:8]}…)"
                raw_args = {**(raw_args or {}), "group_id": g["id"], "group_name": g["displayName"]}
            else:
                if tool == "create_temporary_access_pass":
                    summary = (f"Temporary Access Pass for {t.upn}, {args.lifetime_minutes} min, "
                               f"{'one-time' if args.one_time_use else 'reusable'}")
                else:
                    summary = {
                        "disable_account": f"set accountEnabled=false on {t.upn}",
                        "enable_account": f"set accountEnabled=true on {t.upn}",
                        "reset_password": f"admin password reset for {t.upn} (new password generated at execution, shown once)",
                        "revoke_sessions": f"revoke all sessions/refresh tokens for {t.upn}",
                    }[tool]
                call = f"{TEMPLATES[WRITE_TOOL_TEMPLATES[tool]].method} {TEMPLATES[WRITE_TOOL_TEMPLATES[tool]].path}"
        a = self.store.propose(tool, raw_args or {}, target, summary, call)
        return {"status": "proposed", "approval_id": a.id, "tool": tool, "target": target, "would_do": summary,
                "graph_call": call, "expires_at": a.expires_at,
                "next_step": f"A human must approve in Terminal: entra-mcp approve {a.id}  (then call approve with this id). "
                             "Nothing has changed yet."}

    def _resolve_group(self, group: str) -> dict:
        """Group by GUID or exact display name; refuses role-assignable, mail-enabled or M365 groups."""
        if "-" in group and len(group) == 36:
            r = self.read.get("group_by_id", id=group)
            cands = [r] if isinstance(r, dict) and r.get("id") else []
        else:
            r = self.read.get("group_by_name", name=group)
            cands = r.get("value", []) if isinstance(r, dict) else []
        if len(cands) != 1:
            raise Refused(f"group {group!r} not found or ambiguous ({len(cands)} matches)", "group_not_found")
        g = cands[0]
        if g.get("isAssignableToRole"):
            raise Refused("group is role-assignable; membership changes there are never proposed", "admin_target")
        if not g.get("securityEnabled") or g.get("mailEnabled") or "Unified" in (g.get("groupTypes") or []):
            raise Refused("only plain security groups are in scope (no M365 or mail-enabled groups)", "group_out_of_scope")
        return g

    # ------------------------------------------------------------------ execution
    def execute(self, approval_id: str) -> dict[str, Any]:
        """Run a HUMAN-APPROVED proposal exactly once with the delegated client.

        Outcomes recorded on the proposal and surfaced to the caller:
          executed  Graph answered 2xx (and the verification read agrees where one exists)
          failed    Graph answered 4xx/5xx, or a local precondition failed; nothing was retried
          uncertain no HTTP response at all (timeout / connection drop): the write MAY have happened; verify with
                    a read before acting again. Never retried automatically.
        In every case the proposal is spent."""
        a = self.store.claim_for_execution(approval_id)         # raises unless status == approved; flips to executed
        ctx = {"action": a.tool, "target": a.target, "actor": None}
        if self._wtp is None:
            self.store.record_result(a.id, None, "failed: write path not configured", status="failed")
            raise ToolError("writes_disabled", "write path is not configured ([writes].client_id empty)", ctx)
        try:
            token = self._wtp()
        except NotSignedIn as e:
            self.store.record_result(a.id, None, f"failed: {e}", status="failed")
            raise ToolError("not_signed_in", str(e), ctx) from None
        try:
            ensure_delegated(token)
        except GraphError as e:
            self.store.record_result(a.id, None, f"failed: {e.code}", status="failed")
            raise ToolError(e.code, str(e), ctx) from None
        who = token_claims(token).get("upn")          # the operator; on the deny list as a TARGET, never as an actor
        ctx["actor"] = who
        client = self._factory(lambda: token)
        try:
            result = getattr(self, "_" + a.tool)(client, a)
        except GraphError as e:
            if e.status == 0:                           # no response: outcome unknown, do not retry a write
                self.store.record_result(a.id, who, "uncertain: no response from Graph; verify with a read", status="uncertain")
                raise ToolError("uncertain", f"no response from Graph for {a.tool} on {a.target}: the change may or may not "
                                             "have been applied. Verify with a read (get_user / list_user_groups / "
                                             "list_auth_methods) before proposing it again.", ctx) from None
            self.store.record_result(a.id, who, f"failed: graph_{e.status} {e.code}", status="failed")
            raise ToolError(f"graph_{e.status}", str(e), ctx) from None
        except ToolError as e:
            self.store.record_result(a.id, who, f"failed: {e.code}", status="failed")
            e.context = e.context or ctx
            raise
        except Refused as e:
            self.store.record_result(a.id, who, f"failed: {e.code}", status="failed")
            raise ToolError(e.code, str(e), ctx) from None
        self.store.record_result(a.id, who, result.get("result_summary", "ok"), status="executed")
        out = {"status": "executed", "approval_id": a.id, "tool": a.tool, "target": a.target, "executed_as": who,
               "graph_status": client.last_status, "request_id": client.last_request_id, **result}
        return out

    # each executor: exactly one write template; verification reads use the delegated client too
    def _target_id(self, a: Approval) -> str:
        self.guard._cache.pop(a.target.lower(), None)   # fresh lookups: roles can change within the 10-minute window
        t = self.guard.resolve(a.target)
        return t.id

    def _read_back(self, upn: str, want_enabled: bool) -> tuple[bool | None, int]:
        """Directory reads lag writes by seconds (observed live: the next read still showed the previous value).
        Poll the READ client until it reflects the write, up to ~15 s. Returns (value, seconds waited)."""
        waited = 0.0
        while True:
            after = self.read.get("user_by_upn", upn=upn)
            val = after.get("accountEnabled") if isinstance(after, dict) else None
            if val == want_enabled or waited >= 15:
                return val, int(waited)
            self._sleep(2.5)
            waited += 2.5

    _sleep = staticmethod(time.sleep)

    def _disable_account(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        c.write("user_set_account_enabled", {"accountEnabled": False}, id=uid)
        val, waited = self._read_back(a.target, False)
        return {"accountEnabled": val, "verified_after_seconds": waited,
                "result_summary": f"accountEnabled={val} (read-back after {waited}s)",
                "note": "existing tokens stay valid until they expire; use revoke_sessions to force sign-out"}

    def _enable_account(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        c.write("user_set_account_enabled", {"accountEnabled": True}, id=uid)
        val, waited = self._read_back(a.target, True)
        return {"accountEnabled": val, "verified_after_seconds": waited,
                "result_summary": f"accountEnabled={val} (read-back after {waited}s)"}

    def _reset_password(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        methods = c.get("user_password_methods", id=uid)
        vals = methods.get("value", []) if isinstance(methods, dict) else []
        if not vals:
            raise ToolError("no_password_method", "user has no password method to reset")
        new_pw = _strong_password()
        r = c.write("user_reset_password", {"newPassword": new_pw}, id=uid, mid=vals[0]["id"])
        status = r.get("_status") if isinstance(r, dict) else None
        return {"temporaryPassword": new_pw, "shown_once": True,
                "graph_accepted": status, "operation_location": bool(r.get("_location")) if isinstance(r, dict) else False,
                "result_summary": f"resetPassword accepted ({status}); password returned once, not stored",
                "note": "Graph processes the reset asynchronously (202). The user should change this password at first "
                        "sign-in. This also clears any smart-lockout state."}

    def _create_temporary_access_pass(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        body = {"lifetimeInMinutes": int(a.args.get("lifetime_minutes", 60)), "isUsableOnce": bool(a.args.get("one_time_use", True))}
        try:
            r = c.write("user_create_tap", body, id=uid)
        except GraphError as e:
            if e.status == 400 and "LifetimeInMinutes" in str(e):
                raise ToolError("tap_policy", "the tenant's Temporary Access Pass policy rejected the lifetime; the default "
                                              "policy allows 60-480 minutes") from None
            raise
        return {"temporaryAccessPass": r.get("temporaryAccessPass"), "shown_once": True,
                "startDateTime": r.get("startDateTime"), "lifetimeInMinutes": r.get("lifetimeInMinutes"),
                "isUsableOnce": r.get("isUsableOnce"),
                "result_summary": f"TAP created ({r.get('_status')}), {r.get('lifetimeInMinutes')} min; code returned once, not stored"}

    def _revoke_sessions(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        r = c.write("user_revoke_sessions", None, id=uid)
        return {"revoked": r.get("value") if isinstance(r, dict) else None,
                "result_summary": f"revokeSignInSessions -> value={r.get('value') if isinstance(r, dict) else r}",
                "note": "takes effect within minutes; already-issued access tokens live until expiry"}

    def _add_to_group(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        gid = a.args["group_id"]
        c.write("group_add_member", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{uid}"}, gid=gid)
        groups = self._groups_after(a.target, a.args.get("group_name"), True)
        return {"group": a.args.get("group_name"), "memberNow": a.args.get("group_name") in groups,
                "result_summary": f"added to {a.args.get('group_name')}; memberOf now {len(groups)} groups"}

    def _remove_from_group(self, c: WriteGraphClient, a: Approval) -> dict:
        uid = self._target_id(a)
        gid = a.args["group_id"]
        c.write("group_remove_member", None, gid=gid, id=uid)
        groups = self._groups_after(a.target, a.args.get("group_name"), False)
        return {"group": a.args.get("group_name"), "memberNow": a.args.get("group_name") in groups,
                "result_summary": f"removed from {a.args.get('group_name')}; memberOf now {len(groups)} groups"}

    def _groups_after(self, upn: str, want_member: str | None = None, want: bool = True) -> list[str]:
        waited = 0.0
        while True:
            self.guard._cache.pop(upn.lower(), None)
            names = [g.get("displayName") for g in self.guard.resolve(upn).member_of]
            if want_member is None or (want_member in names) == want or waited >= 15:
                return names
            self._sleep(2.5)
            waited += 2.5

    def _sync_device(self, c: WriteGraphClient, a: Approval) -> dict:
        r = c.write("device_sync", None, id=a.target)
        return {"accepted": r.get("_status") if isinstance(r, dict) else None, "result_summary": f"syncDevice -> {r.get('_status') if isinstance(r, dict) else r}"}

    def _reboot_device(self, c: WriteGraphClient, a: Approval) -> dict:
        r = c.write("device_reboot", None, id=a.target)
        return {"accepted": r.get("_status") if isinstance(r, dict) else None, "result_summary": f"rebootNow -> {r.get('_status') if isinstance(r, dict) else r}"}

    # ------------------------------------------------------------------ listing
    def pending(self) -> dict[str, Any]:
        items = self.store.pending()
        return {"count": len(items), "pending": [
            {"approval_id": a.id, "tool": a.tool, "target": a.target, "would_do": a.summary, "status": a.status,
             "expires_at": a.expires_at, "approve_in_terminal": f"entra-mcp approve {a.id}"} for a in items]}
