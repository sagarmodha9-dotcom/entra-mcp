"""The seven milestone-1 tools. Engine.run(tool, args) is the single entry point the MCP server calls.

Every call: validate (schemas) -> guard (deny list, admin check) -> allowlisted GETs -> shape -> audit line.
Shaping keeps results minimal and privacy-safe: phone numbers masked, no method ids, no IP addresses, no serials.
"""
from __future__ import annotations

import datetime as dt
import time
from typing import Any

from pydantic import ValidationError

from .approvals import ApprovalError
from .audit import AuditLog
from .config import Config
from .graph import GraphClient, GraphError
from .guard import Refused, TargetGuard
from .redact import redact_text
from .schemas import APPROVAL_SCHEMAS, SCHEMAS, WRITE_SCHEMAS

TOOLS = tuple(SCHEMAS)
ALL_TOOLS = tuple(SCHEMAS) + tuple(APPROVAL_SCHEMAS) + tuple(WRITE_SCHEMAS)


class ToolError(Exception):
    def __init__(self, code: str, message: str, context: dict | None = None):
        self.code = code
        self.context = context or {}          # action/target/actor of a write execution, for the audit line
        super().__init__(redact_text(message))


def _mask_phone(p: str | None) -> str | None:
    if not p:
        return p
    digits = [c for c in p if c.isdigit()]
    return "***" + "".join(digits[-2:]) if len(digits) >= 2 else "***"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Engine:
    def __init__(self, cfg: Config, graph: GraphClient, audit: AuditLog, guard: TargetGuard | None = None,
                 now=_utc_now, writes=None):
        self.cfg, self.graph, self.audit = cfg, graph, audit
        self.guard = guard or TargetGuard(cfg, graph)
        self._now = now
        self.writes = writes                      # WriteEngine when the write path is configured, else None

    @property
    def tool_names(self) -> tuple[str, ...]:
        return ALL_TOOLS if self.writes is not None else TOOLS

    def _schema(self, tool: str):
        if tool in SCHEMAS:
            return SCHEMAS[tool]
        if self.writes is not None and (tool in WRITE_SCHEMAS or tool in APPROVAL_SCHEMAS):
            return WRITE_SCHEMAS.get(tool) or APPROVAL_SCHEMAS[tool]
        return None

    # ------------------------------------------------------------------ entry point
    def run(self, tool: str, raw_args: dict[str, Any] | None) -> dict[str, Any]:
        t0 = time.perf_counter()
        calls_before = getattr(self.graph, "calls", 0)
        target = None
        ctx: dict = {}
        try:
            schema = self._schema(tool)
            if schema is None:
                raise ToolError("unknown_tool", f"no such tool: {tool!r}")
            try:
                args = schema.model_validate(raw_args or {})
            except ValidationError as e:
                msgs = "; ".join(f"{'.'.join(str(x) for x in err['loc']) or 'args'}: {err['msg']}" for err in e.errors())
                raise ToolError("invalid_arguments", msgs) from None
            target = getattr(args, "upn", None) or getattr(args, "device_id", None) or getattr(args, "approval_id", None)
            if tool in SCHEMAS:
                result = getattr(self, "_" + tool)(args)
                decision = "allowed"
            elif tool in WRITE_SCHEMAS:
                result = self.writes.propose(tool, args, raw_args)          # no write request happens here
                decision = "proposed"
            elif tool == "approve":
                result = self.writes.execute(args.approval_id)              # only if a human approved it
                decision = "executed"
                ctx = {"action": result["tool"], "target": result["target"], "actor": result.get("executed_as")}
                target = f"{ctx['action']} -> {ctx['target']}"
            else:
                result = self.writes.pending()
                decision = "allowed"
            self._log(tool, raw_args, target, decision, t0, calls_before, ctx=ctx)
            return result
        except ToolError as e:
            ctx = e.context or ctx
            if tool == "approve" and ctx.get("action"):
                target = f"{ctx['action']} -> {ctx['target']}"
            decision = ("invalid" if e.code in ("invalid_arguments", "unknown_tool") else
                        "uncertain" if e.code == "uncertain" else
                        "failed" if tool == "approve" and e.code not in ("not_approved", "not_executable", "unknown_approval", "tampered") else
                        "refused" if e.code in ("not_approved", "not_executable", "unknown_approval", "tampered") else "error")
            self._log(tool, raw_args, target, decision, t0, calls_before, error=f"{e.code}: {e}", ctx=ctx)
            raise
        except Refused as e:
            self._log(tool, raw_args, target, "refused", t0, calls_before, error=f"{e.code}: {e}")
            raise ToolError(e.code, str(e)) from None
        except GraphError as e:
            self._log(tool, raw_args, target, "error", t0, calls_before, error=f"graph_{e.status}: {e}")
            if e.status == 404:
                raise ToolError("not_found", str(e)) from None
            raise ToolError(f"graph_{e.status}", str(e)) from None
        except ApprovalError as e:
            self._log(tool, raw_args, target, "refused", t0, calls_before, error=f"{e.code}: {e}")
            raise ToolError(e.code, str(e)) from None
        except Exception as e:                      # nothing escapes the engine; the server never crashes
            self._log(tool, raw_args, target, "error", t0, calls_before, error=f"internal: {type(e).__name__}")
            raise ToolError("internal", f"internal error ({type(e).__name__}); see the audit log") from None

    def _log(self, tool, raw_args, target, decision, t0, calls_before, error=None, ctx=None):
        calls = getattr(self.graph, "calls", 0) - calls_before
        ctx = ctx or {}
        action, actor = ctx.get("action"), ctx.get("actor")
        if tool in WRITE_SCHEMAS:
            action = tool
        self.audit.write(tool=tool, action=action, actor=actor, args=raw_args, target=target, decision=decision,
                         graph_status=(self.graph.last_status or None) if calls else None,
                         graph_calls=calls,
                         latency_ms=int((time.perf_counter() - t0) * 1000),
                         request_id=(self.graph.last_request_id or None) if calls else None, error=error)

    # ------------------------------------------------------------------ tools
    def _get_user(self, a) -> dict:
        t = self.guard.resolve(a.upn)
        u = t.user
        return {
            "userPrincipalName": u.get("userPrincipalName"), "displayName": u.get("displayName"),
            "accountEnabled": u.get("accountEnabled"), "jobTitle": u.get("jobTitle"), "department": u.get("department"),
            "createdDateTime": u.get("createdDateTime"), "lastPasswordChangeDateTime": u.get("lastPasswordChangeDateTime"),
            "cloudOnly": not bool(u.get("onPremisesSyncEnabled")), "usageLocation": u.get("usageLocation"),
            "note": "Microsoft Graph exposes no lockout flag; smart lockout clears itself (60 s, growing) and is not "
                    "readable or clearable by API. Use get_sign_in_logs to see failed sign-ins.",
        }

    def _get_last_sign_in(self, a) -> dict:
        t = self.guard.resolve(a.upn)
        base = {"userPrincipalName": t.upn}
        try:
            r = self.graph.get("user_sign_in_activity", id=t.id)
        except GraphError as e:
            if e.status in (403,):
                return {**base, "status": "unavailable",
                        "reason": "Graph refused signInActivity (403): needs Entra ID P1 and AuditLog.Read.All"}
            raise
        act = r.get("signInActivity") if isinstance(r, dict) else None
        if not act:
            # a bare 204 / missing property is NOT proof of no activity: cross-check with the documented list form
            try:
                lst = self.graph.get("users_sign_in_activity_list", id=t.id)
                vals = lst.get("value", []) if isinstance(lst, dict) else []
                act = vals[0].get("signInActivity") if vals else None
                if not act:
                    return {**base, "status": "unknown",
                            "reason": "Graph returned no signInActivity for this user on both the single-user and the "
                                      "list query. This can mean the user has never signed in, or that the property has "
                                      "not updated yet: Microsoft documents that signInActivity can take up to 24 hours. "
                                      "Not treated as proof of either. For recent activity use get_sign_in_logs."}
            except GraphError as e:
                return {**base, "status": "unavailable", "reason": f"cross-check query failed (HTTP {e.status})"}
        return {**base, "status": "known", "lastSignInDateTime": act.get("lastSignInDateTime"),
                "lastNonInteractiveSignInDateTime": act.get("lastNonInteractiveSignInDateTime"),
                "lastSuccessfulSignInDateTime": act.get("lastSuccessfulSignInDateTime")}

    def _list_user_groups(self, a) -> dict:
        t = self.guard.resolve(a.upn)
        groups = []
        for g in t.member_of:
            kind = "directoryRole" if g.get("@odata.type", "").endswith("directoryRole") else (
                "microsoft365" if "Unified" in (g.get("groupTypes") or []) else
                "security" if g.get("securityEnabled") else "distribution")
            groups.append({"displayName": g.get("displayName"), "type": kind,
                           "roleAssignable": bool(g.get("isAssignableToRole"))})
        return {"userPrincipalName": t.upn, "count": len(groups), "groups": groups,
                "note": "direct memberships only (memberOf); nested groups are not expanded"}

    def _list_auth_methods(self, a) -> dict:
        t = self.guard.resolve(a.upn)
        r = self.graph.get("user_auth_methods", id=t.id)
        out = []
        for m in r.get("value", []) if isinstance(r, dict) else []:
            kind = m.get("@odata.type", "").split(".")[-1].replace("AuthenticationMethod", "")
            item = {"type": kind or "unknown"}
            if m.get("createdDateTime"):
                item["createdDateTime"] = m["createdDateTime"]
            if m.get("phoneNumber"):
                item["phoneNumber"] = _mask_phone(m["phoneNumber"])
                item["phoneType"] = m.get("phoneType")
            if m.get("displayName") and kind in ("microsoftAuthenticator", "fido2", "softwareOath"):
                item["displayName"] = redact_text(str(m["displayName"]))[:40]
            if kind == "temporaryAccessPass":
                item["isUsable"] = m.get("isUsable")
            out.append(item)
        return {"userPrincipalName": t.upn, "count": len(out), "methods": out,
                "note": "method ids and full phone numbers are never returned"}

    def _get_sign_in_logs(self, a) -> dict:
        t = self.guard.resolve(a.upn)
        since = (self._now() - dt.timedelta(days=a.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            r = self.graph.get("sign_in_logs", id=t.id, since=since, top=a.top)
        except GraphError as e:
            if e.status == 403:
                return {"userPrincipalName": t.upn, "status": "unavailable",
                        "reason": "sign-in logs refused (403): needs Entra ID P1 and AuditLog.Read.All"}
            if e.status == 0:
                return {"userPrincipalName": t.upn, "status": "unavailable",
                        "reason": "Graph's sign-in log query did not answer within the 20 s budget (twice). This endpoint "
                                  "is slow on this tenant (9-19 s typical, occasional stalls); try again, or narrow "
                                  "days/top."}
            raise
        rows = []
        for s in r.get("value", []) if isinstance(r, dict) else []:
            st = s.get("status") or {}
            dd = s.get("deviceDetail") or {}
            loc = s.get("location") or {}
            rows.append({
                "createdDateTime": s.get("createdDateTime"), "app": s.get("appDisplayName"),
                "client": s.get("clientAppUsed"), "interactive": s.get("isInteractive"),
                "result": "success" if st.get("errorCode") in (0, None) else "failure",
                "errorCode": st.get("errorCode"), "failureReason": st.get("failureReason") if st.get("errorCode") else None,
                "os": dd.get("operatingSystem"), "browser": dd.get("browser"),
                "location": ", ".join(x for x in (loc.get("city"), loc.get("countryOrRegion")) if x) or None,
                "conditionalAccess": s.get("conditionalAccessStatus"),
            })
        return {"userPrincipalName": t.upn, "days": a.days, "since": since, "status": "known",
                "count": len(rows), "signIns": rows,
                "note": "IP addresses are not returned; Entra ID P1 retains 30 days; Graph can lag by minutes"}

    def _list_devices(self, a) -> dict:
        if a.upn:
            self.guard.resolve(a.upn)
            r = self.graph.get("managed_devices_by_user", upn=a.upn, top=a.top)
        else:
            r = self.graph.get("managed_devices", top=a.top)
        devs = [self._device(d) for d in (r.get("value", []) if isinstance(r, dict) else [])]
        return {"filterUpn": a.upn, "count": len(devs), "devices": devs,
                "note": "serial numbers are never returned; 0 devices means nothing is enrolled in Intune yet"}

    def _get_device(self, a) -> dict:
        r = self.graph.get("managed_device", id=a.device_id)
        return self._device(r if isinstance(r, dict) else {})

    @staticmethod
    def _device(d: dict) -> dict:
        return {"id": d.get("id"), "deviceName": d.get("deviceName"), "operatingSystem": d.get("operatingSystem"),
                "osVersion": d.get("osVersion"), "complianceState": d.get("complianceState"),
                "managementAgent": d.get("managementAgent"), "managementState": d.get("managementState"),
                "enrollmentType": d.get("deviceEnrollmentType"), "enrolledDateTime": d.get("enrolledDateTime"),
                "lastSyncDateTime": d.get("lastSyncDateTime"), "primaryUser": d.get("userPrincipalName"),
                "isEncrypted": d.get("isEncrypted"), "model": d.get("model"), "manufacturer": d.get("manufacturer")}
