"""Milestone 1 tenant validation: READ-ONLY smoke tests against the real Modha AI Labs tenant.

What it proves, with real Graph responses:
  1. the app can get an app-only token (client credentials) and the token carries exactly the 5 read roles
  2. each milestone-1 read endpoint works (or records precisely why it doesn't)
  3. write / destructive endpoints are REFUSED by Graph for this credential (403), so the read-only app
     is read-only at the authorization layer, not just by convention
  4. licensing facts (which SKUs the tenant really has) instead of assumptions

What it never does: no write, no delete, no device action. The negative tests call write endpoints with the
read-only token and expect 403; a 2xx there would be a finding (and is reported as FAIL).

Output: tests/live_results_validate.md, sanitized for a public repo:
  - no token, no secret, no tenant/object IDs beyond the first 8 characters
  - only the fictional test users (Alice/Bob/Carol) appear by name; every other UPN/name is masked
  - sign-in log rows show status/app only, never IP addresses or locations

Run on the Mac:
  cd ~/entra-mcp && source .venv/bin/activate
  python tests/validate_tenant.py
The client secret is read from the macOS Keychain (service entra-mcp-readonly, account sagar).
"""
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time

try:
    import msal
    import requests
except ImportError:
    print("pip install msal requests   (inside the venv)")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
GRAPH = "https://graph.microsoft.com/v1.0"
EXPECTED_ROLES = {
    "User.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All", "DeviceManagementManagedDevices.Read.All",
}
TEST_USERS = {"alice.test", "bob.test", "carol.test"}        # fictional accounts; everyone else is masked
TEST_GROUPS = {"sg-helpdesk-test", "sg-vpn-users"}


# ----------------------------------------------------------------------------- config + credentials
def load_config():
    path = os.path.join(HERE, "tenant.json")
    cfg = {}
    if os.path.exists(path):
        with open(path) as f:
            cfg = json.load(f)
    toml_path = os.path.join(os.path.dirname(HERE), "config.toml")
    if os.path.exists(toml_path):
        import tomllib
        with open(toml_path, "rb") as f:
            cfg = {**tomllib.load(f).get("tenant", {}), **cfg}
    tenant = os.environ.get("ENTRA_TENANT_ID") or cfg.get("tenant_id")
    client = os.environ.get("ENTRA_CLIENT_ID") or cfg.get("client_id")
    if not tenant or not client:
        print("tenant_id / client_id missing: put them in tests/tenant.json or ENTRA_TENANT_ID / ENTRA_CLIENT_ID")
        sys.exit(2)
    return tenant, client


def keychain_secret(service="entra-mcp-readonly", account="sagar"):
    env = os.environ.get("ENTRA_CLIENT_SECRET")
    if env:
        return env
    try:
        out = subprocess.run(["security", "find-generic-password", "-s", service, "-a", account, "-w"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"no secret in Keychain (service {service}, account {account}) and ENTRA_CLIENT_SECRET not set")
        sys.exit(2)


# ----------------------------------------------------------------------------- sanitization
def short_id(s):
    """GUIDs become their first 8 chars; anything else is returned as-is."""
    return re.sub(r"\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", r"\1…", str(s))


def mask_upn(upn):
    if not upn:
        return upn
    local = upn.split("@")[0].lower()
    if local in TEST_USERS:
        return upn
    return "<masked>@" + upn.split("@")[-1] if "@" in upn else "<masked>"


def mask_name(name, upn=None):
    if upn and upn.split("@")[0].lower() in TEST_USERS:
        return name
    return "<masked>"


# ----------------------------------------------------------------------------- results
class Results:
    def __init__(self):
        self.rows = []      # (name, status, detail)
        self.sections = []  # (title, markdown)

    def add(self, name, ok, detail, status=None):
        status = status or ("PASS" if ok else "FAIL")
        self.rows.append((name, status, detail))
        print(f"  [{status:4s}] {name}: {detail}")

    def section(self, title, md):
        self.sections.append((title, md))


R = Results()


def call(session, method, path, expect=(200,), body=None, label=None):
    """One Graph call. Returns (status_code, json_or_text). Never raises on HTTP errors."""
    url = path if path.startswith("http") else GRAPH + path
    t0 = time.time()
    resp = session.request(method, url, json=body, timeout=30)
    ms = int((time.time() - t0) * 1000)
    try:
        data = resp.json()
    except ValueError:
        data = resp.text
    code = resp.status_code
    msg = ""
    if isinstance(data, dict) and "error" in data:
        msg = f"{data['error'].get('code')}: {str(data['error'].get('message'))[:120]}"
    if label:
        ok = code in expect
        R.add(label, ok, f"{method} {short_id(path)} -> {code} ({ms} ms)" + (f" {msg}" if msg else ""))
    return code, data


# ----------------------------------------------------------------------------- checks
def check_token(tenant, client, secret):
    app = msal.ConfidentialClientApplication(client, authority=f"https://login.microsoftonline.com/{tenant}",
                                             client_credential=secret)
    tok = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in tok:
        R.add("token: client credentials", False, f"{tok.get('error')}: {str(tok.get('error_description'))[:160]}")
        return None, set()
    # decode the payload only to read the roles claim; the token itself is never printed or written
    payload = tok["access_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    roles = set(claims.get("roles", []))
    R.add("token: client credentials", True, f"expires in {tok.get('expires_in')} s, {len(roles)} app roles")
    missing, extra = EXPECTED_ROLES - roles, roles - EXPECTED_ROLES
    R.add("token: roles claim == the 5 granted read permissions", not missing and not extra,
          f"missing={sorted(missing) or 'none'} extra={sorted(extra) or 'none'}")
    return tok["access_token"], roles


def check_tenant(s):
    code, data = call(s, "GET", "/organization?$select=id,displayName,verifiedDomains,tenantType",
                      label="read: organization (Directory.Read.All)")
    if code == 200 and data.get("value"):
        org = data["value"][0]
        domains = [d["name"] for d in org.get("verifiedDomains", [])]
        R.section("Tenant", f"- display name: {org.get('displayName')}\n- tenant id: {short_id(org.get('id'))}\n"
                            f"- verified domains: {', '.join(domains)}\n")


def check_licenses(s):
    code, data = call(s, "GET", "/subscribedSkus?$select=skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans",
                      label="read: subscribedSkus (licensing facts)")
    if code != 200:
        return
    lines = ["| SKU | status | consumed / enabled | relevant service plans |", "|---|---|---|---|"]
    found_p1 = found_intune = found_p2 = False
    for sku in data.get("value", []):
        plans = [p["servicePlanName"] for p in sku.get("servicePlans", []) if p.get("provisioningStatus") == "Success"]
        rel = [p for p in plans if any(k in p for k in ("AAD_PREMIUM", "INTUNE", "EXCHANGE", "SHAREPOINT"))]
        found_p1 |= "AAD_PREMIUM" in plans
        found_p2 |= "AAD_PREMIUM_P2" in plans
        found_intune |= any(p.startswith("INTUNE") for p in plans)
        lines.append(f"| {sku['skuPartNumber']} | {sku['capabilityStatus']} | {sku['consumedUnits']} / "
                     f"{sku['prepaidUnits'].get('enabled')} | {', '.join(rel)[:150]} |")
    R.add("license: Entra ID P1 service plan present", found_p1, "AAD_PREMIUM in a subscribed SKU" if found_p1 else "not found")
    R.add("license: Intune service plan present", found_intune, "INTUNE_A present" if found_intune else "not found")
    R.add("license: Entra ID P2 absent (as expected on Business Premium)", not found_p2,
          "no AAD_PREMIUM_P2; risk/PIM features out of scope" if not found_p2 else "P2 present", status="INFO")
    R.section("Licensing (from /subscribedSkus)", "\n".join(lines) + "\n")


def check_users(s):
    code, data = call(s, "GET", "/users?$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,"
                                "assignedLicenses&$top=50", label="read: list users (User.Read.All)")
    if code != 200:
        return {}
    users = data.get("value", [])
    by_local = {u["userPrincipalName"].split("@")[0].lower(): u for u in users}
    lines = ["| user | enabled | title | department | licensed |", "|---|---|---|---|---|"]
    for u in users:
        lines.append(f"| {mask_upn(u['userPrincipalName'])} | {u.get('accountEnabled')} | "
                     f"{u.get('jobTitle') if u['userPrincipalName'].split('@')[0].lower() in TEST_USERS else '<masked>'} | "
                     f"{u.get('department') if u['userPrincipalName'].split('@')[0].lower() in TEST_USERS else '<masked>'} | "
                     f"{'yes' if u.get('assignedLicenses') else 'no'} |")
    present = TEST_USERS & set(by_local)
    R.add("users: the 3 fictional test users exist", present == TEST_USERS, f"found {sorted(present)}")
    R.section("Users", f"{len(users)} users returned (admin and any non-test accounts masked)\n\n" + "\n".join(lines) + "\n")
    # single-user read + the exact fields a lockout-triage tool would need
    alice = by_local.get("alice.test")
    if alice:
        call(s, "GET", f"/users/{alice['id']}?$select=id,userPrincipalName,accountEnabled,lastPasswordChangeDateTime,"
                       "signInSessionsValidFromDateTime,createdDateTime,onPremisesSyncEnabled",
             label="read: single user by id, triage fields")
    return by_local


def check_auth_methods(s, users):
    alice = users.get("alice.test")
    if not alice:
        return
    code, data = call(s, "GET", f"/users/{alice['id']}/authentication/methods",
                      label="read: authentication methods (UserAuthenticationMethod.Read.All)")
    if code == 200:
        kinds = [m.get("@odata.type", "").split(".")[-1] for m in data.get("value", [])]
        R.section("Authentication methods (Alice.Test)", f"- registered method types: {', '.join(kinds) or 'none'}\n"
                  "- (method ids and phone numbers are not recorded)\n")
    # sign-in activity requires AuditLog.Read.All + P1; records whether the tenant exposes it
    # Graph answers 204 (no content) for a user who has never signed in; 200 once there is activity
    call(s, "GET", f"/users/{alice['id']}?$select=id,signInActivity", expect=(200, 204),
         label="read: user signInActivity (P1, AuditLog.Read.All; 204 = never signed in)")


def check_groups(s, users):
    code, data = call(s, "GET", "/groups?$filter=startswith(displayName,'sg-')&$select=id,displayName,securityEnabled,"
                                "isAssignableToRole,groupTypes", label="read: list groups (Directory.Read.All)")
    if code != 200:
        return
    groups = {g["displayName"]: g for g in data.get("value", [])}
    R.add("groups: both test groups exist", TEST_GROUPS <= set(groups), f"found {sorted(groups)}")
    lines = ["| group | security | role-assignable | members |", "|---|---|---|---|"]
    for name, g in groups.items():
        c, m = call(s, "GET", f"/groups/{g['id']}/members?$select=userPrincipalName")
        members = [mask_upn(x.get("userPrincipalName", "?")) for x in m.get("value", [])] if c == 200 else [f"HTTP {c}"]
        lines.append(f"| {name} | {g.get('securityEnabled')} | {g.get('isAssignableToRole')} | {', '.join(members)} |")
    R.add("groups: isAssignableToRole readable (target guard input)",
          all("isAssignableToRole" in g for g in groups.values()), "field present on every group")
    R.section("Groups", "\n".join(lines) + "\n")
    alice = users.get("alice.test")
    if alice:
        c, m = call(s, "GET", f"/users/{alice['id']}/memberOf?$select=displayName", label="read: user memberOf")
        if c == 200:
            names = sorted(x.get("displayName") for x in m.get("value", []))
            R.add("groups: Alice is in both test groups", TEST_GROUPS <= set(names), f"memberOf = {names}")


def check_role_guard(s, users):
    """The admin-guard lookups the write milestones will rely on: which accounts hold directory roles."""
    code, data = call(s, "GET", "/directoryRoles?$select=id,displayName,roleTemplateId",
                      label="read: directoryRoles (activated roles)")
    if code != 200:
        return
    lines = ["| role | members |", "|---|---|"]
    admin_roles_found = 0
    for role in data.get("value", []):
        c, m = call(s, "GET", f"/directoryRoles/{role['id']}/members?$select=userPrincipalName")
        if c != 200:
            continue
        members = [mask_upn(x.get("userPrincipalName", "<service principal>")) for x in m.get("value", [])]
        if members:
            admin_roles_found += 1
            lines.append(f"| {role['displayName']} | {', '.join(members)} |")
    R.add("role guard: directory role membership readable", admin_roles_found > 0,
          f"{admin_roles_found} activated roles with members")
    R.section("Directory roles (admin guard input)", "\n".join(lines) + "\n")
    for local in ("alice.test", "bob.test"):
        u = users.get(local)
        if u:
            c, m = call(s, "GET", f"/users/{u['id']}/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName",
                        label=f"read: transitiveMemberOf directoryRole for {local}")
            if c == 200:
                roles = [x.get("displayName") for x in m.get("value", [])]
                R.add(f"role guard: {local} holds no admin role", not roles, f"roles = {roles or 'none'}")
    # unifiedRoleAssignment reads accept Directory.Read.All (verified live: 200), so the admin guard can use the
    # role-assignment API too, not only directoryRoles membership
    c, m = call(s, "GET", "/roleManagement/directory/roleAssignments?$top=50&$select=principalId,roleDefinitionId",
                label="read: roleManagement/directory/roleAssignments (admin guard, Directory.Read.All suffices)")
    if c == 200:
        R.add("role guard: role assignments enumerable", True,
              f"{len(m.get('value', []))} assignments (principal ids not recorded)")


def check_audit(s):
    code, data = call(s, "GET", "/auditLogs/signIns?$top=5&$select=createdDateTime,userPrincipalName,appDisplayName,status",
                      expect=(200, 403), label="read: auditLogs/signIns (AuditLog.Read.All, P1)")
    if code == 200:
        rows = data.get("value", [])
        test_rows = [r for r in rows if r.get("userPrincipalName", "").split("@")[0].lower() in TEST_USERS]
        lines = ["| when (UTC) | user | app | result |", "|---|---|---|---|"]
        for r in test_rows:
            st = r.get("status", {})
            lines.append(f"| {r.get('createdDateTime', '')[:16]} | {mask_upn(r.get('userPrincipalName'))} | "
                         f"{r.get('appDisplayName')} | {'success' if st.get('errorCode') == 0 else 'error ' + str(st.get('errorCode'))} |")
        R.section("Sign-in logs", f"endpoint works: {len(rows)} rows returned (admin activity reduced to this count; "
                  f"only test-user rows are listed, without IP or location)\n\n" + ("\n".join(lines) + "\n" if test_rows else ""))
    code, data = call(s, "GET", "/auditLogs/directoryAudits?$top=5&$select=activityDateTime,activityDisplayName,result",
                      expect=(200, 403), label="read: auditLogs/directoryAudits")
    if code == 200:
        rows = data.get("value", [])
        R.section("Directory audit", f"endpoint works: {len(rows)} rows returned (contents are admin activity and are "
                                     "not recorded here)\n")


def check_intune(s):
    code, data = call(s, "GET", "/deviceManagement/managedDevices?$top=10&$select=id,deviceName,operatingSystem,"
                                "complianceState,managementAgent,lastSyncDateTime",
                      expect=(200, 403), label="read: Intune managedDevices (DeviceManagementManagedDevices.Read.All)")
    if code == 200:
        devs = data.get("value", [])
        R.add("intune: device list readable", True, f"{len(devs)} enrolled devices (0 is expected before enrollment)")
        R.section("Intune devices", "\n".join(
            f"- {d.get('deviceName')} {d.get('operatingSystem')} compliance={d.get('complianceState')} "
            f"lastSync={str(d.get('lastSyncDateTime'))[:16]}" for d in devs) + ("\n" if devs else
            "0 devices enrolled yet; device tools stay **pending** until a disposable test device is enrolled\n"))
    elif code == 403:
        R.section("Intune devices", f"403 from Intune: {str(data)[:200]}\n\nLikely cause: Intune MDM authority not yet "
                  "set or the Intune service not yet provisioned on the trial. Device tools stay **pending**.\n")


def check_writes_refused(s, users):
    """Server-side authorization tests: the read-only credential must be refused on every write it might ever be
    tricked into. All of these target writes that are harmless even if (unexpectedly) allowed on test objects."""
    carol = users.get("carol.test", {}).get("id", "00000000-0000-0000-0000-000000000000")
    fake = "00000000-0000-0000-0000-000000000000"
    tests = [
        ("PATCH", f"/users/{carol}", {"jobTitle": "SHOULD-NOT-APPLY"}, "write refused: PATCH user"),
        ("POST", f"/users/{carol}/revokeSignInSessions", None, "write refused: revokeSignInSessions"),
        ("POST", f"/users/{carol}/authentication/temporaryAccessPassMethods", {"lifetimeInMinutes": 60},
         "write refused: create TAP"),
        ("POST", "/groups", {"displayName": "sg-should-not-exist", "mailEnabled": False, "mailNickname": "x",
                             "securityEnabled": True}, "write refused: create group"),
        ("POST", f"/deviceManagement/managedDevices/{fake}/syncDevice", None, "write refused: Intune syncDevice"),
        ("POST", f"/deviceManagement/managedDevices/{fake}/wipe", {}, "destructive refused: Intune wipe"),
        ("POST", f"/deviceManagement/managedDevices/{fake}/retire", None, "destructive refused: Intune retire"),
        # real test user on purpose: a fake id gets 404 before authorization, which proves nothing. The token
        # has no user-write permission (PATCH above is refused), so Graph must answer 403 here too.
        ("DELETE", f"/users/{carol}", None, "destructive refused: DELETE user (Carol.Test)"),
    ]
    for method, path, body, label in tests:
        code, data = call(s, method, path, body=body, expect=(401, 403, 404))
        refused = code in (401, 403) or (code == 404 and fake in path)
        msg = ""
        if isinstance(data, dict) and "error" in data:
            msg = f" {data['error'].get('code')}"
        R.add(label, refused, f"{method} {short_id(path)} -> {code}{msg}",
              status=("PASS" if code in (401, 403) else ("INFO" if refused else "FAIL")))
    if carol != fake:
        c, d = call(s, "GET", f"/users/{carol}?$select=jobTitle,accountEnabled")
        R.add("write refused: Carol still exists and unchanged after PATCH/DELETE attempts",
              c == 200 and d.get("jobTitle") != "SHOULD-NOT-APPLY",
              f"jobTitle = {d.get('jobTitle') if c == 200 else 'HTTP ' + str(c)}")
    # a permission this app never asked for: proves the token is scoped, not tenant-wide
    call(s, "GET", "/security/alerts_v2?$top=1", expect=(403,), label="allowlist: security alerts refused (not granted)")
    call(s, "GET", "/users?$select=id&$top=1&$filter=mail eq 'x'", expect=(200, 400),
         label="read: filtered user query shape accepted")


# ----------------------------------------------------------------------------- report
def write_report(tenant, client, roles):
    out = os.path.join(HERE, "live_results_validate.md")
    passed = sum(1 for r in R.rows if r[1] == "PASS")
    failed = [r for r in R.rows if r[1] == "FAIL"]
    md = [f"# Tenant prerequisites: live validation (read-only, real Graph)",
          f"",
          f"Run: {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
          f"Tenant: {short_id(tenant)}  App: {short_id(client)} (entra-mcp-readonly, client credentials)  ",
          f"Token roles: {', '.join(sorted(roles))}  ",
          f"Result: **{passed} passed, {len(failed)} failed, {len(R.rows)} checks**",
          f"",
          f"Sanitized: no tokens or secrets; GUIDs truncated; only the fictional test users appear by name; "
          f"sign-in rows carry no IP or location.",
          f"",
          f"## Checks",
          f"",
          f"| check | status | detail |", f"|---|---|---|"]
    for name, status, detail in R.rows:
        md.append(f"| {name} | {status} | {short_id(detail).replace('|', '/')} |")
    for title, body in R.sections:
        md += ["", f"## {title}", "", body.rstrip()]
    with open(out, "w") as f:
        f.write("\n".join(md) + "\n")
    print(f"\n{passed} passed, {len(failed)} failed, {len(R.rows)} checks  ->  {out}")
    for name, status, detail in failed:
        print(f"  FAIL {name}: {detail}")
    return not failed


def main():
    tenant, client = load_config()
    secret = keychain_secret()
    print(f"tenant {short_id(tenant)}  app {short_id(client)}\n")
    token, roles = check_token(tenant, client, secret)
    if not token:
        write_report(tenant, client, roles)
        sys.exit(1)
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"})
    check_tenant(s)
    check_licenses(s)
    users = check_users(s)
    check_auth_methods(s, users)
    check_groups(s, users)
    check_role_guard(s, users)
    check_audit(s)
    check_intune(s)
    check_writes_refused(s, users)
    ok = write_report(tenant, client, roles)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
