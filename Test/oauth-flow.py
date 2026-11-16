#!/usr/bin/env python3
"""Local end-to-end OAuth check for CFB. Run against `wrangler dev` (see README below).

Prereqs (local only, nothing is deployed, no real secrets):
  .dev.vars   CFB_SESSION_SECRET=<>=32 chars>   CFB_LOGIN_PASSWORD=test-password
  seed client: wrangler kv key put --binding OAUTH_KV --local --persist-to .wrangler/state \
      client:testclient '{"clientId":"testclient","redirectUris":["https://claude.ai/api/mcp/auth_callback"],
      "clientName":"Test","registrationDate":1700000000,"tokenEndpointAuthMethod":"none",
      "grantTypes":["authorization_code","refresh_token"],"responseTypes":["code"]}'
  wrangler dev --local --persist-to .wrangler/state --port 8787
"""
import http.client, urllib.parse, re, sys, hashlib, base64, os, json
PORT = int(os.environ.get("PORT", "8787"))
HOST = f"localhost:{PORT}"
RES = "https://claude-freedom-bridge.manasodvaigaod.workers.dev/mcp"
CB = "https://claude.ai/api/mcp/auth_callback"
FORM = {"Content-Type": "application/x-www-form-urlencoded"}
fails = []

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok: fails.append(name)

class Browser:
    def __init__(self): self.jar = {}
    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("localhost", PORT)
        h = {"Host": HOST}
        if self.jar: h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        if headers: h.update(headers)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse(); data = r.read().decode()
        hs = {}
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                n, _, val = v.split(";")[0].partition("=")
                if "Max-Age=0" in v: self.jar.pop(n, None)
                else: self.jar[n] = val
            hs[k.lower()] = v
        return r.status, hs, data

def pkce():
    v = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")

def auth_path(chal, redirect=CB, client="testclient"):
    return "/authorize?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": client, "redirect_uri": redirect, "state": "xyz",
        "code_challenge": chal, "code_challenge_method": "S256", "scope": "mcp:read", "resource": RES})

def login(b, path):
    s, h, d = b.req("GET", path)
    csrf = re.search(r'name="csrf" value="([a-f0-9]+)"', d).group(1)
    nxt = re.search(r'name="next" value="([^"]*)"', d).group(1).replace("&amp;", "&")
    s, h, d = b.req("POST", "/authorize", urllib.parse.urlencode(
        {"csrf": csrf, "password": "test-password", "next": nxt}), FORM)
    return s, h

# ---- 1. happy path ----
ver, chal = pkce(); b = Browser(); path = auth_path(chal)
s, h = login(b, path); check("login -> 303", s == 303, s)
s, h, d = b.req("GET", h["location"])
csp = h.get("content-security-policy", "")
check("consent page rendered", s == 200 and 'name="handle"' in d, s)
check("consent CSP form-action allows validated client origin",
      f"form-action 'self' https://claude.ai;" in csp, csp)
check("consent CSP does not allow anything else",
      re.search(r"form-action ([^;]*);", csp).group(1).split() == ["'self'", "https://claude.ai"], csp)
check("consent CSP keeps anti-framing", "frame-ancestors 'none'" in csp and h.get("x-frame-options") == "DENY")
check("consent response not cacheable", h.get("cache-control") == "no-store")
handle = re.search(r'name="handle" value="([^"]+)"', d).group(1)
cookie_names = list(b.jar)
check("binding cookie set by provider", any(n.startswith("__Host-oauth-consent-") for n in cookie_names), cookie_names)
body = urllib.parse.urlencode([("handle", handle), ("scope", "mcp:read"), ("decision", "approve")])
pre = dict(b.jar)
s, h, d = b.req("POST", "/authorize", body, FORM)
loc = h.get("location", "")
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
check("approve -> 302 to registered callback", s == 302 and loc.startswith(CB), (s, loc[:80]))
check("state preserved", q.get("state") == ["xyz"], q)
code = q["code"][0]
s, h, d = b.req("POST", "/oauth/token", urllib.parse.urlencode({
    "grant_type": "authorization_code", "code": code, "client_id": "testclient",
    "redirect_uri": CB, "code_verifier": ver, "resource": RES}), FORM)
tok = json.loads(d) if s == 200 else {}
check("token exchange -> 200 with mcp:read", s == 200 and tok.get("scope") == "mcp:read", (s, d[:120]))

# ---- 2. MCP endpoint ----
# NOTE: the Worker pins its resource URL to the production workers.dev host, so a
# token minted against localhost is (correctly) rejected here with
# "Token audience does not match resource server". The ORIGINAL 0.7.0 code gives the
# identical 401 locally, so authenticated tools/list can only be verified on the
# deployed Worker. Locally we check only that /mcp is protected.
s, h, d = b.req("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                {"Content-Type": "application/json"})
check("MCP without token -> 401 + WWW-Authenticate", s == 401 and "www-authenticate" in h, (s, h))
print("SKIP authenticated tools/list (needs production hostname; verify after deploy)")

# ---- 3. security properties unchanged ----
check("handle is single-use (replay -> 400)", b.req("POST", "/authorize", body, FORM)[0] == 400)
b.jar.clear(); b.jar.update(pre)
check("replay even with old cookies -> 400", b.req("POST", "/authorize", body, FORM)[0] == 400)

b2 = Browser(); s, h = login(b2, auth_path(chal)); s, h, d = b2.req("GET", h["location"])
h2 = re.search(r'name="handle" value="([^"]+)"', d).group(1)
b3 = Browser(); b3.jar["__Host-cfb-session"] = b2.jar["__Host-cfb-session"]  # signed in, but no binding cookie
s, _, _ = b3.req("POST", "/authorize", urllib.parse.urlencode([("handle", h2), ("scope", "mcp:read"), ("decision", "approve")]), FORM)
check("handle from another browser (no binding cookie) -> 400", s == 400, s)

s, _, d = b2.req("POST", "/authorize", urllib.parse.urlencode([("handle", h2), ("scope", "evil:admin"), ("decision", "approve")]), FORM)
check("unsupported scope rejected", s == 400, s)

b4 = Browser(); s, h = login(b4, auth_path(chal, redirect="https://evil.example/cb"))
s, h, d = b4.req("GET", h["location"])
check("unregistered redirect_uri: no consent page, no evil origin in CSP",
      'name="handle"' not in d and "evil.example" not in h.get("content-security-policy", ""), (s, d[:100]))

s, h, d = Browser().req("GET", auth_path(chal))
check("login page CSP stays form-action 'self' only",
      "form-action 'self';" in h.get("content-security-policy", ""), h.get("content-security-policy"))
s, h, d = Browser().req("POST", "/authorize", "csrf=aa&password=x", FORM)
check("login POST without CSRF cookie -> 403", s == 403, s)

# ---- 4. deny path still redirects with access_denied ----
b5 = Browser(); s, h = login(b5, auth_path(chal)); s, h, d = b5.req("GET", h["location"])
h5 = re.search(r'name="handle" value="([^"]+)"', d).group(1)
s, h, d = b5.req("POST", "/authorize", urllib.parse.urlencode([("handle", h5), ("decision", "deny")]), FORM)
check("deny -> 302 access_denied", s == 302 and "error=access_denied" in h.get("location", ""), (s, h.get("location")))

print("\n%d failure(s)" % len(fails)); sys.exit(1 if fails else 0)
