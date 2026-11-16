# Security Review: Authentication, Authorization, Tokens, IDOR

**Scope:** MemoryLayer `memorylayer-core-python` authn/authz, API routers, Docker/CLI bind defaults, token handling, workspace/tenant isolation.  
**Method:** Static call-chain tracing from HTTP entrypoints to auth checks. Only end-to-end-supported issues reported.  
**Date:** 2026-11-16  
**Branch:** `cursor/security-review-findings-memory-117b`

---

## Executive summary

Default OSS mode is intentionally **open authentication + allow-all authorization**. The local CLI bind (`127.0.0.1`) limits exposure for `memorylayer serve`, but the **published Docker image binds `0.0.0.0` with the same open defaults**, making the full REST surface reachable without credentials. Separately, `GET /kb/{workspace_id}` never calls auth at all (including under Aether mode). Several workspace-scoped endpoints accept attacker-controlled workspace IDs; under open auth (and under Aether authz that only checks numeric access level, not workspace membership) that yields cross-workspace IDOR.

---

## Finding 1 — Docker publishes open-auth API on all interfaces

| Field | Detail |
|---|---|
| Severity | **Critical** (when Docker image / `0.0.0.0` bind is used as shipped) |
| CWE | CWE-306 (Missing Authentication), CWE-1188 (Insecure Default Initialization) |
| Exploitable E2E | **Yes** for the Docker default path |

### Call chain

1. Container starts with `CMD ["serve"]` and `MEMORYLAYER_SERVER_HOST=0.0.0.0`  
   Evidence: `Dockerfile:40-54`
2. CLI `serve` reads host from env, defaulting to `127.0.0.1` only when unset  
   Evidence: `memorylayer-core-python/src/memorylayer_server/cli.py:40-53`, `config.py:13-14`
3. Auth plugin default is `"default"` → `OpenAuthenticationService.verify_api_key` always returns `DEFAULT_TENANT_ID` with no key check  
   Evidence: `config.py:150-151`, `services/authentication/default.py:53-65`
4. Authz plugin default is `"default"` → `OpenPermissionsAuthorizationService.authorize` always `ALLOW`  
   Evidence: `config.py:156-157`, `services/authorization/default.py:23-28`
5. Typical protected route (example memories):  
   `POST /v1/memories` → `build_context` → `require_authorization(..., "memories", "create")` → always succeeds under open auth → writes data  
   Evidence: `api/v1/memories.py:104-107`

### Attacker model

Network adversary who can reach the published port (`61001`) on a host running the official image (`docker run -p 61001:61001 ...` as documented in root `README.md:77-78`).

### Impact

Full unauthenticated CRUD over memories, sessions, workspaces, documents, MCP server configs (including `reveal_secrets=true`), skills, chat threads, audit logs (admin actions always allowed), export/import, etc.

### Mitigations that reduce/omit

- Bind Docker to localhost or a private network only; do not publish `61001` publicly without an auth gateway.
- Set `MEMORYLAYER_AUTHENTICATION_SERVICE=aether` **and** `MEMORYLAYER_AUTHORIZATION_SERVICE=aether` **and** ensure clients cannot hit MemoryLayer HTTP except through the Aether auth-proxy (header stripping/minting).
- Change image defaults to refuse start unless an auth mode other than open is configured, or bind `127.0.0.1` inside the container and require an explicit override.
- Document the open-auth + `0.0.0.0` combination as unsafe for shared networks (currently Docker comments only explain accessibility, not auth risk: `Dockerfile:40-42`).

**Note:** Plain `memorylayer serve` without Docker defaults to `127.0.0.1` (`config.py:14`), so localhost-only CLI use is **not** the same severity unless the operator passes `--host 0.0.0.0` (encouraged in `memorylayer-core-python/README.md:53`).

---

## Finding 2 — Unauthenticated knowledgebase HTML viewer (`GET /kb/{workspace_id}`)

| Field | Detail |
|---|---|
| Severity | **High** |
| CWE | CWE-306, CWE-639 (Authorization Bypass Through User-Controlled Key) |
| Exploitable E2E | **Yes** whenever the HTTP server is reachable and KB articles exist |

### Call chain

1. Router registered via `KBViewerPlugin` (`is_multi_extension=True`)  
   Evidence: `api/v1/kb_viewer.py:420-433`
2. `GET /kb/{workspace_id}` handler takes `workspace_id` from the path and loads articles directly from storage — **no** `get_auth_service` / `build_context` / `require_authorization`  
   Evidence: `api/v1/kb_viewer.py:340-358`
3. Contrast: sibling `GET /kb` *does* call `build_context` and optionally filters via `get_allowed_workspaces`  
   Evidence: `api/v1/kb_viewer.py:255-297`  
   Under open auth that filter is `["*"]` (`authorization/default.py:30-32`); under Aether authz it is also `["*"]` (`authorization/aether.py:187-198`).

### Attacker model

Unauthenticated HTTP client who knows or guesses a workspace ID (or enumerates via `GET /kb` under open/`*` allow-list).

### Impact

Disclosure of knowledgebase article content (communities, entities, index) for any workspace ID, **even when Aether authz is enabled**, because this route never consults authz.

### Mitigations

- Require `build_context` + `require_authorization(ctx, "knowledgebase", "read", workspace_id=...)` before `list_kb_articles`.
- Disable the viewer plugin outside development, or gate with an explicit env flag defaulting to off.
- Avoid predictable workspace IDs if the viewer must remain open (insufficient alone).

---

## Finding 3 — Attacker-controllable workspace IDs → cross-workspace access (IDOR under open / weak Aether workspace binding)

| Field | Detail |
|---|---|
| Severity | **High** under open auth on a reachable bind; **Medium–High** under Aether if HTTP is reachable without gateway workspace re-binding |
| CWE | CWE-639 |
| Exploitable E2E | **Yes** under Finding 1 conditions; conditional under Aether (see below) |

### Call chain (open auth)

1. Client supplies `workspace_id` via body, `X-Workspace-ID`, path param, or query (endpoint-dependent).  
   Base auth resolution: body then `X-Workspace-ID` (`authentication/base.py:175-185`).  
   Aether also reads query `workspace_id` (`authentication/aether.py:275-279`).
2. `OpenAuthenticationService.resolve_workspace` prefers `request_workspace_id` and **auto-creates** the workspace (`authentication/default.py:97-107`).
3. `require_authorization` always ALLOW (`authorization/default.py:23-28`).
4. Data APIs then operate on that ID, e.g.:
   - `GET /v1/workspaces/{workspace_id}` — path ID used for authz + fetch (`api/v1/workspaces.py:207-213`)
   - `GET /v1/workspaces` — lists **all** workspaces with no `get_allowed_workspaces` filter (`api/v1/workspaces.py:155-161`)
   - `GET /v1/sessions?workspace_id=` — query overrides (`api/v1/sessions.py:231-238`)
   - `GET /v1/mcp-servers?workspace_id=&reveal_secrets=true` (`api/v1/mcp_servers.py:178-180`, `167`)
   - `GET /v1/memories/{memory_id}` — global ID lookup then authz on `memory.workspace_id` (`api/v1/memories.py:208-214`); under open auth, any known memory ID is readable

### Call chain (Aether mode residual)

1. Access decision uses only `metadata[aether_access_level]` vs permission map — **does not** verify `context.workspace_id` ∈ allowed workspaces (`authorization/aether.py:141-171`, `187-198` returns `["*"]`).
2. Direct (non-OBO) mode does **not** enforce `workspace_scope` (`authentication/aether.py:172-180` only when `mode == "on_behalf_of"` and scope present).
3. Therefore a client that can present a non-zero `X-Auth-Workspace-Access` (or reach ML with gateway-minted level while choosing another workspace via `X-Workspace-ID` / query / path) can act on workspaces the level was not scoped to, unless the gateway exclusively sets/locks workspace identity.

### Attacker model

- Open auth: any network client (Finding 1) who can list workspaces or guess IDs.
- Aether: client with ability to talk to MemoryLayer HTTP with forged or overly broad `X-Auth-*` / workspace selectors (see Finding 5).

### Impact

Read/modify/delete another workspace’s memories, sessions, MCP secrets (with `reveal_secrets`), skills, documents, exports.

### Mitigations

- Enforce workspace membership in `AuthorizationService.authorize` (compare `workspace_id` to `get_allowed_workspaces` / grant scope) for **direct** and OBO modes.
- Filter `list_workspaces` through `get_allowed_workspaces`.
- Stop auto-creating workspaces from untrusted client-supplied IDs in non-dev modes.
- For resource-by-id APIs, authorize using the resource’s workspace and deny if caller’s allowed set does not include it.

---

## Finding 4 — Token management API is authorized only by open/admin checks; plaintext returned once

| Field | Detail |
|---|---|
| Severity | **High** if Aether gRPC is connected while open auth is used; otherwise endpoints return 503 (lower practical impact) |
| CWE | CWE-306, CWE-522 (Insufficiently Protected Credentials) |
| Exploitable E2E | **Yes** when `AetherServiceConnection` client is non-None and auth defaults remain open |

### Call chain

1. `TokensAPIPlugin` registers router as multi-extension (`api/v1/tokens.py:444-459`).
2. `POST /v1/tokens` → `build_context` → `require_authorization(ctx, "admin", "write")` (`tokens.py:219-220`).  
   Under open auth, admin write always ALLOW (`authorization/default.py:23-28`, `get_user_role` returns `"admin"` at lines 34-36).
3. Forwards to Aether `create_token` with default `workspace_patterns=["*"]`, `scopes=["*"]` (`tokens.py:36-43`, `229-235`).
4. Response includes `plaintext_token` (`tokens.py:250-261`). Logs include name/id but not plaintext (`tokens.py:264`) — good.
5. Hashing/storage of tokens is **not** implemented in MemoryLayer; delegated to Aether. This package only proxies.

### Attacker model

Unauthenticated client against an open-auth MemoryLayer that has a live Aether connection.

### Impact

Mint, list, get, revoke, delete API tokens with wildcard workspace/scopes; obtain plaintext secret at creation.

### Mitigations

- Do not enable token routes under open auth; require Aether authz with real ADMIN level.
- Keep Aether disconnected in OSS Docker unless auth is hardened.
- Avoid default `workspace_patterns=["*"]` / `scopes=["*"]` on create.

---

## Finding 5 — Aether authentication trusts client-supplied `X-Auth-*` when not behind the proxy

| Field | Detail |
|---|---|
| Severity | **High** if `MEMORYLAYER_AUTHENTICATION_SERVICE=aether` is enabled on a directly reachable HTTP port |
| CWE | CWE-290 (Authentication Bypass by Spoofing) |
| Exploitable E2E | **Yes** for direct HTTP to MemoryLayer with aether auth plugin; **mitigated** on the Aether proxy-http terminator path (strict header strip — see tests) |

### Call chain

1. `AetherAuthenticationService.build_context` reads identity and access level solely from request headers (`authentication/aether.py:245-250`, `333-353`, `355-368`).
2. No signature / mTLS peer check in this service; comments state gateway is assumed (`aether.py:99-107`).
3. Absent `X-Auth-Tenant-ID` → fallback `DEFAULT_TENANT_ID` (`aether.py:342-347`).
4. Absent/malformed `X-Auth-Workspace-Access` → level `0` → Aether authz DENY (`authorization/aether.py:141`, `173-185`) — safe default when headers missing.
5. Attacker sending `X-Auth-Workspace-Access: 40` (ADMIN) + optional tenant/user headers → `require_authorization` ALLOW for admin resources.
6. Contrast: Aether in-process terminator **does** strip inbound spoofed `X-Auth-*` and remint from validated envelope (`tests/integration/test_aether_terminator_chain.py:330-366`). That protection does **not** apply to raw FastAPI HTTP.

### Attacker model

Network client reaching MemoryLayer’s uvicorn port while aether authn/authz plugins are selected, without forcing traffic through the auth-proxy/terminator.

### Impact

Full impersonation of any tenant/user and privilege escalation to SUPERADMIN-equivalent access levels; OBO subject spoofing if OBO headers are accepted without proxy validation (`aether.py:370-445`).

### Mitigations

- Never expose MemoryLayer HTTP when using aether plugins; only attach via Aether front-door / terminator.
- Reject requests lacking a gateway attestation (shared secret, mTLS client cert, or signed header) when aether mode is on.
- Fail closed if `X-Auth-Tenant-ID` is missing in production (remove default-tenant fallback).

---

## Finding 6 — MCP `reveal_secrets=true` has no extra privilege gate

| Field | Detail |
|---|---|
| Severity | **High** under open auth / Finding 1; **Medium** under Aether (any principal with `mcp_servers` read at mapped level) |
| CWE | CWE-200 |
| Exploitable E2E | **Yes** under open auth on reachable bind |

### Call chain

1. List/get/export/resolve accept `reveal_secrets: bool = Query(False)` (`api/v1/mcp_servers.py:123`, `167`, `221`, `410`, `448`, `487`).
2. Authz check is only `mcp_servers` + `read`/`write` — no separate “secrets” action (`mcp_servers.py:178-180`).
3. `_mask_secrets(..., reveal=True)` returns plaintext env/headers (`mcp_servers.py:48-54`).
4. OSS at-rest encryption is a no-op passthrough unless Enterprise registers an encrypter (`services/mcp_servers/encryption.py:30-41`).

### Impact

Exfiltration of MCP server credentials (API keys, DB URLs) stored in `env`/`headers`.

### Mitigations

- Require elevated authz (e.g. `admin` / MANAGE) for `reveal_secrets=true`.
- Default-deny reveal in open-auth mode.
- Enable real at-rest encryption in deployments that store secrets.

---

## Finding 7 — Rate-limit key derived from spoofable `X-Auth-User-ID`

| Field | Detail |
|---|---|
| Severity | **Low** (availability / control bypass, not data access by itself) |
| CWE | CWE-290 |
| Exploitable E2E | **Yes** when a non-noop rate limit service is enabled |

### Call chain

`RateLimitMiddleware` uses `request.headers.get("X-Auth-User-ID")` as the bucket key without verifying authenticity (`middleware/rate_limit.py:62-69`).

### Impact

Attacker rotates spoofed user IDs to bypass per-user limits (falls back to IP only when header absent).

### Mitigations

Derive rate-limit keys from verified `RequestContext` after auth, or from connection identity — not raw client headers.

---

## Explicit non-findings / accepted risks (verified)

| Topic | Verdict |
|---|---|
| Health endpoints without auth (`/health`, `/health/ready`) | Expected; no sensitive data beyond connectivity status (`api/health.py:15-60`). |
| CLI default bind `127.0.0.1` | Safe default for local serve (`config.py:14`). Risk is Docker/`--host 0.0.0.0`. |
| Token plaintext in create response | Standard once-display pattern; not logged (`tokens.py:261-264`). Hashing lives in Aether, not this repo. |
| Aether authz default DENY when access metadata absent | Correct fail-closed for missing level (`authorization/aether.py:125-127`, `141`). |
| Most `/v1/*` routers call `build_context` + `require_authorization` | Confirmed; only `kb_viewer` (detail route) and health skip auth among API routers. |
| Action name mismatches (`"create"` vs mapped `"write"`) under Aether | Unmapped pairs use `_DEFAULT_REQUIRED_LEVEL = MANAGE` (`authorization/aether.py:87-89`) — **more restrictive**, not a bypass. Functional inconsistency, not privilege escalation. |

---

## Answers to review questions

1. **Is default auth actually open (allow-all), and reachable beyond localhost?**  
   Yes — open authn + allow-all authz by default. CLI binds localhost; **Docker image binds `0.0.0.0` with those same defaults**, so yes it is reachable beyond localhost as shipped.

2. **Can tokens be created/used without auth? Are workspace IDs attacker-controllable?**  
   Token CRUD calls auth hooks, but under open auth those hooks do not authenticate; create succeeds if Aether is connected. Workspace IDs are attacker-controllable via body/header/query/path on many endpoints (Finding 3). API key verification in OSS ignores the key entirely (`default.py:53-65`).

3. **Missing auth on endpoints that should be protected?**  
   `GET /kb/{workspace_id}` (Finding 2). All other `/v1` business routers invoke auth hooks (which are no-ops under open defaults).

4. **Token hashing, storage, leakage?**  
   No local hashing/storage — Aether-backed. Plaintext returned once on create; not written to logs in this layer. MCP secrets can be revealed via query flag (Finding 6).

5. **Privilege escalation paths?**  
   Open auth → any caller is effectively admin (`get_user_role` → `"admin"`). Aether header spoofing on direct HTTP → arbitrary access level (Finding 5). Token minting with `workspace_patterns=["*"]` / `scopes=["*"]` under open auth (Finding 4). Cross-workspace IDOR via controllable workspace IDs (Finding 3).

---

## Priority remediation order

1. Treat Docker `0.0.0.0` + open auth as an unsafe combination (fail-closed or warn loudly; prefer localhost or require auth plugin).  
2. Add authz to `GET /kb/{workspace_id}` or disable the route by default.  
3. Enforce workspace scope in Aether (and any non-open) authorization for direct mode; filter workspace listings.  
4. Gate `reveal_secrets` and token admin APIs on strong auth.  
5. Attest gateway headers before trusting `X-Auth-*` on the FastAPI HTTP surface.
