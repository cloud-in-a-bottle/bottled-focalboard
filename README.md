# openhost-focalboard

[Focalboard](https://www.focalboard.com/) — Notion-style boards,
cards, and Kanban for personal task management — packaged as an
OpenHost app with seamless OpenHost SSO.

## What you get

- Focalboard running on `https://focalboard.<zone>/` with TLS
  terminated by the OpenHost outer Caddy.
- The zone owner is auto-logged in to Focalboard on first visit.
  No application-level sign-in form ever appears.
- Real-time board updates (`/ws/onchange`) work through the
  proxy via WebSocket forwarding.
- Persistent state under `/data/app_data/focalboard/` — sqlite
  DB, uploaded files, and the on-disk single-user token.

## Why this app

Focalboard is one of the cleanest open-source picks for an
"agent-facing task store": every board is a flat list of cards
with arbitrary properties (status, priority, assignee, due date,
markdown body), the SPA renders them as Kanban / table /
calendar / gallery views with one click, and the REST API
(`/api/v2/boards/.../blocks`) is straightforward enough that an
LLM agent can post task progress directly. The SPA is fast and
keyboard-driven, and the data model is just blocks-with-props,
so you can shape it to whatever workflow makes sense.

The upstream project has been dormant since 2023 (Mattermost
pivoted away from the standalone product), but the v7.11.4 image
is stable, and the data model is forward-compatible if a future
fork picks up development.

## Architecture

```
browser
   │
   ▼
OpenHost outer Caddy (TLS)
   │
   ▼
OpenHost router (verifies zone_auth JWT;
                 stamps X-OpenHost-Is-Owner: true)
   │
   ▼
container :8090  ── auth_proxy.py ────────────────┐
                   • re-verifies JWT via JWKS    │
                   • on first owner visit, 303's │
                     with FOCALBOARDAUTHTOKEN    │
                     cookie set to the           │
                     configured single-user      │
                     token                       │
                   • subsequent requests:        │
                     forwards verbatim with the  │
                     cookie + an Authorization:  │
                     Bearer <token> header       │
                     injected (defence in depth) │
                                                  │
                                                  ▼
                                       127.0.0.1:8000
                                       focalboard-server
                                       (single-user mode)
```

## Auth model

Focalboard's `-single-user` CLI flag puts the server in fixed-
token mode: every API call must carry the configured token via
the `FOCALBOARDAUTHTOKEN` cookie or `Authorization: Bearer`
header. There is no per-user model, no registration form, no
password.

The auth-proxy:

1. Verifies every inbound request's `zone_auth` cookie against
   the OpenHost router's published JWKS. Non-owners get 403.
2. On the first owner request without `FOCALBOARDAUTHTOKEN`,
   replies 303 to the same URL with the cookie set.
3. On subsequent requests, forwards verbatim and injects
   `Authorization: Bearer <token>` so the cookie path and the
   header path both authenticate (belt and braces).
4. WebSocket upgrades for `/ws/onchange` are JWT-gated and
   then forwarded as bidirectional byte streams; the
   `Authorization` header is injected on the upgrade request.

The single-user token is generated on first boot and persisted
to `$OPENHOST_APP_DATA_DIR/config/single-user-token.txt`.
Rotating means deleting the file, restarting the container,
and clearing the browser's `FOCALBOARDAUTHTOKEN` cookie.

## API access (for agents)

Once an operator has signed in once via the browser, the same
single-user token is the authentication credential for any
out-of-browser API client. Read it from the host:

```bash
oh exec focalboard cat /data/app_data/focalboard/config/single-user-token.txt
```

Then drive the API directly:

```bash
TOKEN="$(cat single-user-token.txt)"
curl -H "Authorization: Bearer $TOKEN" \
     https://focalboard.<zone>/api/v2/teams/0/boards
```

The agent can use this same token to post task progress as
cards or update card properties as work proceeds. The token
does NOT carry an OpenHost zone_auth cookie, so requests from
the agent skip the SSO bounce — they hit the auth-proxy, fail
the JWT check (no cookie), and would normally 403. To allow
agent-direct API access, the operator must either:

- Run the agent on the same host (network-namespace local-
  loopback to the upstream container port — bypasses the
  proxy entirely), or
- Configure the OpenHost router to allow API paths through
  with token-based auth in lieu of zone_auth (planned, not
  yet built).

For now, the simplest pattern is: agent runs in the same
zone (e.g. as another OpenHost app), uses `OPENHOST_*`
environment variables to reach focalboard's container loopback,
and never touches the public URL.

## Persistence

```
$OPENHOST_APP_DATA_DIR/
├── config/
│   ├── single-user-token.txt   # the long-lived auth token
│   └── config.json             # generated runtime config
└── focalboard-data/
    ├── focalboard.db           # sqlite DB (boards, cards, blocks)
    └── files/                  # uploaded attachments
```

## Limitations

- **No multi-user mode.** Single-user is the OpenHost-friendly
  shape; multi-user would require either fronting Focalboard
  with an OIDC issuer (planned for OpenHost) or running it in
  Mattermost-plugin mode (which embeds the boards UI inside
  Mattermost and is out of scope for a standalone app).
- **Upstream is dormant.** Last release v7.11.4 (Aug 2023). The
  app still works fine; bring-your-own-bugfixes is the deal.
- **No mobile native app.** The web UI is responsive enough that
  it works on phones, but Mattermost discontinued the iOS/
  Android Focalboard apps along with the standalone server.
