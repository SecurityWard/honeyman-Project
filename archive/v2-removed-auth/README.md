# V2 Auth Code (Archived)

These files were removed from the V2 backend on 2026-05-09 as part of simplifying
V2 to a public read-only dashboard with per-sensor API keys for write endpoints.

| File | Was at | Removed because |
|---|---|---|
| `auth.py` | `backend/app/api/auth.py` | JWT login flow not used in V2 |
| `security.py` | `backend/app/core/security.py` | JWT + password hashing replaced by API-key SHA256 |
| `user_model.py` | `backend/app/models/user.py` | No user accounts in V2 |
| `user_schema.py` | `backend/app/schemas/user.py` | No user accounts in V2 |

V2 auth model:

- **Read endpoints** (sensors list, threats list, analytics, websocket) are public, no auth.
- **Write endpoints** (sensor heartbeat, threat ingest, rule poll) require `Authorization: Bearer <api_key>` where `<api_key>` is the per-sensor key issued at registration.

See `HONEYMAN-V2-PLAN.md` at the repo root.
