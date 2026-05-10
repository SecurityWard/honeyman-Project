# V2 Standalone Provisioning API (Archived)

These files were a standalone Flask provisioning API that duplicated the
sensor-registration logic now living in the FastAPI backend at
`honeyman-v2/dashboard-v2/backend/app/api/onboarding.py`.

| File | Was at | Why archived |
|---|---|---|
| `provisioning_api.py` | `honeyman-v2/readme/onboarding/provisioning_api.py` | Duplicated by the FastAPI `onboarding.py` endpoints; standalone Flask service was never deployed |
| `requirements.txt` | `honeyman-v2/readme/onboarding/requirements.txt` | Was the Flask service's dependency list |

The canonical V2 onboarding flow is documented in `HONEYMAN-V2-PLAN.md`
section "Onboarding". A sensor calls `POST /api/v2/sensors/register` and
receives a one-time API key.
