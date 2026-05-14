# V1-era scripts

Single-use scripts kept for reference, not run as part of regular operation.

| Script | Purpose |
|---|---|
| `migrate_v1_to_v2.py` | One-shot helper used during the V1 → V2 cleanup pass. Reads the V1 Elasticsearch / Kibana-era threat data and rewrites it into the new Postgres schema. Not idempotent; not needed for fresh installs. |
