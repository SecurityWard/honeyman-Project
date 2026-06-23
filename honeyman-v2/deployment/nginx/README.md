# Nginx site config

`honeyman.conf` is a snapshot of the production nginx config from the VPS at
72.60.25.24. It defines three vhosts:

| vhost | role |
|---|---|
| `dashboard.honeymanproject.com` | Serves the React SPA from `dist/`. Also serves `install.sh` at `/install` so the one-liner on the Add Sensor page actually reaches a shell script. |
| `api.honeymanproject.com` | Reverse-proxies to the FastAPI backend on `127.0.0.1:8000`. WebSocket upgrade headers are passed through for the live feed. |
| `honeymanproject.com` (and `www.`) | 301 redirect to `dashboard.honeymanproject.com`. |

## Deploy

```bash
cp honeyman.conf /etc/nginx/sites-available/honeyman
ln -sf /etc/nginx/sites-available/honeyman /etc/nginx/sites-enabled/honeyman
nginx -t && systemctl reload nginx
```

If certs aren't yet provisioned, get them with certbot afterwards — it will
edit the file in place to add the `ssl_*` and `:80 → :443` directives:

```bash
certbot --nginx \
  -d dashboard.honeymanproject.com \
  -d api.honeymanproject.com \
  -d honeymanproject.com \
  -d www.honeymanproject.com
```

## Watch out for

- **Don't drop backup files in `sites-enabled/`.** Nginx loads everything in
  that dir via `include /etc/nginx/sites-enabled/*;`. A `honeyman.bak-…`
  file there will conflict with the live config and nginx will silently
  ignore one of them (with `[warn] conflicting server name … ignored` in
  the test output). Put backups under `/etc/nginx/backups/` instead.
- **Path is hardcoded.** `root` and the `alias` for `/install` point at
  `/root/honeyman-Project/honeyman-v2/...`. Adjust if the repo lives
  somewhere else.
- **Certbot maintains the ssl_/listen/301 lines.** Re-running certbot is the
  supported way to refresh those; hand-editing them works but they may be
  rewritten on the next renewal hook.
