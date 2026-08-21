# Isolated labs

Local training services attach only to the `isolated_labs` internal network.
No lab uses host networking or requires internet access, and every lab runs
behind the opt-in `labs` Compose profile, so nothing vulnerable starts unless
you ask for it:

```bash
docker compose --profile labs up lab-sqli
```

The backend joins `isolated_labs` so the scanner and repeater can reach a lab
by its Compose service name (e.g. `http://lab-sqli:5000`) once the target host
is registered in a project scope. `GET /api/labs` returns the catalog, and the
Local Labs UI can launch a pre-filled scan against any running lab.

## Labs

- [`sqli`](./sqli/README.md) — UNION-based SQL injection; recover a flag from a
  `secrets` table.
- [`xss`](./xss/README.md) — reflected XSS; `q` is echoed into the page
  unescaped so a `<script>` payload runs and reads the session flag.
- [`idor`](./idor/README.md) — broken object-level authorization; read another
  user's note by changing the `id`.
- [`path-traversal`](./path-traversal/README.md) — `../` escapes the public
  document root to read the flag (and system files).
- [`cmdi`](./cmdi/README.md) — command injection; `host` is concatenated into a
  shell command, leaking the flag from the environment.
