# Path traversal lab (`lab-path-traversal`)

**Intentionally vulnerable. Training use only.**

A tiny standard-library HTTP service whose `/download?file=` endpoint joins the
`file` parameter onto a public document root (`/srv/public`) without any
containment check. It attaches only to the `isolated_labs` internal Docker
network — no host ports, no internet — and runs behind the optional `labs`
Compose profile, so it never starts unless you ask for it:

```bash
docker compose --profile labs up lab-path-traversal
```

## Objective

Serve a public file with `/download?file=welcome.txt`, then escape the document
root with `../` sequences. `/download?file=../secret/flag.txt` reads the flag
outside the public root, and `../../../../etc/passwd` reads a system file — the
signature the scanner's path-traversal detection looks for.

The platform's scanner and repeater can target
`http://lab-path-traversal:5000/download` from inside the Compose network once
the host is registered in a project scope.
