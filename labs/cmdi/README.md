# Command injection lab (`lab-cmdi`)

**Intentionally vulnerable. Training use only.**

A tiny standard-library HTTP service whose `/ping?host=` endpoint concatenates
the `host` parameter into a shell command run through `/bin/sh -c`. It attaches
only to the `isolated_labs` internal Docker network — no host ports, no
internet — and runs behind the optional `labs` Compose profile, so it never
starts unless you ask for it:

```bash
docker compose --profile labs up lab-cmdi
```

## Objective

A normal request (`/ping?host=localhost`) just echoes the host. Because the
input is concatenated into a shell command, a payload like
`host=localhost; echo $FLAG` runs a second command and leaks the flag from the
process environment. `$(...)` and backtick substitution work too.

The platform's repeater can target `http://lab-cmdi:5000/ping` from inside the
Compose network once the host is registered in a project scope.
