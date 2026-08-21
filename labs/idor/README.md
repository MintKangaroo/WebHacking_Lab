# IDOR lab (`lab-idor`)

**Intentionally vulnerable. Training use only.**

A tiny standard-library HTTP service whose `/notes?id=` endpoint returns any
note by its identifier with no ownership check. It attaches only to the
`isolated_labs` internal Docker network — no host ports, no internet — and runs
behind the optional `labs` Compose profile, so it never starts unless you ask
for it:

```bash
docker compose --profile labs up lab-idor
```

## Objective

You own notes `1` and `2`. Increment the identifier to reach a note you do not
own — `/notes?id=42` returns another user's private note, which holds the flag.
This is broken object-level authorization (IDOR); use the repeater to walk the
identifiers.

The platform's repeater can target `http://lab-idor:5000/notes` from inside the
Compose network once the host is registered in a project scope.
