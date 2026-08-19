# SQL Injection lab (`lab-sqli`)

**Intentionally vulnerable. Training use only.**

A tiny standard-library HTTP service whose `/products?id=` endpoint
concatenates the `id` parameter straight into a SQL query. It attaches only to
the `isolated_labs` internal Docker network — no host ports, no internet — and
runs behind the optional `labs` Compose profile, so it never starts unless you
ask for it:

```bash
docker compose --profile labs up lab-sqli
```

## Objective

Recover the flag stored in the `secrets` table via a UNION-based injection, for
example `id=0 UNION SELECT 1, flag, 3 FROM secrets`. The endpoint also reflects
raw SQLite errors, so error-based detection works too.

The platform's scanner and repeater can target `http://lab-sqli:5000/products`
from inside the Compose network once the target host is registered in a
project's scope.
