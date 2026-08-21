# Reflected XSS lab (`lab-xss`)

**Intentionally vulnerable. Training use only.**

A tiny standard-library HTTP service whose `/search?q=` endpoint reflects the
`q` parameter into the HTML response without escaping. It attaches only to the
`isolated_labs` internal Docker network — no host ports, no internet — and runs
behind the optional `labs` Compose profile, so it never starts unless you ask
for it:

```bash
docker compose --profile labs up lab-xss
```

## Objective

Inject a `<script>` payload through `q` that runs in the victim's browser and
reads the `SESSION_FLAG` embedded on every page, for example
`q=<script>...</script>`. The reflection is completely unescaped, so the
scanner's reflected-input detection flags the injection context.

The platform's scanner and repeater can target `http://lab-xss:5000/search`
from inside the Compose network once the host is registered in a project scope.
