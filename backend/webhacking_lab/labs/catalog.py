"""Static catalog of the isolated training labs shipped with the platform.

Each lab is an intentionally vulnerable service that runs only on the
``isolated_labs`` internal Docker network, behind the optional ``labs`` Compose
profile. The catalog is metadata only; it never launches or reaches a lab.
"""

from webhacking_lab.api.schemas.labs import LabInfo

LAB_WARNING = (
    "These targets are intentionally vulnerable and run only on the isolated "
    "internal lab network. Never expose them to an untrusted network."
)

LABS: tuple[LabInfo, ...] = (
    LabInfo(
        id="sqli",
        name="SQL Injection",
        category="sql_injection",
        difficulty="beginner",
        description=(
            "A product lookup that concatenates the id parameter into a SQL "
            "query, allowing UNION-based extraction of a secret flag."
        ),
        base_url="http://lab-sqli:5000",
        target_path="/products?id=1",
        objective="Recover the flag from the secrets table via SQL injection.",
        hint="Try id=0 UNION SELECT 1, flag, 3 FROM secrets.",
    ),
    LabInfo(
        id="xss",
        name="Reflected XSS",
        category="xss",
        difficulty="beginner",
        description=(
            "A search page that reflects the q parameter into the HTML "
            "response without escaping, so an injected script runs in the "
            "browser and can read the session flag."
        ),
        base_url="http://lab-xss:5000",
        target_path="/search?q=hello",
        objective="Inject a script through q that reads the SESSION_FLAG.",
        hint="Try q=<script>alert(document.title)</script> and watch it reflect raw.",
    ),
    LabInfo(
        id="idor",
        name="Insecure Direct Object Reference",
        category="idor",
        difficulty="beginner",
        description=(
            "A notes endpoint that returns any note by id with no ownership "
            "check, so changing the id exposes another user's private note."
        ),
        base_url="http://lab-idor:5000",
        target_path="/notes?id=1",
        objective="Read a note you do not own to recover the flag.",
        hint="You own notes 1 and 2; try /notes?id=42.",
    ),
    LabInfo(
        id="path-traversal",
        name="Path Traversal",
        category="path_traversal",
        difficulty="intermediate",
        description=(
            "A file download endpoint that joins the file parameter onto a "
            "public directory without containment, so ../ sequences read "
            "files outside the document root."
        ),
        base_url="http://lab-path-traversal:5000",
        target_path="/download?file=welcome.txt",
        objective="Escape the public root with ../ to read the secret flag file.",
        hint="Try file=../secret/flag.txt (../../../../etc/passwd also works).",
    ),
    LabInfo(
        id="cmdi",
        name="Command Injection",
        category="command_injection",
        difficulty="intermediate",
        description=(
            "A diagnostics endpoint that concatenates the host parameter into "
            "a shell command, so shell metacharacters run arbitrary commands."
        ),
        base_url="http://lab-cmdi:5000",
        target_path="/ping?host=localhost",
        objective="Run a second command through host to leak the flag from the environment.",
        hint="Try host=localhost; echo $FLAG.",
    ),
)


def list_labs() -> list[LabInfo]:
    """Return the catalog of available training labs."""

    return list(LABS)
