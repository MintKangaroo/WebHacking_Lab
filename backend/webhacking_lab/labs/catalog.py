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
)


def list_labs() -> list[LabInfo]:
    """Return the catalog of available training labs."""

    return list(LABS)
