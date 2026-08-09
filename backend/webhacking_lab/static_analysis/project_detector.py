"""Detect project languages and frameworks without dependency installation."""

import json
import tomllib
from pathlib import Path

from webhacking_lab.static_analysis.models import IndexedFile, ProjectDetection

DEPENDENCY_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
}
MAX_DETECTION_SAMPLE = 2_000_000


def _safe_text(root: Path, relative_path: str) -> str:
    return (root / relative_path).read_text(encoding="utf-8", errors="replace")


def _sample_language(root: Path, files: list[IndexedFile], languages: set[str]) -> str:
    remaining = MAX_DETECTION_SAMPLE
    samples: list[str] = []
    for item in files:
        if item.language not in languages or remaining <= 0:
            continue
        sample = _safe_text(root, item.relative_path)[:remaining]
        samples.append(sample)
        remaining -= len(sample)
    return "\n".join(samples).lower()


def _python_dependencies(root: Path, paths: set[str], warnings: list[str]) -> str:
    values: list[str] = []
    requirements = next((path for path in paths if Path(path).name == "requirements.txt"), None)
    if requirements:
        values.extend(_safe_text(root, requirements).lower().splitlines())
    pyproject = next((path for path in paths if Path(path).name == "pyproject.toml"), None)
    if pyproject:
        try:
            document = tomllib.loads(_safe_text(root, pyproject))
            values.append(str(document).lower())
        except tomllib.TOMLDecodeError:
            warnings.append("pyproject.toml could not be parsed; source imports were still checked")
    return "\n".join(values)


def detect_project(root: Path, files: list[IndexedFile]) -> ProjectDetection:
    """Infer supported frameworks from manifests and inert source text."""

    paths = {item.relative_path for item in files}
    languages = sorted({item.language for item in files})
    dependencies = sorted(path for path in paths if Path(path).name in DEPENDENCY_NAMES)
    warnings: list[str] = []
    framework_signals: set[str] = set()
    python_dependency_text = _python_dependencies(root, paths, warnings)
    python_sources = _sample_language(root, files, {"python"})
    python_signals = f"{python_dependency_text}\n{python_sources}"
    for dependency, framework in (
        ("flask", "Flask"),
        ("django", "Django"),
        ("fastapi", "FastAPI"),
        ("starlette", "Starlette"),
        ("bottle", "Bottle"),
    ):
        if dependency in python_signals:
            framework_signals.add(framework)

    package_path = next((path for path in paths if Path(path).name == "package.json"), None)
    if package_path:
        try:
            package = json.loads(_safe_text(root, package_path))
            package_text = json.dumps(package).lower()
            for dependency, framework in (
                ("express", "Express"),
                ("@nestjs/", "NestJS"),
                ("next", "Next.js"),
                ("koa", "Koa"),
                ("@hapi/", "Hapi"),
            ):
                if dependency in package_text:
                    framework_signals.add(framework)
        except (json.JSONDecodeError, TypeError):
            warnings.append("package.json could not be parsed")

    composer_path = next((path for path in paths if Path(path).name == "composer.json"), None)
    if composer_path:
        try:
            composer_text = json.dumps(json.loads(_safe_text(root, composer_path))).lower()
            for dependency, framework in (
                ("laravel/framework", "Laravel"),
                ("symfony/framework-bundle", "Symfony"),
                ("codeigniter", "CodeIgniter"),
            ):
                if dependency in composer_text:
                    framework_signals.add(framework)
        except (json.JSONDecodeError, TypeError):
            warnings.append("composer.json could not be parsed")
    if "php" in languages and not framework_signals.intersection(
        {"Laravel", "Symfony", "CodeIgniter"}
    ):
        framework_signals.add("Plain PHP")

    java_text = _sample_language(root, files, {"java", "xml", "groovy", "kotlin"})
    if "spring-boot" in java_text or "org.springframework" in java_text:
        framework_signals.add("Spring Boot")

    return ProjectDetection(
        languages=languages,
        frameworks=sorted(framework_signals),
        dependency_files=dependencies,
        warnings=sorted(set(warnings)),
    )
