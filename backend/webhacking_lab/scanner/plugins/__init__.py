"""Bounded SAFE and CTF scanner plugin registry."""

from typing import cast

from webhacking_lab.scanner.plugins.base import ActiveScannerPlugin
from webhacking_lab.scanner.plugins.cors import CorsProbePlugin
from webhacking_lab.scanner.plugins.ctf import (
    CtfOpenRedirectPlugin,
    CtfPathTraversalPlugin,
    CtfReflectedXssPlugin,
    CtfSqlInjectionPlugin,
)
from webhacking_lab.scanner.plugins.open_redirect import OpenRedirectPlugin
from webhacking_lab.scanner.plugins.reflected_xss import ReflectedXssPlugin
from webhacking_lab.scanner.plugins.security_headers import SecurityHeaderPlugin
from webhacking_lab.scanner.plugins.sql_injection import SqlInjectionPlugin

SAFE_ACTIVE_PLUGINS: tuple[ActiveScannerPlugin, ...] = (
    cast(ActiveScannerPlugin, SqlInjectionPlugin()),
    cast(ActiveScannerPlugin, ReflectedXssPlugin()),
    cast(ActiveScannerPlugin, OpenRedirectPlugin()),
    cast(ActiveScannerPlugin, CorsProbePlugin()),
    cast(ActiveScannerPlugin, SecurityHeaderPlugin()),
)

CTF_ACTIVE_PLUGINS: tuple[ActiveScannerPlugin, ...] = (
    cast(ActiveScannerPlugin, CtfSqlInjectionPlugin()),
    cast(ActiveScannerPlugin, CtfReflectedXssPlugin()),
    cast(ActiveScannerPlugin, CtfPathTraversalPlugin()),
    cast(ActiveScannerPlugin, CtfOpenRedirectPlugin()),
)

PLUGIN_BY_ID = {
    plugin.plugin_id: plugin for plugin in (*SAFE_ACTIVE_PLUGINS, *CTF_ACTIVE_PLUGINS)
}

__all__ = [
    "CTF_ACTIVE_PLUGINS",
    "PLUGIN_BY_ID",
    "SAFE_ACTIVE_PLUGINS",
    "ActiveScannerPlugin",
]
