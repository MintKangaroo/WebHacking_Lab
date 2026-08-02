"""Passive analyzers that never perform network requests."""

from webhacking_lab.analyzers.auth_analyzer import AuthenticationAnalyzer
from webhacking_lab.analyzers.cors_analyzer import CorsAnalyzer
from webhacking_lab.analyzers.header_analyzer import SecurityHeaderAnalyzer
from webhacking_lab.analyzers.injection_analyzer import InjectionIndicatorAnalyzer
from webhacking_lab.analyzers.jwt_analyzer import JwtStructureAnalyzer
from webhacking_lab.analyzers.xss_analyzer import XssReflectionAnalyzer

__all__ = [
    "AuthenticationAnalyzer",
    "CorsAnalyzer",
    "InjectionIndicatorAnalyzer",
    "JwtStructureAnalyzer",
    "SecurityHeaderAnalyzer",
    "XssReflectionAnalyzer",
]
