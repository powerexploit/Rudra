"""Importing this package registers all built-in detectors."""
from . import python_ast, rules_yaml, secrets  # noqa: F401
from .base import get_detectors, register  # noqa: F401
