"""Old name kept for compatibility. Use `tronpy.providers.HTTPProvider` instead."""

from .http import HTTPProvider as AsyncHTTPProvider

__all__ = ["AsyncHTTPProvider"]
