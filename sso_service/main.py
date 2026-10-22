"""ASGI entry point for ``uvicorn sso_service.main:app``; the CLI ``serve`` is the deployed path."""

from .api import create_app

app = create_app()
