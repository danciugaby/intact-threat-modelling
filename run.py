"""WSGI entry point: `gunicorn run:app` (production) or `flask --app run run` (dev)."""
from app import create_app

app = create_app()
