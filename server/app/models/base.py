"""Declarative base for every Wadjet model."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """All models inherit from this so Alembic can autogenerate migrations."""
