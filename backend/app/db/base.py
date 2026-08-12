"""Declarative base shared by every SQLAlchemy model.

Kept in its own module (rather than defined in session.py or a model file)
so both `models/*.py` and `alembic/env.py` can import it without pulling in
engine/session setup or any single model's dependencies.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
