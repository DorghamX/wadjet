"""SQLAlchemy models for the Wadjet application.

Section 4 of the build guide defines the domain model.
"""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Users(Base):
    """Users table (section 4).

    - username: unique slug, immutable
    - email: unique
    - display_name
    - password_hash: argon2id
    - is_admin
    - is_active
    - last_login_at
    - created_at / updated_at
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(nullable=False, unique=True)
    email: Mapped[str] = mapped_column(nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(nullable=True)
    password_hash: Mapped[str] = mapped_column(nullable=False)
    is_admin: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_login_at: Mapped[str | None] = mapped_column(nullable=True)
    created_at: Mapped[str] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[str] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )
