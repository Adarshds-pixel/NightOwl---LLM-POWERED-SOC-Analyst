"""`admin_sessions` -- server-side record of each admin login.

The signed session cookie used to be the only state, so logout could only
clear the browser's copy: a cookie copied before logout stayed valid for the
full max_age. Each login now creates a row with a random id that the cookie
carries; `require_session_auth` accepts the cookie only while that row exists,
is unexpired and unrevoked, and logout revokes it.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
