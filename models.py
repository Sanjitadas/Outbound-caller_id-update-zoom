# models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
from settings import engine, SessionLocal

Base = declarative_base()


class User(Base):
    """
    Stores allowed users (both Admin and normal users).
    Password stored as plain text as requested.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # relationship to logs
    login_logs = relationship("LoginLog", back_populates="user")
    callerid_updates = relationship("CallerIDUpdate", back_populates="user")


class CallerIDUpdate(Base):
    """
    Logs single or bulk updates of outbound caller IDs.
    """
    __tablename__ = "callerid_updates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email = Column(String(255), nullable=False)  # email being updated
    old_caller_id = Column(String(50))
    new_caller_id = Column(String(50))
    status = Column(String(50))  # "success" / "fail"
    reason = Column(String(255))  # failure reason
    update_type = Column(String(1))  # S=single, B=bulk
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="callerid_updates")


class LoginLog(Base):
    """
    Stores login events.
    """
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    email = Column(String(255))
    success = Column(Boolean, default=True)
    ip_address = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="login_logs")


# -------------------- Create tables if not exists --------------------
def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("Database tables created successfully.")
























