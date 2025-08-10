from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey
from app.database.config import Base
from sqlalchemy.orm import relationship

# Association tables
user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id"))
)

role_actions = Table(
    "role_actions", Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id")),
    Column("action_id", Integer, ForeignKey("actions.id"))
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    roles = relationship("Role", secondary=user_roles, back_populates="users")

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)
    users = relationship("User", secondary=user_roles, back_populates="roles")
    actions = relationship("Action", secondary=role_actions, back_populates="roles")

class Action(Base):
    __tablename__ = "actions"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)
    roles = relationship("Role", secondary=role_actions, back_populates="actions")