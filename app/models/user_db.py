import json
import os
from sqlalchemy import create_engine, Column, String, Boolean, Integer, Enum, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from app.ext.error import ElasticsearchError
from dotenv import load_dotenv
import logging
from typing import List
from logging import getLogger
from sqlalchemy import select
from sqlalchemy.orm import joinedload

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables from .env file
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)
    user_role = Column(Enum('user', 'admin', name='user_roles'), default='user')
    groups = relationship("Group", back_populates="user")

class Group(Base):
    __tablename__ = "group"
    group_name = Column(String(255), primary_key=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="groups")

Base.metadata.create_all(bind=engine)

class UserModel:
    def __init__(self,id: int, username: str, password: str, disabled: bool, user_role: str = 'user'):
        self.id = id
        self.username = username
        self.password = password
        self.disabled = disabled
        self.user_role = user_role

    @staticmethod
    def create_user(username: str, password: str, user_role: str = 'user'):
        try:
            session = SessionLocal()
            new_user = User(username=username, password=password, disabled=False, user_role=user_role)
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
            session.close()
        except Exception as e:
            print(e)
            raise ElasticsearchError(f'Database error: {e}')

    @staticmethod
    def get_user(username: str):
        try:
            session = SessionLocal()
            user = session.query(User).filter(User.username == username).first()
            session.close()
            if user:
                return UserModel(id=user.id, username=user.username, password=user.password, disabled=user.disabled, user_role=user.user_role)
            else:
                return None
        except Exception as e:
            print(e)
            raise ElasticsearchError(f'Database error: {e}')
        
    @staticmethod
    def get_user_groups(user_id: int) -> List[str]:
        try:
            session = SessionLocal()
            stmt = select(Group.group_name).join(User.groups).where(User.id == user_id)
            result = session.execute(stmt)
            groups = [row[0] for row in result]
            session.close()
            return groups
        except Exception as e:
            print(f"Error retrieving user groups: {e}")
            raise ElasticsearchError(f'Database error: {e}')
        
    @staticmethod
    def check_user_group(user_id: int, group_name: str) -> bool:
        try:
            session = SessionLocal()
            stmt = select(Group).join(User.groups).where(User.id == user_id, Group.group_name == group_name)
            result = session.execute(stmt).first()
            session.close()
            has_permission = result is not None
            logger.info(f"User {user_id} permission check for group {group_name}: {has_permission}")
            return has_permission
        except Exception as e:
            logger.error(f"Database error in check_user_group: {e}")
            raise ElasticsearchError(f'Database error: {e}', 500)