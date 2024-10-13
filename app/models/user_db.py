import os
from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from app.ext.error import ElasticsearchError, UserExistedError, AuthControllerError
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from typing import List
from logging import getLogger
from sqlalchemy import select

# Get the centralized logger
logger = getLogger('app_logger')

# Load environment variables from .env file
load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserSignup(Base):
    __tablename__ = "user_signup"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    company_name = Column(String(255), nullable=False)
    user_role = Column(String(255),nullable=False, default='user')
    license_amount = Column(Integer, nullable=0)
    disabled = Column(Integer, default=1)
    create_date = Column(DateTime, server_default=func.now())
    update_date = Column(DateTime, server_default=func.now(), onupdate=func.now())

    groups = relationship("GroupSignup", back_populates="user")

class GroupSignup(Base):
    __tablename__ = "group_signup"
    group_name = Column(String(255), primary_key=True, index=True, nullable=False)
    user_signup_id = Column(Integer, ForeignKey('user_signup.id'), nullable=False)
    create_date = Column(DateTime, server_default=func.now())
    update_date = Column(DateTime, server_default=func.now(), onupdate=func.now())
    user = relationship("UserSignup", back_populates="groups")

Base.metadata.create_all(bind=engine)

class UserModel:
    
    def __init__(self,id: int, username: str, password: str, disabled: bool, user_role: str = 'user'):
        self.id = id
        self.username = username
        self.password = password
        self.disabled = disabled
        self.user_role = user_role
        
    @staticmethod
    def get_user_groups(user_id: int) -> List[str]:
        try:
            session = SessionLocal()
            stmt = select(GroupSignup.group_name).join(UserSignup.groups).where(UserSignup.id == user_id)
            result = session.execute(stmt)
            groups = [row[0] for row in result]
            session.close()
            return groups
        except Exception as e:
            logger.error(f"Error retrieving user groups: {e}")
            raise ElasticsearchError(f'Database error: {e}')

    @staticmethod
    def check_user_group(user_id: int, group_name: str) -> bool:
        try:
            session = SessionLocal()
            stmt = select(GroupSignup).join(UserSignup.groups).where(UserSignup.id == user_id, GroupSignup.group_name == group_name)
            result = session.execute(stmt).first()
            session.close()
            has_permission = result is not None
            logger.info(f"User {user_id} permission check for group {group_name}: {has_permission}")
            return has_permission
        except Exception as e:
            raise 
        
    @staticmethod
    def create_user_signup(username: str, password: str, email: str, company_name: str, license_amount: int, disabled: bool = True):
        session = SessionLocal()
        try:
            new_user = UserSignup(
                username=username, 
                password=password, 
                email=email, 
                company_name=company_name,
                user_role='user',
                license_amount=license_amount,
                disabled=disabled,
                create_date=func.now(),
                update_date=func.now()
            )
            session.add(new_user)
            session.commit()
            session.refresh(new_user)
        except IntegrityError as e:
            session.rollback()
            if "unique_active_username" in str(e):
                raise UserExistedError("An active user with this username already exists")
            elif "unique_active_email" in str(e):
                raise UserExistedError("An active user with this email already exists")
            else:
                raise AuthControllerError("An error occurred while creating the user")
        except SQLAlchemyError as e:
            session.rollback()
            raise AuthControllerError(f"Database error: {str(e)}")
        finally:
            session.close()

    @staticmethod
    def get_active_user(username: str, email: str):
        session = SessionLocal()
        try:
            user = session.query(UserSignup).filter(
                ((UserSignup.username == username) | (UserSignup.email == email)) &
                (UserSignup.disabled == 0)  
            ).first()
            return user
        finally:
            session.close()

    @staticmethod
    def get_any_user(username: str, email: str):
        session = SessionLocal()
        try:
            user = session.query(UserSignup).filter(
                (UserSignup.username == username) | (UserSignup.email == email)
            ).first()
            return user
        finally:
            session.close()

    @staticmethod
    def get_user_by_username(username: str):
        session = SessionLocal()
        try:
            user = session.query(UserSignup).filter(UserSignup.username == username).first()
            return user
        finally:
            session.close()