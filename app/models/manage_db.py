from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, select
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from logging import getLogger
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from app.schemas.manage import UserInfo
import os
from typing import List


logger = getLogger('app_logger')

load_dotenv()

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserSignup(Base):
    __tablename__ = 'user_signup'

    id= Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    company_name = Column(String(255), nullable=False)
    user_role = Column(String(50), nullable=False, default="user")
    license_amount = Column(Integer, default=0)
    disabled = Column(Integer, default=1)
    create_date = Column(DateTime)
    update_date = Column(DateTime)

    groups = relationship("Group", back_populates="user")

    @classmethod
    def toggle_disabled_status(cls, user_id: int) -> bool:
        """
        Toggle the disabled status of a user.
        Returns the new disabled status.
        """
        with SessionLocal() as session:
            user = session.query(cls).filter(cls.id == user_id).first()
            if user:
                user.disabled = not user.disabled
                user.update_date = func.now()
                session.commit()
                return user.disabled
            return None

    @classmethod
    def update_license_amount(cls, user_id: int, license_amount: int):
        with SessionLocal() as session:
            user = session.query(cls).filter(cls.id == user_id).first()
            if user:
                user.license_amount = license_amount
                user.update_date = func.now()
                session.commit()
                return True
            return False

    @classmethod
    def get_user_groups(cls, user_id: int) -> List[str]:
        with SessionLocal() as session:
            user = session.query(cls).filter(cls.id == user_id).first()
            if user:
                return [group.group_name for group in user.groups]
            return []

    @classmethod
    def get_user_license(cls, user_id: int) -> int:
        with SessionLocal() as session:
            user = session.query(cls).filter(cls.id == user_id).first()
            return user.license_amount if user else 0

    @classmethod
    def get_total_license(cls) -> int:
        with SessionLocal() as session:
            result = session.execute(select(func.sum(cls.license_amount))).scalar()
            return result or 0
    
    @classmethod
    def get_all_users(cls, db: Session):
        users = db.query(cls).filter(cls.user_role != 'admin').all()
        return [
            UserInfo(
                user_id=user.id,
                username=user.username,
                email=user.email,
                company_name=user.company_name,
                license_amount=user.license_amount,
                disabled=bool(user.disabled)
            )
            for user in users
        ]

class Group(Base):
    __tablename__ = 'group_signup'

    group_name = Column(String(255), primary_key=True, nullable=False)
    user_signup_id = Column(Integer, ForeignKey('user_signup.id'), nullable=True)
    create_date = Column(DateTime, server_default=func.now(), nullable=True)
    update_date = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=True)

    user = relationship("UserSignup", back_populates="groups")
    
Base.metadata.create_all(bind=engine)