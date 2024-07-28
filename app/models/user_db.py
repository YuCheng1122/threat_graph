import json
import os
from sqlalchemy import create_engine, Column, String, Boolean, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.ext.error import ElasticsearchError
from dotenv import load_dotenv

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

Base.metadata.create_all(bind=engine)

class UserModel:
    def __init__(self, username: str, password: str, disabled: bool):
        self.username = username
        self.password = password
        self.disabled = disabled

    @staticmethod
    def create_user(username: str, password: str):
        try:
            session = SessionLocal()
            new_user = User(username=username, password=password, disabled=False)
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
                return UserModel(username=user.username, password=user.password, disabled=user.disabled)
            else:
                return None

        except Exception as e:
            print(e)
            raise ElasticsearchError(f'Database error: {e}')
