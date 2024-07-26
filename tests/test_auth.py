import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.utils.auth import AuthManager, UserInDB
from dotenv import load_dotenv
import os

load_dotenv()

client = TestClient(app)

def test_get_access_token():
    response = client.post(
        "/token",
        data={"username": os.getenv("USER_EMAIL"), "password": "7727"},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_get_access_token_invalid_password():
    response = client.post(
        "/token",
        data={"username": os.getenv("USER_EMAIL"), "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}

def test_get_access_token_invalid_username():
    response = client.post(
        "/token",
        data={"username": "invalid@example.com", "password": "7727"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}

def test_get_access_token_inactive_user(monkeypatch):
    def mock_get_user(db, username):
        return UserInDB(
            username=username,
            hashed_password=AuthManager.get_password_hash("7727"),
            disabled=True
        )

    monkeypatch.setattr("app.auth.AuthManager.get_user", mock_get_user)

    response = client.post(
        "/token",
        data={"username": os.getenv("USER_EMAIL"), "password": "7727"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Inactive user"}
