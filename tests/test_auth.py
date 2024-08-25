import requests
import pytest
from requests.exceptions import SSLError, ConnectionError, Timeout

BASE_URL = "https://202.5.255.223/api/auth/login"

def make_login_request(url, username, password, headers=None, timeout=10):
    try:
        response = requests.post(
            url,
            data={"username": username, "password": password},
            headers=headers,
            verify=False,  # Disable SSL verification (not recommended for production)
            timeout=timeout
        )
        return response
    except SSLError:
        pytest.skip("SSL verification failed.")
    except ConnectionError:
        pytest.fail("Failed to connect to the server.")
    except Timeout:
        pytest.fail("Request timed out.")

def test_successful_login():
    response = make_login_request(BASE_URL, "poting", "KYU4m2bmg")
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["success"] == True
    assert "access_token" in json_response["content"]
    assert json_response["content"]["token_type"] == "bearer"
    assert json_response["message"] == "Login successfully"

def test_invalid_credentials():
    response = make_login_request(BASE_URL, "poting", "wrongpassword")
    assert response.status_code == 404
    json_response = response.json()
    assert json_response == {
        "success": False,
        "content": None,
        "message": "Incorrect username or password"
    }

def test_user_not_found():
    response = make_login_request(BASE_URL, "nonexistent_user", "password")
    assert response.status_code == 404
    json_response = response.json()
    assert json_response == {
        "success": False,
        "content": None,
        "message": "Incorrect username or password"
    }

def test_empty_credentials():
    response = make_login_request(BASE_URL, "", "")
    assert response.status_code == 422
    json_response = response.json()
    assert json_response["success"] == False
    assert "message" in json_response
    assert json_response["content"] is None

def test_missing_username():
    response = requests.post(BASE_URL, data={"password": "somepassword"}, verify=False)
    assert response.status_code == 422
    json_response = response.json()
    assert json_response["success"] == False
    assert "message" in json_response
    assert json_response["content"] is None

def test_missing_password():
    response = requests.post(BASE_URL, data={"username": "someuser"}, verify=False)
    assert response.status_code == 422
    json_response = response.json()
    assert json_response["success"] == False
    assert "message" in json_response
    assert json_response["content"] is None

def test_malformed_request():
    response = requests.post(BASE_URL, data="malformed data", verify=False)
    assert response.status_code == 422
    json_response = response.json()
    assert json_response["success"] == False
    assert "message" in json_response
    assert json_response["content"] is None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])