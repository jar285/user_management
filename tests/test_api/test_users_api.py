from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_fetch_user_by_id(async_client, admin_user, admin_token):
    # Request to fetch the user by their unique identifier
    response = await async_client.get(f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200, "Expected a successful response"
    
    # Validate the content of the response
    user_info = response.json()
    assert user_info["id"] == str(admin_user.id), "User ID does not match the expected value"

@pytest.mark.asyncio
async def test_fetch_nonexistent_user(async_client, admin_token):
    # Using a clearly invalid UUID to test error handling
    invalid_user_id = "00000000-0000-0000-0000-000000000000"
    response = await async_client.get(f"/users/{invalid_user_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 404, "Expected a Not Found response for non-existent user"

@pytest.mark.asyncio
async def test_modify_user_details(async_client, admin_user, admin_token):
    # Updating user information, specifically the email address
    modifications = {"email": "new_email@example.com"}
    response = await async_client.put(f"/users/{admin_user.id}", json=modifications, headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200, "Expected a successful update response"
    assert response.json()["email"] == modifications["email"], "Email update not reflected in response"

@pytest.mark.asyncio
async def test_remove_user(async_client, admin_user, admin_token):
    # Request to delete a user
    response = await async_client.delete(f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 204, "Expected successful deletion status"

    # Attempt to fetch the deleted user to verify removal
    verification_response = await async_client.get(f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert verification_response.status_code == 404, "Deleted user should no longer be retrievable"

@pytest.mark.asyncio
async def test_access_user_details(async_client, admin_user, admin_token):
    # Fetch user details to verify accurate retrieval
    response = await async_client.get(f"/users/{admin_user.id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200, "Failed to retrieve user details"
    user_details = response.json()
    assert user_details["id"] == str(admin_user.id) and user_details["email"] == admin_user.email, "Mismatch in user details"

@pytest.mark.asyncio
async def test_overview_of_users(async_client, admin_token):
    # Retrieve a list of users
    response = await async_client.get("/users/", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200, "Failed to fetch user list"
    user_list = response.json()
    assert "items" in user_list, "Response missing expected 'items' key"
    # Validate pagination and structure of user list further if necessary

@pytest.mark.asyncio
async def test_update_professional_status_as_admin(async_client, admin_token, regular_user):
    """Test that an admin can update the professional status."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    updated_status = {"is_professional": True}
    
    # Attempt to update the professional status
    response = await async_client.patch(
        f"/users/{regular_user.id}/professional-status?is_professional=true",
        headers=headers
    )
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == str(regular_user.id)
    assert response_data["is_professional"] is True

@pytest.mark.asyncio
async def test_update_professional_status_as_manager(async_client, manager_token, regular_user):
    """Test that a manager can update the professional status."""
    headers = {"Authorization": f"Bearer {manager_token}"}
    updated_status = {"is_professional": False}
    
    # Attempt to update the professional status
    response = await async_client.patch(
        f"/users/{regular_user.id}/professional-status?is_professional=false",
        headers=headers
    )
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["id"] == str(regular_user.id)
    assert response_data["is_professional"] is False

@pytest.mark.asyncio
async def test_update_professional_status_access_denied(async_client, user_token, regular_user):
    """Test that a regular user cannot update the professional status."""
    headers = {"Authorization": f"Bearer {user_token}"}
    
    # Attempt to update the professional status, expecting an error
    response = await async_client.patch(
        f"/users/{regular_user.id}/professional-status?is_professional=true",
        headers=headers
    )
    assert response.status_code == 403  # Forbidden
    assert "Operation not permitted" in response.json()["detail"]
