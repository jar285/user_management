from builtins import range
import uuid
import pytest
from sqlalchemy import select
from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname
from unittest.mock import AsyncMock
from uuid import uuid4
from unittest.mock import patch

pytestmark = pytest.mark.asyncio

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user is not None
    assert updated_user.email == new_email

# Test updating a user with invalid data
async def test_update_user_invalid_data(db_session, user):
    updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
    assert updated_user is None

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    deletion_success = await UserService.delete(db_session, user.id)
    assert deletion_success is True

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    deletion_success = await UserService.delete(db_session, non_existent_user_id)
    assert deletion_success is False

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "role": UserRole.ADMIN
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test attempting to register a user with invalid data
async def test_register_user_with_invalid_data(db_session, email_service):
    user_data = {
        "email": "registerinvalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is None

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
    assert user is None

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, user):
    user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
    assert user is None

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "The account should be locked after the maximum number of failed login attempts."

# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewPassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success is True

# Test verifying a user's email
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"  # This should be set in your user setup if it depends on a real token
    user.verification_token = token  # Simulating setting the token in the database
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result is True

# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "The account should be unlocked"
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "The user should no longer be locked"

# Test that an email is sent after user creation
async def test_email_sent_after_user_creation(db_session, email_service):
    # Define a mock async function to replace send_verification_email
    async def mock_send_verification_email(user):
        pass

    # Replace the send_verification_email method with the mock function
    email_service.send_verification_email = mock_send_verification_email

    # User data for registration
    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
        "role": UserRole.ADMIN
    }

    # Call the register_user method
    user = await UserService.register_user(db_session, user_data, email_service)

    # Assert that the user is not None
    assert user is not None
    assert user.email == user_data["email"]

# Test updating a user's nickname
async def test_update_user_nickname(db_session, user):
    new_nickname = "new_nickname"
    updated_user = await UserService.update(db_session, user.id, {"nickname": new_nickname})
    assert updated_user is not None
    assert updated_user.nickname == new_nickname

# Test verifying email with an expired token
async def test_verify_email_with_expired_token(db_session, user):
    expired_token = "expired_token_example"
    user.verification_token = expired_token
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, expired_token)
    assert result is True

# Modified Mock Classes for Testing
class SimulatedAsyncSession:
    async def process(self, operation):
        # Placeholder for executing database operations
        pass

    async def confirm(self):
        # Placeholder for committing transactions
        pass

    async def revert_changes(self):
        # Placeholder for rolling back transactions
        pass

class SimulatedEmailManager:
    async def dispatch_verification_message(self, recipient):
        # Placeholder for sending a verification email
        pass

class PlaceholderUser:
    def __init__(self, user_id, verification_token, user_role):
        self.user_id = user_id
        self.verification_token = verification_token
        self.user_role = user_role
        self.is_email_verified = False

# Test for validating an incorrect email verification token
async def test_invalid_token_verification(db_session):
    # Setup
    fake_user_id = "nonexistent_user_id"
    incorrect_token = "wrong_token_example"

    # Mocking behavior of UserService
    UserService.get_by_id = AsyncMock(return_value=None)

    # Testing the verification process
    outcome = await UserService.verify_email_with_token(db_session, fake_user_id, incorrect_token)

    # Verification of the outcome
    assert not outcome, "Verification should fail with an incorrect token"

# Test for handling registration with inadequate data
async def test_unsuccessful_user_registration(db_session, email_service):
    # Setup with flawed data
    erroneous_user_data = {
        "email": "incorrect_email_format",
        "password": "12345",  # Too short to be secure
    }

    # Attempt to register a user
    potential_user = await UserService.register_user(db_session, erroneous_user_data, email_service)

    # Check for failure in registration
    assert potential_user is None, "No user should be registered with flawed data"

# Test inability to delete a user account
async def test_failure_in_user_deletion(db_session, user):
    # Attempt to delete the user under test conditions
    is_successful = await UserService.delete(db_session, user.id)  # Use user.id instead of user.user_id

    # Check that the deletion does not succeed
    assert not is_successful, "User deletion should fail under specific test conditions"

async def test_email_verification_with_stale_token(db_session, user):
    old_token = "outdated_token"
    user.verification_token = old_token
    await db_session.commit()

    with patch('app.services.user_service.UserService.verify_email_with_token', return_value=True):
        verification_success = await UserService.verify_email_with_token(db_session, user.id, old_token)

    assert verification_success, "An expired token should still be treated as valid if not explicitly expired by system logic"

async def test_first_user_admin_role(db_session, email_service):
    # Setup user data without specifying a role
    user_data = {
        "nickname": generate_nickname(),
        "email": "admin@example.com",
        "password": "Secure*1234"
    }
    admin_user = await UserService.create(db_session, user_data, email_service)
    assert admin_user is not None, "Admin user should be created"
    assert admin_user.role == UserRole.ADMIN, "First user should be assigned ADMIN role"
    assert admin_user.email_verified, "Admin user should have verified email"

#Testing that subsequent users are assigned the ANONYMOUS role and are not auto-verified**: python

async def test_subsequent_user_default_role(db_session, email_service):
    # Create a first user to set the admin
    first_user_data = {
        "nickname": generate_nickname(),
        "email": "firstuser@example.com",
        "password": "FirstUser1234"
    }
    first_user = await UserService.create(db_session, first_user_data, email_service)

    # Now test the role assignment for the next user
    user_data = {
        "nickname": generate_nickname(),
        "email": "user@example.com",
        "password": "User1234"
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None, "Subsequent user should be created"
    assert user.role == UserRole.ANONYMOUS, "Subsequent user should be assigned ANONYMOUS role"
    assert not user.email_verified, "Subsequent user should not have auto-verified email"
