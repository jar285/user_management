"""
This Python file is part of a FastAPI application, demonstrating user management functionalities including creating, reading,
updating, and deleting (CRUD) user information. It uses OAuth2 with Password Flow for security, ensuring that only authenticated
users can perform certain operations. Additionally, the file showcases the integration of FastAPI with SQLAlchemy for asynchronous
database operations, enhancing performance by non-blocking database calls.

The implementation emphasizes RESTful API principles, with endpoints for each CRUD operation and the use of HTTP status codes
and exceptions to communicate the outcome of operations. It introduces the concept of HATEOAS (Hypermedia as the Engine of
Application State) by including navigational links in API responses, allowing clients to discover other related operations dynamically.

OAuth2PasswordBearer is employed to extract the token from the Authorization header and verify the user's identity, providing a layer
of security to the operations that manipulate user data.

Key Highlights:
- Use of FastAPI's Dependency Injection system to manage database sessions and user authentication.
- Demonstrates how to perform CRUD operations in an asynchronous manner using SQLAlchemy with FastAPI.
- Implements HATEOAS by generating dynamic links for user-related actions, enhancing API discoverability.
- Utilizes OAuth2PasswordBearer for securing API endpoints, requiring valid access tokens for operations.
"""

from builtins import dict, int, len, str
from datetime import timedelta
from http import HTTPStatus
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Response, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, HTTPException, Response, status, Request, Query
import app
from app.dependencies import get_current_user, get_db, get_email_service, require_role
from app.schemas.pagination_schema import EnhancedPagination
from app.schemas.token_schema import TokenResponse
from app.schemas.user_schemas import LoginRequest, UserBase, UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.utils.link_generation import create_user_links, generate_pagination_links
from app.dependencies import get_settings
import pytest
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from app.schemas.user_schemas import UserUpdate, UserResponse
from app.services.user_service import UserService
from app.dependencies import get_db, oauth2_scheme, require_role
from uuid import UUID
from typing import Optional
from fastapi import Query
from datetime import datetime
from app.schemas.user_schemas import UserListResponse
from app.services.email_service import EmailService
router = APIRouter()
# Setting up the OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db_session: AsyncSession = Depends(get_db)
):
    # Check if the account is locked
    if await UserService.is_account_locked(db_session, form_data.username):
        raise HTTPException(
            status_code=400, 
            detail="Account locked due to too many failed login attempts."
        )
    
    # Attempt to login user with provided credentials
    authenticated_user = await UserService.login_user(db_session, form_data.username, form_data.password)
    if authenticated_user:
        token_expiration = timedelta(minutes=settings.access_token_expire_minutes)
        token_data = {
            "sub": authenticated_user.email,
            "role": str(authenticated_user.role.name)
        }
        
        # Generate access token
        access_token = create_access_token(
            data=token_data, 
            expires_delta=token_expiration
        )

        # Return the access token and type
        return {
            "access_token": access_token, 
            "token_type": "bearer"
        }

    # If login fails, raise an unauthorized error
    raise HTTPException(
        status_code=401, 
        detail="Incorrect email or password."
    )
settings = get_settings()
@router.get("/users/{user_id}", response_model=UserResponse, name="get_user", tags=["User Management Requires (Admin or Manager Roles)"])
async def get_user(user_id: UUID, request: Request, db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme), current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    """
    Endpoint to fetch a user by their unique identifier (UUID).

    Utilizes the UserService to query the database asynchronously for the user and constructs a response
    model that includes the user's details along with HATEOAS links for possible next actions.

    Args:
        user_id: UUID of the user to fetch.
        request: The request object, used to generate full URLs in the response.
        db: Dependency that provides an AsyncSession for database access.
        token: The OAuth2 access token obtained through OAuth2PasswordBearer dependency.
    """
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        id=user.id,
        nickname=user.nickname,
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        profile_picture_url=user.profile_picture_url,
        github_profile_url=user.github_profile_url,
        linkedin_profile_url=user.linkedin_profile_url,
        role=user.role,
        email=user.email,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        links=create_user_links(user.id, request),
        is_professional=user.is_professional  
    )

# Additional endpoints for update, delete, create, and list users follow a similar pattern, using
# asynchronous database operations, handling security with OAuth2PasswordBearer, and enhancing response
# models with dynamic HATEOAS links.

# This approach not only ensures that the API is secure and efficient but also promotes a better client
# experience by adhering to REST principles and providing self-discoverable operations.

@router.put("/users/{user_id}", response_model=UserResponse, name="update_user", tags=["User Management Requires (Admin or Manager Roles)"])
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Update user information.

    - **user_id**: UUID of the user to update.
    - **user_update**: UserUpdate model with updated user information.
    """
    user_data = user_update.model_dump(exclude_unset=True)

    # Restrict sensitive fields based on user roles
    if current_user["role"] not in ["ADMIN", "MANAGER"]:
        user_data.pop("role", None)  # Remove `role` field if not an admin/manager

    updated_user = await UserService.update(db, user_id, user_data)
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        id=updated_user.id,
        bio=updated_user.bio,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        nickname=updated_user.nickname,
        email=updated_user.email,
        role=updated_user.role,
        last_login_at=updated_user.last_login_at,
        profile_picture_url=updated_user.profile_picture_url,
        github_profile_url=updated_user.github_profile_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        is_professional=updated_user.is_professional,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        links=create_user_links(updated_user.id, request)
    )


@router.patch("/users/{user_id}/professional-status", response_model=UserResponse, tags=["User Management"])
async def update_professional_status(
    user_id: UUID,
    is_professional: bool,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    # Retrieve the user from the database
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check that the current user has the right role (ADMIN or MANAGER)
    if current_user["role"] not in ["ADMIN", "MANAGER"]:
        raise HTTPException(status_code=403, detail="You are not authorized to update this user's professional status")

    # Update the professional status
    user.is_professional = is_professional
    await db.commit()

    # Return the updated user information
    return UserResponse(
        id=user.id,
        nickname=user.nickname,
        email=user.email,
        is_professional=user.is_professional,
        professional_status_updated_at=datetime.now(),  # Update the timestamp or get it from the model
        bio=user.bio,
        first_name=user.first_name,
        last_name=user.last_name,
        profile_picture_url=user.profile_picture_url,
        linkedin_profile_url=user.linkedin_profile_url,
        github_profile_url=user.github_profile_url,
        role=user.role,
        created_at=user.created_at,
        updated_at=user.updated_at
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, name="delete_user", tags=["User Management Requires (Admin or Manager Roles)"])
async def delete_user(user_id: UUID, db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme), current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    """
    Delete a user by their ID.

    - **user_id**: UUID of the user to delete.
    """
    success = await UserService.delete(db, user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)



@router.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["User Management Requires (Admin or Manager Roles)"], name="create_user")
async def create_user(user: UserCreate, request: Request, db: AsyncSession = Depends(get_db), email_service: EmailService = Depends(get_email_service), token: str = Depends(oauth2_scheme), current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))):
    """
    Create a new user.

    This endpoint creates a new user with the provided information. If the email
    already exists, it returns a 400 error. On successful creation, it returns the
    newly created user's information along with links to related actions.

    Parameters:
    - user (UserCreate): The user information to create.
    - request (Request): The request object.
    - db (AsyncSession): The database session.

    Returns:
    - UserResponse: The newly created user's information along with navigation links.
    """
    existing_user = await UserService.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
    
    created_user = await UserService.create(db, user.model_dump(), email_service)
    if not created_user:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")
    
    
    return UserResponse.model_construct(
        id=created_user.id,
        bio=created_user.bio,
        first_name=created_user.first_name,
        last_name=created_user.last_name,
        profile_picture_url=created_user.profile_picture_url,
        nickname=created_user.nickname,
        email=created_user.email,
        role=created_user.role,
        last_login_at=created_user.last_login_at,
        created_at=created_user.created_at,
        updated_at=created_user.updated_at,
        links=create_user_links(created_user.id, request),
        is_professional=created_user.is_professional,
        linkedin_profile_url=created_user.linkedin_profile_url,
        github_profile_url=created_user.github_profile_url
    )


@router.get("/users/", response_model=UserListResponse, tags=["User Management Requires (Admin or Manager Roles)"])
async def list_users(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)

    user_responses = [
        UserResponse.model_validate(user) for user in users
    ]
    
    pagination_links = generate_pagination_links(request, skip, limit, total_users)
    
    # Construct the final response with pagination details
    return UserListResponse(
        items=user_responses,
        total=total_users,
        page=skip // limit + 1,
        size=len(user_responses),
        links=pagination_links  # Ensure you have appropriate logic to create these links
    )


@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
async def register(user_data: UserCreate, session: AsyncSession = Depends(get_db), email_service: EmailService = Depends(get_email_service)):
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    if user:
        return user
    raise HTTPException(status_code=400, detail="Email already exists")

@router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_db)):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(status_code=400, detail="Account locked due to too many failed login attempts.")

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if user:
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)

        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name)},
            expires_delta=access_token_expires
        )

        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Incorrect email or password.")

@router.post("/login/", include_in_schema=False, response_model=TokenResponse, tags=["Login and Registration"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_db)):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(status_code=400, detail="Account locked due to too many failed login attempts.")

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if user:
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)

        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name)},
            expires_delta=access_token_expires
        )

        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Incorrect email or password.")


@router.get("/verify-email/{user_id}/{token}", status_code=status.HTTP_200_OK, name="verify_email", tags=["Login and Registration"])
async def verify_email(user_id: UUID, token: str, db: AsyncSession = Depends(get_db), email_service: EmailService = Depends(get_email_service)):
    """
    Verify user's email with a provided token.
    
    - **user_id**: UUID of the user to verify.
    - **token**: Verification token sent to the user's email.
    """
    if await UserService.verify_email_with_token(db, user_id, token):
        return {"message": "Email verified successfully"}
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

@router.get("/users/search/", response_model=UserListResponse, tags=["User Management Requires (Admin or Manager Roles)"])
async def search_users(
    request: Request,
    username: Optional[str] = Query(None, description="Username to search for"),
    email: Optional[str] = Query(None, description="Email to search for"),
    first_name: Optional[str] = Query(None, description="First name to search for"),
    last_name: Optional[str] = Query(None, description="Last name to search for"),
    role: Optional[str] = Query(None, description="Role to search for"),
    account_status: Optional[str] = Query(None, description="Account status to filter (active or locked)"),
    registration_date_from: Optional[datetime] = Query(None, description="Start of registration date range"),
    registration_date_to: Optional[datetime] = Query(None, description="End of registration date range"),
    skip: int = Query(0, description="Number of records to skip"),
    limit: int = Query(10, description="Maximum number of records to return"),
    db: AsyncSession = Depends(get_db)
):
    total_users = await UserService.count(db)

    users = await UserService.search_users(db, username=username, email=email, first_name=first_name, last_name=last_name, role=role, account_status=account_status, registration_date_from=registration_date_from, registration_date_to=registration_date_to, skip=skip, limit=limit)

    if not users:
        raise HTTPException(status_code=404, detail="No users found with the provided criteria.")

    user_responses = [
        UserResponse.model_validate(user) for user in users
    ]

    pagination_links = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=user_responses,
        total=total_users,
        page=skip // limit + 1,
        size=len(user_responses),
        links=pagination_links
    )

#Pytest test case for the create user endpoint, ISSUE #9

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
async def db_session():
    # Assuming you have a session maker or a similar setup
    session = AsyncSession()
    yield session
    await session.rollback()

def test_create_user_endpoint(client, db_session):
    # Define user creation data including professional status and profile URLs
    user_data = {
        "email": "newprofessional@example.com",
        "password": "strongpassword",
        "nickname": "newpro123",
        "is_professional": True,
        "linkedin_profile_url": "https://linkedin.com/in/newpro123",
        "github_profile_url": "https://github.com/newpro123"
    }

    # Send POST request to the create user endpoint
    response = client.post("/users/", json=user_data)
    assert response.status_code == HTTPStatus.CREATED, "Expected 201, got {response.status_code}"

    # Check the response data
    response_json = response.json()
    assert response_json['email'] == user_data['email'], "Email mismatch in response"
    assert response_json['nickname'] == user_data['nickname'], "Nickname mismatch in response"
    assert response_json['is_professional'] == user_data['is_professional'], "Professional status mismatch in response"
    assert response_json['linkedin_profile_url'] == user_data['linkedin_profile_url'], "LinkedIn URL mismatch in response"
    assert response_json['github_profile_url'] == user_data['github_profile_url'], "GitHub URL mismatch in response"

    # Optionally, verify that the response includes navigation links
    assert 'links' in response_json, "Response should include navigation links"
