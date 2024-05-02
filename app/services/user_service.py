from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging
from sqlalchemy import func, update, select
from app.schemas.user_schemas import UserCreate, UserUpdate, UserResponse

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            # Determine the role before validation
            user_count = await cls.count(session)
            user_role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS
            user_data['role'] = user_role  # Set the role based on the user count condition

            validated_data = UserCreate(**user_data).model_dump()
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            new_user = User(**validated_data)

            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            new_user.nickname = new_nickname

            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True  # Auto-verify admin for convenience

            new_user.verification_token = generate_verification_token()

            session.add(new_user)
            await session.commit()
            await email_service.send_verification_email(new_user)
            return new_user

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
         # Extract specific data and validate update payload
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

         # If updating password, hash it before saving
            if 'password' in validated_data:
                 validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
        
            # Apply updates to the user
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            result = await cls._execute_query(session, query)
            if result is None:
                logger.error(f"Update failed for User {user_id}")
                return None

        # Fetch updated user to ensure the update was applied
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)  # Ensure the session has the latest data
                logger.info(f"User {user_id} updated successfully with data: {validated_data}")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            return None


    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        return await cls.create(session, user_data, get_email_service)
    

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if user:
            if user.email_verified is False:
                return None
            if user.is_locked:
                return None
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                session.add(user)
                await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            if user.role == UserRole.ANONYMOUS:
                user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
    
    @classmethod
    async def search_users(cls, session: AsyncSession, username: Optional[str] = None, email: Optional[str] = None, first_name: Optional[str] = None, last_name: Optional[str] = None, role: Optional[str] = None, account_status: Optional[str] = None, registration_date_from: Optional[datetime] = None, registration_date_to: Optional[datetime] = None, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User)
        filters = {
            User.nickname: func.lower(username) if username else None,
            User.email: func.lower(email) if email else None,
            User.first_name: func.lower(first_name) if first_name else None,
            User.last_name: func.lower(last_name) if last_name else None,
            User.role: role if role else None,
            User.is_locked: True if account_status and account_status.lower() == 'locked' else (False if account_status and account_status.lower() == 'active' else None),
            User.created_at: (registration_date_from, registration_date_to)
        }
    
        for attribute, value in filters.items():
            if isinstance(value, tuple):  # Special handling for date range
                query = query.filter(attribute >= value[0], attribute <= value[1]) if value[0] and value[1] else query
            elif value is not None:
                query = query.filter(attribute == value)

        query = query.offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        users = result.scalars().all() if result else []

    # Prepare user responses with registration date and account status
        user_responses = [
            UserResponse(
                id=user.id,
                email=user.email,
                nickname=user.nickname,
                is_professional=user.is_professional,
                role=user.role,
                registration_date=user.created_at,
                account_status="Active" if not user.is_locked else "Locked"
            ) for user in users
        ]

        return user_responses

