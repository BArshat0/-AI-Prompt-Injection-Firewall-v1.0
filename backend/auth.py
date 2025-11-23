import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
import jwt
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session
from database import get_db
from models import User
import bcrypt
import logging

# Configure logging
logger = logging.getLogger("aipif.auth")

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Validate JWT secret
if not SECRET_KEY or SECRET_KEY == "your-secret-key-change-in-production":
    logger.warning("🚨 INSECURE JWT SECRET - Change JWT_SECRET_KEY in production!")


# User models
class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if len(v) > 20:
            raise ValueError('Username must be less than 20 characters')
        if not v.replace('_', '').isalnum():
            raise ValueError('Username can only contain letters, numbers and underscores')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    created_at: str


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# Database Auth System
class DatabaseAuth:
    def __init__(self, db: Session):
        self.db = db

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt"""
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt).decode()
        except Exception as e:
            logger.error(f"❌ Password hashing failed: {e}")
            raise

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against bcrypt hash"""
        try:
            return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
        except Exception as e:
            logger.error(f"❌ Password verification failed: {e}")
            return False

    def create_user(self, user_data: UserSignup) -> Dict[str, Any]:
        # Check if user already exists
        existing_user = self.db.query(User).filter(
            (User.email == user_data.email) | (User.username == user_data.username)
        ).first()

        if existing_user:
            if existing_user.email == user_data.email:
                raise ValueError("Email already registered")
            else:
                raise ValueError("Username already taken")

        # Create new user
        user_id = secrets.token_urlsafe(16)
        user = User(
            id=user_id,
            username=user_data.username,
            email=user_data.email,
            password_hash=self._hash_password(user_data.password),
            created_at=datetime.utcnow(),
            last_login=None,
            is_active=True
        )

        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        logger.info(f"✅ User created: {user.email}")

        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'created_at': user.created_at.isoformat() + "Z"
        }

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.email == email).first()
        if user and self._verify_password(password, user.password_hash):
            # Update last login
            user.last_login = datetime.utcnow()
            self.db.commit()

            logger.info(f"✅ User authenticated: {user.email}")

            return {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat() + "Z"
            }

        logger.warning(f"❌ Authentication failed for: {email}")
        return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        user = self.db.query(User).filter(User.id == user_id).first()
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.isoformat() + "Z"
            }
        return None

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get user from JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id: str = payload.get("sub")
            if user_id is None:
                logger.warning("❌ JWT token missing subject")
                return None
            return self.get_user_by_id(user_id)
        except jwt.ExpiredSignatureError:
            logger.warning("❌ JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ JWT token decoding error: {e}")
            return None


# File-based Auth System
class FileAuth:
    def __init__(self, user_file: str = "users.json"):
        self.user_file = user_file
        self.users_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(self.users_dir, exist_ok=True)
        self.user_file_path = os.path.join(self.users_dir, user_file)
        self.users = self._load_users()

    def _load_users(self) -> Dict[str, Any]:
        """Load users from JSON file"""
        try:
            if os.path.exists(self.user_file_path):
                with open(self.user_file_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"❌ Error loading users: {e}")
        return {}

    def _save_users(self):
        """Save users to JSON file"""
        try:
            with open(self.user_file_path, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Error saving users: {e}")

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt with salt"""
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt).decode()
        except Exception as e:
            logger.error(f"❌ Password hashing failed: {e}")
            raise

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against bcrypt hash"""
        try:
            return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
        except Exception as e:
            logger.error(f"❌ Password verification failed: {e}")
            return False

    def create_user(self, user_data: UserSignup) -> Dict[str, Any]:
        """Create a new user"""
        # Check if email already exists
        for user_id, user in self.users.items():
            if user['email'] == user_data.email:
                raise ValueError("Email already registered")
            if user['username'] == user_data.username:
                raise ValueError("Username already taken")

        # Create new user
        user_id = secrets.token_urlsafe(16)
        user = {
            'id': user_id,
            'username': user_data.username,
            'email': user_data.email,
            'password_hash': self._hash_password(user_data.password),
            'created_at': datetime.utcnow().isoformat() + "Z",
            'last_login': None
        }

        self.users[user_id] = user
        self._save_users()

        logger.info(f"✅ User created: {user['email']}")

        return user

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user and return user data if valid"""
        for user_id, user in self.users.items():
            if user['email'] == email:
                if self._verify_password(password, user['password_hash']):
                    # Update last login
                    user['last_login'] = datetime.utcnow().isoformat() + "Z"
                    self._save_users()

                    logger.info(f"✅ User authenticated: {user['email']}")

                    return user
                break

        logger.warning(f"❌ Authentication failed for: {email}")
        return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        return self.users.get(user_id)

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get user from JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id: str = payload.get("sub")
            if user_id is None:
                logger.warning("❌ JWT token missing subject")
                return None
            return self.get_user_by_id(user_id)
        except jwt.ExpiredSignatureError:
            logger.warning("❌ JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ JWT token decoding error: {e}")
            return None


# Factory function to get auth system
def get_auth_system(db: Session = None):
    """Get appropriate auth system based on configuration"""
    use_database = os.getenv("USE_DATABASE", "true").lower() == "true"
    logger.info(f"🔧 Auth System: Using {'DATABASE' if use_database else 'FILE'} storage")

    if use_database and db:
        return DatabaseAuth(db)
    else:
        return FileAuth()


# Initialize file-based auth system for backward compatibility
auth_system = FileAuth()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"✅ JWT Token created for user: {data.get('sub')}")
        return encoded_jwt
    except Exception as e:
        logger.error(f"❌ JWT Token creation failed: {e}")
        raise