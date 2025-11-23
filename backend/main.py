from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, validator
from typing import Optional, Dict, Any
from .auth import UserSignup, UserLogin, Token, UserResponse, create_access_token, get_auth_system, DatabaseAuth
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import os
import time
import urllib.parse
import logging
from contextlib import asynccontextmanager
import re
from .scanner import HybridPromptScanner as PromptScanner
from .sandbox import SandboxLLM
from .logger import get_logger, DatabaseLogger
from .database import get_db, engine
from .models import Base
from sqlalchemy.orm import Session
import secrets
from fastapi import Cookie, Form
from typing import Optional
import bcrypt

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('aipif.log')
    ]
)
logger = logging.getLogger("aipif")


# Enhanced rate limiting storage with cleanup
class RateLimiter:
    def __init__(self):
        self.requests = {}
        self.last_cleanup = time.time()

    def _cleanup_old_entries(self):
        """Clean up entries older than 1 hour"""
        now = time.time()
        if now - self.last_cleanup > 300:  # Clean every 5 minutes
            for key in list(self.requests.keys()):
                self.requests[key] = [req_time for req_time in self.requests[key]
                                      if now - req_time < 3600]
                if not self.requests[key]:
                    del self.requests[key]
            self.last_cleanup = now

    def is_rate_limited(self, identifier: str, max_requests: int, window_seconds: int) -> bool:
        self._cleanup_old_entries()
        now = time.time()
        if identifier not in self.requests:
            self.requests[identifier] = []

        # Clean old requests
        self.requests[identifier] = [req_time for req_time in self.requests[identifier]
                                     if now - req_time < window_seconds]

        # Check if rate limited
        if len(self.requests[identifier]) >= max_requests:
            return True

        # Add current request
        self.requests[identifier].append(now)
        return False


# Initialize rate limiter
rate_limiter = RateLimiter()


# Configuration from environment variables with defaults
class Settings:
    def __init__(self):
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")
        self.rate_limit_per_minute = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
        self.max_prompt_length = int(os.getenv("MAX_PROMPT_LENGTH", "10000"))
        self.use_database = os.getenv("USE_DATABASE", "true").lower() == "true"
        self.jwt_secret_key = os.getenv("JWT_SECRET_KEY")

        # Validate critical environment variables
        if not self.jwt_secret_key or self.jwt_secret_key == "your-secret-key-change-in-production":
            logger.warning("⚠️  Using default JWT secret key - THIS IS INSECURE FOR PRODUCTION!")
            self.jwt_secret_key = "your-secret-key-change-in-production"


settings = Settings()


def validate_environment():
    """Validate critical environment variables"""
    if not settings.jwt_secret_key or settings.jwt_secret_key == "your-secret-key-change-in-production":
        logger.warning("🚨 INSECURE JWT SECRET - Change JWT_SECRET_KEY in production!")

    if settings.debug:
        logger.warning("⚠️  DEBUG MODE ENABLED - Disable in production!")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting AI Prompt Injection Firewall...")
    validate_environment()

    # Create database tables
    if settings.use_database:
        logger.info("📊 Creating database tables...")
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("✅ Database tables created successfully")
        except Exception as e:
            logger.error(f"❌ Database table creation failed: {e}")
            if settings.debug:
                raise

    try:
        # Test all components
        test_result = scanner.calculate_risk_score("test prompt")
        logger.info(f"✅ Scanner test completed")

        sandbox_result = sandbox.process_prompt("test", 0, "safe")
        logger.info(f"✅ Sandbox test completed")

        # Test logger with database session
        if settings.use_database:
            with next(get_db()) as db:
                test_logger = get_logger(db)
                stats = test_logger.get_stats()
                logger.info(f"✅ Database logger test: {stats['total_requests']} logs found")
        else:
            # Fallback to file logger test
            logs = logger_component.get_logs(limit=1)
            logger.info(f"✅ File logger test: {len(logs)} logs found")

        logger.info("🎉 All components initialized successfully!")
    except Exception as e:
        logger.error(f"❌ Component initialization failed: {e}")
        if settings.debug:
            raise
    yield
    # Shutdown
    logger.info("🛑 Shutting down AI Prompt Injection Firewall...")


app = FastAPI(
    title="AI Prompt Injection Firewall",
    description="Production-grade system for detecting and blocking AI prompt injection attacks",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url="/api/redoc" if settings.debug else None
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Initialize components
scanner = PromptScanner()
sandbox = SandboxLLM()

# For backward compatibility - file-based logger (will be used if USE_DATABASE=false)
try:
    from logger import AIPIFLogger as FileLogger

    logger_component = FileLogger()
except ImportError:
    logger_component = None


# Models with enhanced validation
class ScanRequest(BaseModel):
    prompt: str
    user_ip: Optional[str] = None

    @validator('prompt')
    def validate_prompt_length(cls, v):
        if len(v) > settings.max_prompt_length:
            raise ValueError(f'Prompt too long. Maximum length is {settings.max_prompt_length} characters')
        return v

    @validator('prompt')
    def validate_prompt_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Prompt cannot be empty')
        return v.strip()


class AskRequest(BaseModel):
    prompt: str
    user_ip: Optional[str] = None

    @validator('prompt')
    def validate_prompt_length(cls, v):
        if len(v) > settings.max_prompt_length:
            raise ValueError(f'Prompt too long. Maximum length is {settings.max_prompt_length} characters')
        return v

    @validator('prompt')
    def validate_prompt_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Prompt cannot be empty')
        return v.strip()


class ScanResponse(BaseModel):
    risk_score: int
    category: str
    explanation: Dict[str, Any]
    status: str = "success"


class AskResponse(BaseModel):
    response: str
    status: str
    risk_score: int
    category: str


class LogsResponse(BaseModel):
    logs: list
    total: int
    stats: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: Dict[str, str]
    version: str = "1.0.0"
    uptime: Optional[float] = None
    database_type: str = "file"  # or "database"


class ClearLogsRequest(BaseModel):
    confirm: bool = True
    filters: Optional[Dict[str, Any]] = None


class ClearLogsResponse(BaseModel):
    status: str
    message: str
    deleted_count: Any


# JWT Security
security = HTTPBearer()


async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
):
    """Get current user from JWT token"""
    if settings.use_database:
        auth_system = get_auth_system(db)
        user = auth_system.get_user_by_token(credentials.credentials)
    else:
        # Fallback to file-based auth
        from auth import auth_system as file_auth_system
        user = file_auth_system.get_user_by_token(credentials.credentials)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# Utility functions
def get_client_ip(request: Request) -> str:
    """Extract client IP from request with enhanced detection"""
    if request.client:
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host
    return "unknown"


def sanitize_prompt(prompt: str) -> str:
    """Basic sanitization to prevent obvious XSS"""
    # Remove script tags and other dangerous patterns
    sanitized = re.sub(r'<script\b[^>]*>.*?</script>', '', prompt, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'vbscript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
    # Limit length
    return sanitized[:settings.max_prompt_length]


def check_rate_limit(identifier: str, endpoint: str) -> bool:
    """Check if request is rate limited"""
    max_requests = settings.rate_limit_per_minute
    if endpoint == "/api/logs":
        max_requests = 120  # Higher limit for logs
    elif endpoint == "/api/stats":
        max_requests = 60  # Moderate limit for stats

    return rate_limiter.is_rate_limited(identifier, max_requests, 60)


# Get the correct base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "../frontend")

# Startup time for uptime calculation
STARTUP_TIME = time.time()


# CSRF Models
class CSRFResponse(BaseModel):
    csrf_token: str
    message: str = "CSRF token generated successfully"


class CSRFVerifyRequest(BaseModel):
    csrf_token: str


class CSRFTokenManager:
    def __init__(self):
        self.token_storage = {}
        self.cleanup_interval = 300  # Clean up every 5 minutes
        self.last_cleanup = time.time()

    def generate_token(self, user_id: str = None) -> str:
        """Generate a secure CSRF token"""
        token = secrets.token_urlsafe(32)
        identifier = user_id or "anonymous"

        # Clean up expired tokens periodically
        self._cleanup_expired_tokens()

        # Store token with timestamp
        self.token_storage[token] = {
            "user_id": identifier,
            "created_at": time.time(),
            "used": False
        }

        logger.info(f"🔐 CSRF Token Generated - User: {identifier}")
        return token

    def verify_token(self, token: str, user_id: str = None) -> bool:
        """Verify CSRF token with user context"""
        if not token or token not in self.token_storage:
            logger.warning("❌ CSRF Token not found in storage")
            return False

        token_data = self.token_storage[token]

        # Check if token is expired (15 minutes)
        if time.time() - token_data["created_at"] > 900:  # 15 minutes
            del self.token_storage[token]
            logger.warning("❌ CSRF Token expired")
            return False

        # Check if token already used
        if token_data["used"]:
            logger.warning("❌ CSRF Token already used")
            return False

        # Check user match - if user_id is provided, it must match
        if user_id and token_data["user_id"] != user_id:
            # Allow if token was generated for "authenticated" and we have any authenticated user
            if token_data["user_id"] != "authenticated":
                logger.warning(f"❌ CSRF Token user mismatch - Expected: {user_id}, Got: {token_data['user_id']}")
                return False

        # Mark token as used (one-time use)
        token_data["used"] = True
        logger.info(f"✅ CSRF Token verified - User: {token_data['user_id']}")
        return True

    def _cleanup_expired_tokens(self):
        """Clean up expired tokens periodically"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        expired_tokens = [
            token for token, data in self.token_storage.items()
            if current_time - data["created_at"] > 900
        ]
        for token in expired_tokens:
            del self.token_storage[token]

        self.last_cleanup = current_time
        if expired_tokens:
            logger.info(f"🧹 Cleaned up {len(expired_tokens)} expired CSRF tokens")


# Initialize CSRF manager
csrf_manager = CSRFTokenManager()


# CSRF Protection Middleware
@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next):
    """CSRF protection for state-changing operations"""

    # Skip CSRF for GET, HEAD, OPTIONS
    if request.method in ["GET", "HEAD", "OPTIONS"]:
        response = await call_next(request)
        return response

    # Skip CSRF for public endpoints
    public_paths = [
        "/api/scan",
        "/api/health",
        "/api/docs",
        "/api/redoc",
        "/api/auth/login",
        "/api/auth/signup"
    ]

    if any(request.url.path.startswith(path) for path in public_paths):
        response = await call_next(request)
        return response

    # CSRF token can be in header
    csrf_token = request.headers.get("x-csrf-token")

    # Get current user for token verification (if available)
    current_user = None
    try:
        # Try to get current user from token
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            if settings.use_database:
                with next(get_db()) as db:
                    auth_system = get_auth_system(db)
                    current_user = auth_system.get_user_by_token(token)
            else:
                from auth import auth_system as file_auth_system
                current_user = file_auth_system.get_user_by_token(token)
    except Exception as e:
        logger.warning(f"⚠️ Error getting current user for CSRF: {e}")
        current_user = None

    # Verify CSRF token with user context
    user_id = current_user["id"] if current_user else None
    if not csrf_token or not csrf_manager.verify_token(csrf_token, user_id):
        user_email = current_user['email'] if current_user else 'unknown'
        logger.warning(f"❌ CSRF token validation failed for {request.url.path} - User: {user_email}")
        return JSONResponse(
            status_code=403,
            content={"detail": "Invalid or missing CSRF token"}
        )

    response = await call_next(request)
    return response


# CSRF Token Endpoints
@app.get("/api/csrf-token", response_model=CSRFResponse)
async def get_csrf_token(
        request: Request,
        current_user: dict = Depends(get_current_user)  # ✅ REQUIRE AUTH for CSRF tokens
):
    """Get a CSRF token - REQUIRES AUTHENTICATION"""
    client_ip = get_client_ip(request)

    # Generate token with user association
    user_id = current_user["id"] if current_user else "authenticated"
    csrf_token = csrf_manager.generate_token(user_id)

    logger.info(f"🔐 CSRF token generated for user: {current_user['email']} from IP: {client_ip}")

    return CSRFResponse(csrf_token=csrf_token)


@app.post("/api/verify-csrf")
async def verify_csrf_token(request: CSRFVerifyRequest):
    """Verify a CSRF token (for testing)"""
    is_valid = csrf_manager.verify_token(request.csrf_token)

    return {
        "valid": is_valid,
        "message": "CSRF token is valid" if is_valid else "CSRF token is invalid"
    }


# API Endpoints
@app.post("/api/scan", response_model=ScanResponse)
async def scan_prompt(
        request: ScanRequest,
        http_request: Request,
        db: Session = Depends(get_db)
):
    """Scan prompt for injection attempts"""
    start_time = time.time()
    client_ip = request.user_ip or get_client_ip(http_request)

    # Rate limiting
    if check_rate_limit(client_ip, "/api/scan"):
        logger.warning(f"🚫 Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    try:
        # DEBUG: Print what we receive
        logger.debug(f"🔍 SCAN ENDPOINT: Original prompt: '{request.prompt}'")

        # SCAN THE ORIGINAL PROMPT (don't sanitize before scanning!)
        risk_score, category, explanation = scanner.calculate_risk_score(request.prompt)

        logger.debug(f"🔍 SCAN ENDPOINT: Scan result - Risk: {risk_score}, Category: {category}")

        # Log the scan
        if settings.use_database:
            logger_component = get_logger(db)
            logger_component.log_request(
                prompt=request.prompt,
                risk_score=risk_score,
                category=category,
                action="scanned",
                user_ip=client_ip,
                additional_data=explanation
            )
        else:
            # Fallback to file logger
            logger_component.log_request(
                prompt=request.prompt,
                risk_score=risk_score,
                category=category,
                action="scanned",
                user_ip=client_ip,
                additional_data=explanation
            )

        scan_duration = time.time() - start_time
        logger.info(f"📊 Scan completed in {scan_duration:.2f}s")

        return ScanResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation
        )

    except ValueError as e:
        logger.warning(f"❌ Validation error in scan from {client_ip}: {e}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"❌ Scan error from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Scanning error: {str(e)}")


@app.post("/api/ask", response_model=AskResponse)
async def ask_sandbox(
        request: AskRequest,
        http_request: Request,
        csrf_token: str = None,  # CSRF token from header
        current_user: dict = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Process prompt through sandbox with CSRF protection"""
    # CSRF verification handled by middleware

    start_time = time.time()
    client_ip = request.user_ip or get_client_ip(http_request)

    # Rate limiting
    if check_rate_limit(client_ip, "/api/ask"):
        logger.warning(f"🚫 Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    try:
        # SCAN THE ORIGINAL PROMPT
        risk_score, category, explanation = scanner.calculate_risk_score(request.prompt)

        # Sanitize for the sandbox processing
        sanitized_prompt = sanitize_prompt(request.prompt)

        # Process through sandbox with SANITIZED prompt
        result = sandbox.process_prompt(sanitized_prompt, risk_score, category)

        # Log the request with ORIGINAL prompt
        action = "blocked" if result["status"] == "blocked" else "allowed"

        if settings.use_database:
            logger_component = get_logger(db)
            logger_component.log_request(
                prompt=request.prompt,
                risk_score=risk_score,
                category=category,
                action=action,
                user_ip=client_ip,
                additional_data={
                    "explanation": explanation,
                    "response_status": result["status"],
                    "user_id": current_user["id"],
                    "user_email": current_user["email"],
                    "sanitized_prompt": sanitized_prompt
                },
                user_id=current_user["id"]
            )
        else:
            # Fallback to file logger
            logger_component.log_request(
                prompt=request.prompt,
                risk_score=risk_score,
                category=category,
                action=action,
                user_ip=client_ip,
                additional_data={
                    "explanation": explanation,
                    "response_status": result["status"],
                    "user_id": current_user["id"],
                    "user_email": current_user["email"],
                    "sanitized_prompt": sanitized_prompt
                }
            )

        ask_duration = time.time() - start_time
        logger.info(
            f"📊 Ask request completed in {ask_duration:.2f}s for user {current_user['email']} - Status: {result['status']}")

        return AskResponse(
            response=result["response"],
            status=result["status"],
            risk_score=risk_score,
            category=category
        )

    except ValueError as e:
        logger.warning(f"❌ Validation error in ask from user {current_user['email']}: {e}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"❌ Ask error from user {current_user['email']}: {e}")
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")


@app.get("/api/logs", response_model=LogsResponse)
async def get_logs(
        limit: int = 100,
        offset: int = 0,
        http_request: Request = None,
        db: Session = Depends(get_db)
):
    """Get logs with pagination"""
    client_ip = get_client_ip(http_request) if http_request else "unknown"

    # Rate limiting
    if check_rate_limit(client_ip, "/api/logs"):
        logger.warning(f"🚫 Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    try:
        # Validate parameters
        if limit > 1000:
            limit = 1000
        if limit < 1:
            limit = 1
        if offset < 0:
            offset = 0

        logger.info(f"📊 Fetching logs from {client_ip} - limit: {limit}, offset: {offset}")

        if settings.use_database:
            logger_component = get_logger(db)
            logs = logger_component.get_logs(limit, offset)
            stats = logger_component.get_stats()
        else:
            # Fallback to file logger
            logs = logger_component.get_logs(limit, offset)
            stats = logger_component.get_stats()

        logger.info(f"✅ Found {len(logs)} logs, total requests: {stats['total_requests']}")

        return LogsResponse(
            logs=logs,
            total=stats["total_requests"],
            stats=stats
        )

    except Exception as e:
        logger.error(f"❌ Logs error from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Log retrieval error: {str(e)}")


@app.delete("/api/logs")
async def clear_logs(
        request: ClearLogsRequest,
        http_request: Request,
        current_user: dict = Depends(get_current_user),  # Require authentication
        db: Session = Depends(get_db)
):
    """Clear all logs - REQUIRES AUTHENTICATION"""
    client_ip = get_client_ip(http_request)

    logger.info(f"🔧 CLEAR_LOGS: Attempt by user {current_user['email']} from IP {client_ip}")

    # Rate limiting for destructive operations
    if check_rate_limit(client_ip, "/api/logs"):
        logger.warning(f"🚫 Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    try:
        if not request.confirm:
            logger.info(f"❌ Clear logs cancelled by user {current_user['email']}")
            return ClearLogsResponse(
                status="cancelled",
                message="Clear operation not confirmed",
                deleted_count=0
            )

        # Get current log count before deletion
        from models import SecurityLog
        from sqlalchemy import func

        log_count_before = db.query(func.count(SecurityLog.id)).scalar()
        logger.info(f"🔧 CLEAR_LOGS: Current log count: {log_count_before}")

        if log_count_before == 0:
            return ClearLogsResponse(
                status="success",
                message="No logs to clear",
                deleted_count=0
            )

        # Delete all logs
        deleted_count = db.query(SecurityLog).delete()
        db.commit()

        # Verify deletion
        log_count_after = db.query(func.count(SecurityLog.id)).scalar()
        logger.info(f"🔧 CLEAR_LOGS: Logs after deletion: {log_count_after}")

        if deleted_count > 0:
            logger.info(f"🗑️ User {current_user['email']} cleared {deleted_count} logs from database")
            return ClearLogsResponse(
                status="success",
                message=f"Successfully cleared {deleted_count} security logs",
                deleted_count=deleted_count
            )
        else:
            logger.warning(f"⚠️ No logs were deleted by user {current_user['email']}")
            return ClearLogsResponse(
                status="success",
                message="No logs were found to clear",
                deleted_count=0
            )

    except Exception as e:
        logger.error(f"❌ Clear logs error from user {current_user['email']}: {e}")
        db.rollback()  # Important: rollback on error
        raise HTTPException(status_code=500, detail=f"Failed to clear logs: {str(e)}")


@app.get("/api/health", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """Enhanced system health check"""
    from datetime import datetime

    components = {
        "scanner": "healthy",
        "sandbox": "healthy",
        "logger": "healthy",
        "api": "healthy",
        "database": "healthy"
    }

    # Basic component checks
    try:
        # Test scanner
        scanner.calculate_risk_score("test")

        # Test sandbox
        sandbox.process_prompt("test", 0, "safe")

        # Test logger based on configuration
        if settings.use_database:
            logger_component = get_logger(db)
            stats = logger_component.get_stats()
            components["database"] = "healthy"
        else:
            stats = logger_component.get_stats()
            components["database"] = "file-based"

    except Exception as e:
        components["api"] = f"degraded: {str(e)}"
        logger.warning(f"⚠️ Health check degradation: {e}")

    return HealthResponse(
        status="healthy" if all("healthy" in str(status) for status in components.values()) else "degraded",
        timestamp=datetime.utcnow().isoformat() + "Z",
        components=components,
        uptime=time.time() - STARTUP_TIME,
        database_type="database" if settings.use_database else "file"
    )


@app.get("/api/stats")
async def get_stats(
        http_request: Request,
        db: Session = Depends(get_db)
):
    """Get comprehensive system statistics"""
    client_ip = get_client_ip(http_request)

    # Rate limiting
    if check_rate_limit(client_ip, "/api/stats"):
        logger.warning(f"🚫 Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    try:
        logger.info(f"📈 Calculating stats for {client_ip}...")

        if settings.use_database:
            logger_component = get_logger(db)
            stats = logger_component.get_stats()
            # Get additional stats from database
            from sqlalchemy import func
            from models import SecurityLog

            total_requests = stats["total_requests"]
            blocked_requests = stats["blocked_requests"]
            average_risk_score = stats["average_risk_score"]
            categories = stats["category_breakdown"]
        else:
            # File-based stats
            logs = logger_component.get_logs(limit=10000, offset=0)
            total_requests = len(logs)
            blocked_requests = len([log for log in logs if log.get('action') == 'blocked'])
            allowed_requests = len([log for log in logs if log.get('action') == 'allowed'])

            risk_scores = [log.get('risk_score', 0) for log in logs if log.get('risk_score')]
            average_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

            # Category distribution
            categories = {}
            for log in logs:
                category = log.get('category', 'unknown')
                categories[category] = categories.get(category, 0) + 1

        threat_level = "high" if average_risk_score > 70 else "medium" if average_risk_score > 30 else "low"

        stats_result = {
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "allowed_requests": total_requests - blocked_requests,
            "average_risk_score": round(average_risk_score, 2),
            "category_distribution": categories,
            "threat_level": threat_level,
            "uptime_seconds": round(time.time() - STARTUP_TIME, 2),
            "storage_type": "database" if settings.use_database else "file"
        }

        logger.info(f"✅ Stats calculated for {client_ip}")
        return stats_result

    except Exception as e:
        logger.error(f"❌ Stats error from {client_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Stats calculation error: {str(e)}")


# Auth Endpoints
@app.post("/api/auth/signup", response_model=Token)
async def signup(
        user_data: UserSignup,
        db: Session = Depends(get_db)
):
    """User registration"""
    logger.info(f"🔧 SIGNUP: Attempting to create user: {user_data.email}")

    try:
        auth_system = get_auth_system(db)
        user = auth_system.create_user(user_data)
        logger.info(f"✅ User created: {user['email']}")

        # Create access token
        access_token = create_access_token(data={"sub": user["id"]})
        logger.info(f"✅ Access token created for: {user['email']}")

        user_response = UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            created_at=user["created_at"]
        )

        logger.info(f"👤 New user registered: {user['email']}")

        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )

    except ValueError as e:
        logger.warning(f"❌ Signup validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"❌ Signup error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/api/auth/login", response_model=Token)
async def login(
        user_data: UserLogin,
        db: Session = Depends(get_db)
):
    """User login"""
    logger.info(f"🔧 LOGIN: Attempting login for: {user_data.email}")

    auth_system = get_auth_system(db)
    user = auth_system.authenticate_user(user_data.email, user_data.password)

    if not user:
        logger.warning(f"❌ Failed login attempt for: {user_data.email}")
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token = create_access_token(data={"sub": user["id"]})
    logger.info(f"✅ Login successful for: {user['email']}")

    user_response = UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        created_at=user["created_at"]
    )

    logger.info(f"✅ User logged in: {user['email']}")

    return Token(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        created_at=current_user["created_at"]
    )


# Serve auth pages
@app.get("/login")
async def serve_login():
    login_path = os.path.join(FRONTEND_DIR, "login.html")
    if not os.path.exists(login_path):
        raise HTTPException(status_code=500, detail="Login page not found.")
    return FileResponse(login_path)


@app.get("/signup")
async def serve_signup():
    signup_path = os.path.join(FRONTEND_DIR, "signup.html")
    if not os.path.exists(signup_path):
        raise HTTPException(status_code=500, detail="Signup page not found.")
    return FileResponse(signup_path)


# Serve frontend
@app.get("/")
async def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(index_path):
        logger.error("❌ Frontend files not found")
        raise HTTPException(status_code=500, detail="Frontend files not found. Please check installation.")
    return FileResponse(index_path)


@app.get("/dashboard")
async def serve_dashboard():
    dashboard_path = os.path.join(FRONTEND_DIR, "dashboard.html")
    if not os.path.exists(dashboard_path):
        logger.error("❌ Dashboard file not found")
        raise HTTPException(status_code=500, detail="Dashboard file not found. Please check installation.")
    return FileResponse(dashboard_path)


# Mount static files
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    client_ip = get_client_ip(request)
    logger.error(f"🚨 Unhandled exception from {client_ip} at {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


if __name__ == "__main__":
    logger.info("🔧 Starting production server...")
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level="info" if settings.debug else "warning",
        access_log=True if settings.debug else False,
        workers=1 if settings.debug else min(4, os.cpu_count() or 1)

    )
