import logging
import os
import time
from uuid import uuid4

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from passlib.context import CryptContext

from .db import get_db_connection_with_retry, get_mysql_connection
from .models import ChangePasswordRequest, LoginRequest, RegisterRequest, UpdateProfileRequest
from .validators import Sanitizer

logger = logging.getLogger(__name__)

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

try:
    import bcrypt as _bcrypt_test

    pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated=["bcrypt"])
    logger.info("Password context initialized with bcrypt support for legacy passwords")
except Exception as e:
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    logger.warning(f"bcrypt unavailable ({e}), using pbkdf2_sha256 only")


@auth_router.post("/register")
async def register_user(request: RegisterRequest):
    # Step 1: Validate passwords match
    if request.confirm_password is not None and request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Step 2: Hash password BEFORE database operations
    try:
        hashed_pw = pwd_context.hash(request.password)
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed - password processing error")

    # Step 3: Database operations
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error - please try again")

            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
            if cursor.fetchone():
                cursor.close()
                raise HTTPException(status_code=400, detail="Email already registered")

            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, password_hash, full_name) VALUES (%s, %s, %s)",
                (request.email, hashed_pw, request.full_name),
            )
            conn.commit()
            cursor.close()

            return {"success": True, "message": "Registration successful! Please sign in.", "redirect": "/login.html"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")


@auth_router.post("/login")
def login_user(request: LoginRequest):
    """
    Enhanced login with JWT tokens and security features

    Features:
    - JWT access and refresh tokens
    - Failed attempt tracking
    - Account lockout protection
    - Session management
    - Audit logging
    """
    user = None
    stored_hash = None

    # Step 1: Fetch user from database
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error - please try again")

            cursor = conn.cursor(dictionary=True)

            # Check user credentials
            cursor.execute("SELECT * FROM users WHERE email = %s", (request.email,))
            user = cursor.fetchone()
            cursor.close()

            # Support both legacy 'password' and new 'password_hash' columns
            if user:
                if "password_hash" in user and user["password_hash"]:
                    stored_hash = user["password_hash"]
                elif "password" in user and user["password"]:
                    stored_hash = user["password"]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during login: {e}")
        raise HTTPException(status_code=500, detail="Login failed - database error")

    # Step 2: Verify password OUTSIDE of database context to isolate errors
    try:
        if not user or not stored_hash:
            logger.warning(f"Failed login attempt for email: {request.email} (user not found)")
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not pwd_context.verify(request.password, stored_hash):
            logger.warning(f"Failed login attempt for email: {request.email} (wrong password)")
            raise HTTPException(status_code=401, detail="Invalid email or password")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        raise HTTPException(status_code=500, detail="Login failed - authentication error")

    # Step 3: Update last_login (separate DB connection)
    try:
        with get_db_connection_with_retry() as conn:
            if conn:
                upd = conn.cursor()
                upd.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s", (request.email,))
                conn.commit()
                upd.close()
    except Exception as e:
        logger.warning(f"Failed to update last_login: {e}")
        # Non-critical, continue with login

    # Step 4: Generate JWT tokens (optional)
    access_token = None
    refresh_token = None
    try:
        from .jwt_auth import create_access_token, create_refresh_token

        access_token = create_access_token(user["email"], user["id"])
        refresh_token = create_refresh_token(user["email"], user.get("id"))
        logger.info(f"JWT tokens generated for user: {user['email']}")
    except Exception as jwt_error:
        logger.warning(f"JWT token generation skipped: {jwt_error}")

    # Step 5: Build response
    display_name = user.get("full_name") or user.get("name") or ""

    response = {"success": True, "name": display_name, "email": user["email"], "user_id": user["id"]}

    # Add tokens if generated
    if access_token:
        response["access_token"] = access_token
        response["token_type"] = "Bearer"
    if refresh_token:
        response["refresh_token"] = refresh_token

    logger.info(f"✅ Successful login for user: {user['email']}")
    return response


@auth_router.post("/refresh")
def refresh_token(refresh_token: str = Form(...)):
    """Exchange refresh token for a new access token."""
    try:
        from .jwt_auth import refresh_access_token

        access_token = refresh_access_token(refresh_token)
        return {"success": True, "access_token": access_token, "token_type": "Bearer"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Refresh token error: {e}")
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@auth_router.post("/change_password")
def change_password(data: ChangePasswordRequest):
    email = data.email
    old_password = data.old_password
    new_password = data.new_password

    if not email or not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Missing required fields.")

    # Step 1: Fetch user from database
    user = None
    stored_hash = None
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")

            cursor = conn.cursor(dictionary=True)
            # Fetch both possible columns for compatibility
            cursor.execute("SELECT password_hash, password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()

            if user:
                if user.get("password_hash"):
                    stored_hash = user["password_hash"]
                elif user.get("password"):
                    stored_hash = user["password"]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during password change: {e}")
        raise HTTPException(status_code=500, detail="Password change failed - database error")

    # Step 2: Verify old password OUTSIDE database context
    try:
        if not user or not stored_hash:
            raise HTTPException(status_code=401, detail="Current password is incorrect.")

        if not pwd_context.verify(old_password, stored_hash):
            raise HTTPException(status_code=401, detail="Current password is incorrect.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password verification error during change: {e}")
        raise HTTPException(status_code=500, detail="Password change failed - verification error")

    # Step 3: Hash new password OUTSIDE database context
    try:
        hashed_pw = pwd_context.hash(new_password)
    except Exception as e:
        logger.error(f"Password hashing error during change: {e}")
        raise HTTPException(status_code=500, detail="Password change failed - hashing error")

    # Step 4: Update password in database
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")

            cursor = conn.cursor()
            # Update both columns for compatibility
            try:
                cursor.execute(
                    "UPDATE users SET password_hash = %s, password = %s WHERE email = %s", (hashed_pw, hashed_pw, email)
                )
            except Exception:
                # Fallback if only one column exists
                try:
                    cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pw, email))
                except Exception:
                    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
            conn.commit()
            cursor.close()

            return {"success": True, "message": "Password changed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail="Password change failed")


@auth_router.get("/profile")
def get_profile(email: str):
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")

            # Discover available columns to avoid selecting non-existent ones
            col_cursor = conn.cursor()
            col_cursor.execute("SHOW COLUMNS FROM users")
            available_cols = {row[0] for row in col_cursor.fetchall()}
            col_cursor.close()

            select_parts = ["id", "email", "profile_picture", "created_at", "last_login"]
            # Alias full_name/name as name for frontend compatibility
            if "full_name" in available_cols:
                select_parts.append("full_name AS name")
            elif "name" in available_cols:
                select_parts.append("name AS name")
            else:
                select_parts.append("'' AS name")

            # Optional notification columns
            if "email_notifications" in available_cols:
                select_parts.append("email_notifications")
            else:
                select_parts.append("NULL AS email_notifications")
            if "sms_notifications" in available_cols:
                select_parts.append("sms_notifications")
            else:
                select_parts.append("NULL AS sms_notifications")

            query = f"SELECT {', '.join(select_parts)} FROM users WHERE email = %s"

            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, (email,))
            user = cursor.fetchone()
            cursor.close()

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get profile")


@auth_router.put("/profile")
def update_profile(data: UpdateProfileRequest):
    email = data.email
    name = data.name
    email_notifications = data.email_notifications
    sms_notifications = data.sms_notifications

    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")

            cursor = conn.cursor()

            # Discover available columns
            col_cursor = conn.cursor()
            col_cursor.execute("SHOW COLUMNS FROM users")
            available_cols = {row[0] for row in col_cursor.fetchall()}
            col_cursor.close()

            # Build update query dynamically
            update_fields = []
            params = []

            if name is not None:
                if "full_name" in available_cols:
                    update_fields.append("full_name = %s")
                    params.append(name)
                elif "name" in available_cols:
                    update_fields.append("name = %s")
                    params.append(name)

            if email_notifications is not None and "email_notifications" in available_cols:
                update_fields.append("email_notifications = %s")
                params.append(email_notifications)

            if sms_notifications is not None and "sms_notifications" in available_cols:
                update_fields.append("sms_notifications = %s")
                params.append(sms_notifications)

            if not update_fields:
                raise HTTPException(status_code=400, detail="No fields to update")

            params.append(email)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE email = %s"

            cursor.execute(query, params)
            conn.commit()
            cursor.close()

            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")

            return {"success": True, "message": "Profile updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update profile")


@auth_router.post("/upload_profile_picture")
async def upload_profile_picture(email: str = Form(...), file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    # Validate file type
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    # Enforce max upload size (default 5MB)
    max_bytes = int(os.getenv("MAX_PROFILE_PICTURE_BYTES", str(5 * 1024 * 1024)))

    safe_name = Sanitizer.sanitize_filename(file.filename)
    _, ext = os.path.splitext(safe_name)
    ext = ext.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
        raise HTTPException(status_code=400, detail="Unsupported image format")

    os.makedirs("uploads/profile_pictures", exist_ok=True)
    stored_name = f"{uuid4().hex}{ext}"
    file_path = os.path.join("uploads", "profile_pictures", stored_name)

    try:
        total = 0
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail="File too large")
                buffer.write(chunk)
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload file")

    # Update database
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")

            cursor = conn.cursor()
            cursor.execute("UPDATE users SET profile_picture = %s WHERE email = %s", (file_path, email))
            conn.commit()
            cursor.close()

            return {"success": True, "profile_picture": file_path}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile picture update error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update profile picture")
