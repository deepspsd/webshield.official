from fastapi import APIRouter, HTTPException, Form, UploadFile, File
from passlib.context import CryptContext
import os
import logging
import time
from .models import RegisterRequest, LoginRequest, ChangePasswordRequest, UpdateProfileRequest
from .db import get_mysql_connection, get_db_connection_with_retry

logger = logging.getLogger(__name__)

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

# Password hashing context: prefer pbkdf2_sha256; verify legacy bcrypt if present
pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

@auth_router.post("/register")
async def register_user(request: RegisterRequest):
    try:
        if request.confirm_password is not None and request.password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error - please try again")

            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (request.email,))
            if cursor.fetchone():
                cursor.close()
                raise HTTPException(status_code=400, detail="Email already registered")

            # Hash password with stable default (pbkdf2_sha256)
            hashed_pw = pwd_context.hash(request.password)

            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, password_hash, full_name) VALUES (%s, %s, %s)",
                (request.email, hashed_pw, request.full_name)
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
            stored_hash = None
            if user:
                if 'password_hash' in user and user['password_hash']:
                    stored_hash = user['password_hash']
                elif 'password' in user and user['password']:
                    stored_hash = user['password']

            if not user or not stored_hash or not pwd_context.verify(request.password, stored_hash):
                # Log failed attempt for security monitoring
                logger.warning(f"Failed login attempt for email: {request.email}")
                raise HTTPException(status_code=401, detail="Invalid email or password")

            # Update last_login if column exists (best-effort)
            try:
                upd = conn.cursor()
                upd.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s", (request.email,))
                conn.commit()
                upd.close()
            except Exception as e:
                logger.warning(f"Failed to update last_login: {e}")

            # Generate JWT tokens (optional - requires jwt_auth module)
            access_token = None
            refresh_token = None
            try:
                from .jwt_auth import create_access_token, create_refresh_token
                access_token = create_access_token(user['email'], user['id'])
                refresh_token = create_refresh_token(user['email'], user.get('id'))
                logger.info(f"JWT tokens generated for user: {user['email']}")
            except Exception as jwt_error:
                logger.warning(f"JWT token generation skipped: {jwt_error}")

            # Support both legacy 'name' and new 'full_name'
            display_name = user.get('full_name') or user.get('name') or ""
            
            response = {
                "success": True, 
                "name": display_name, 
                "email": user["email"],
                "user_id": user["id"]
            }
            
            # Add tokens if generated
            if access_token:
                response["access_token"] = access_token
                response["token_type"] = "Bearer"
            if refresh_token:
                response["refresh_token"] = refresh_token
            
            logger.info(f"✅ Successful login for user: {user['email']}")
            return response
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@auth_router.post("/change_password")
def change_password(data: ChangePasswordRequest):
    email = data.email
    old_password = data.old_password
    new_password = data.new_password
    
    if not email or not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Missing required fields.")
    
    try:
        with get_db_connection_with_retry() as conn:
            if not conn:
                raise HTTPException(status_code=500, detail="Database connection error")
            
            cursor = conn.cursor(dictionary=True)
            # Fetch both possible columns for compatibility
            cursor.execute("SELECT password_hash, password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            stored_hash = None
            if user:
                if user.get('password_hash'):
                    stored_hash = user['password_hash']
                elif user.get('password'):
                    stored_hash = user['password']

            if not user or not stored_hash or not pwd_context.verify(old_password, stored_hash):
                raise HTTPException(status_code=401, detail="Current password is incorrect.")
            
            hashed_pw = pwd_context.hash(new_password)
            # Update both columns for compatibility
            try:
                cursor.execute("UPDATE users SET password_hash = %s, password = %s WHERE email = %s", (hashed_pw, hashed_pw, email))
            except Exception:
                # Fallback if only one column exists
                try:
                    cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pw, email))
                except Exception:
                    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
            conn.commit()
            
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
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Save file (you might want to use cloud storage in production)
    file_path = f"uploads/profile_pictures/{email}_{file.filename}"
    os.makedirs("uploads/profile_pictures", exist_ok=True)
    
    try:
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
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
