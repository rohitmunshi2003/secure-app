# app.py
# All imports
from flask import Flask, render_template, request, redirect, url_for, make_response, g, session, jsonify
import os
import time
import bcrypt
import json
from flask import flash
import smtplib
from email.message import EmailMessage
import config
from utils.decorator import require_role
from utils.auth import SessionManager
from utils.validators import validate_password_strength, validate_username, validate_email
from flask import send_file
import io
from utils.encryption import decrypt_file
from werkzeug.utils import secure_filename  # for safe filenames
from utils.encryption import encrypt_file, decrypt_file  # encryption utils
import os
import datetime
from utils.logger import SecurityLogger
from collections import defaultdict
import time
import html
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Track login attempts per IP 
# defaultdict is a dictionary that automatically initializes missing keys.
# Here, each IP address will map to a list of timestamps of login attempts.
login_attempts = defaultdict(list)

# Maximum allowed login attempts per minute, loaded from config.py
MAX_ATTEMPTS_PER_MINUTE = config.MAX_ATTEMPTS_PER_MINUTE

# Time window in seconds during which login attempts are counted
WINDOW_SECONDS = config.WINDOW_SECONDS

# Initialize security logger to record security-related events
# Logs will be saved to 'logs/security.log'
security_log = SecurityLogger(log_file='logs/security.log')


# Flask app setup 
# Create a Flask app instance
# Flask is a lightweight web framework for Python
app = Flask(__name__)

# Load application configuration from config.py
# This can include SECRET_KEY, database configs, session timeout, etc.
app.config.from_object(config)

# Initialize the session manager for handling user sessions
# The timeout is read from the configuration
session_manager = SessionManager(timeout=config.SESSION_TIMEOUT)

# Define directories for data storage and uploads
DATA_DIR = config.DATA_DIR  # Main directory for application data
UPLOAD_DIR = config.UPLOAD_DIR  # Directory to save uploaded files
ALLOWED_EXTENSIONS = config.ALLOWED_EXTENSIONS  # Set of file extensions that are allowed

# Ensure DATA_DIR exists, create if it doesn't
os.makedirs(DATA_DIR, exist_ok=True)

# Define file path for storing user information
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# Ensure UPLOAD_DIR exists, create if it doesn't
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Helper functions
def load_users():
    """
    Load all users from USERS_FILE (users.json).
    If the file doesn't exist, return an empty dictionary.
    If the file contains invalid JSON, also return an empty dictionary.
    """
    if not os.path.exists(USERS_FILE):
        # File does not exist, so no users yet
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            # Attempt to load JSON data into a dictionary
            return json.load(f)
        except json.JSONDecodeError:
            # JSON is corrupted or empty, return empty dict
            return {}


def save_users(users):
    """
    Save the users dictionary to USERS_FILE (users.json).
    Uses indent=2 for pretty formatting for readability.
    """
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def is_duplicate_user(username, email):
    """
    Check if a username or email is already registered.
    Returns True if either exists, False otherwise.
    """
    users = load_users()  # Load all existing users
    for u in users.values():  # Loop through each user dictionary
        if u["username"] == username or u["email"] == email:
            # Found a duplicate username or email
            return True
    return False  # No duplicates found


def get_user_by_id(user_id):
    """
    Retrieve user details by user ID.
    Returns None if the user does not exist.
    """
    users = load_users()  # Load all users
    return users.get(user_id)  # Get user by ID, or None if not found


def get_user_by_username(username):
    """
    Retrieve user by username or email.
    Returns a tuple (user_id, user_dict) if found, else (None, None)
    """
    users = load_users()  # Load all users
    for uid, u in users.items():
        if u["username"] == username or u["email"] == username:
            # Found a user with matching username or email
            return uid, u
    # No matching user found
    return None, None


def current_user_role():
    """
    Return the role of the currently logged-in user.
    Returns None if no user is logged in.
    """
    if not g.user_id:
        # g.user_id is None => no user logged in
        return None
    user = get_user_by_id(g.user_id)  # Get the user dictionary
    return user.get("role") if user else None  # Return the role if user exists


# File paths for versioning and audit logs
VERSIONS_FILE = os.path.join(DATA_DIR, "versions.json")  # Stores file version history
AUDIT_FILE = os.path.join(DATA_DIR, "audit.json")        # Stores audit logs for actions


def load_versions():
    """
    Load file versions from VERSIONS_FILE.
    Returns empty dict if file does not exist or JSON is invalid.
    """
    if not os.path.exists(VERSIONS_FILE):
        return {}
    with open(VERSIONS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_versions(versions):
    """
    Save file versions to VERSIONS_FILE.
    """
    with open(VERSIONS_FILE, "w") as f:
        json.dump(versions, f, indent=2)


def allowed_file(filename):
    """
    Check if a file has an allowed extension.
    Returns True if allowed, False otherwise.
    """
    # Split filename from the last dot and check extension in allowed list
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_input(value):
    """
    Sanitize user input to prevent XSS attacks.
    - Strips whitespace from start and end
    - Escapes HTML special characters
    """
    if not value:
        return ""  # Return empty string if input is None or empty
    return html.escape(value.strip())  # Remove spaces and escape HTML


def log_audit(user_id, action, filename):
    """
    Log user actions (upload, download, delete, etc.) to AUDIT_FILE.
    Each entry contains user_id, action, file name, epoch timestamp, and human-readable timestamp.
    """
    entry = {
        "user_id": user_id,
        "action": action,
        "file": filename,
        "timestamp": time.time(),  # Epoch time
        "readable_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Human-readable time
    }

    audit = []
    if os.path.exists(AUDIT_FILE):
        try:
            # Load existing audit entries if file exists
            with open(AUDIT_FILE, "r") as f:
                audit = json.load(f)
        except json.JSONDecodeError:
            # Ignore if JSON is invalid
            pass

    # Append the new entry to audit list
    audit.append(entry)

    # Save updated audit log back to file
    with open(AUDIT_FILE, "w") as f:
        json.dump(audit, f, indent=2)


# File paths for file sharing metadata
SHARES_FILE = os.path.join(DATA_DIR, "shares.json")


def load_shares():
    """
    Load file sharing information from SHARES_FILE.
    Returns empty dict if file does not exist or JSON invalid.
    """
    if not os.path.exists(SHARES_FILE):
        return {}
    with open(SHARES_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_shares(shares):
    """
    Save file sharing information to SHARES_FILE.
    """
    with open(SHARES_FILE, "w") as f:
        json.dump(shares, f, indent=2)


# Make the current_user_role() function available in Jinja2 templates
@app.context_processor
def inject_user():
    """
    Injects current_user_role into all templates automatically.
    Allows templates to use {{ current_user_role }}.
    """
    return dict(current_user_role=current_user_role)


# Temporary dictionary to store OTP codes for verification
OTP_STORE = {}

# SMTP configuration for sending emails
SMTP_SERVER = config.SMTP_SERVER
SMTP_PORT = config.SMTP_PORT
EMAIL_ADDRESS = config.EMAIL_ADDRESS
EMAIL_PASSWORD = config.EMAIL_PASSWORD


def send_email(to_email, subject, body):
    """
    Send an email using SMTP with TLS.
    Returns True if successful, False otherwise.
    """
    try:
        msg = EmailMessage()         # Create email message object
        msg.set_content(body)        # Set email body
        msg["Subject"] = subject     # Set email subject
        msg["From"] = EMAIL_ADDRESS  # Set sender
        msg["To"] = to_email         # Set recipient

        # Connect to SMTP server
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.set_debuglevel(1)  # Enable debug logging for SMTP
            server.starttls()         # Start TLS encryption
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  # Login
            server.send_message(msg)  # Send the email

        return True  # Email sent successfully

    except Exception as e:
        # Print the error if sending fails
        print("Failed to send email:", e)
        return False
# Helper functions ends here


# User session management for Flask 
@app.before_request
def load_user_session():
    """
    Load user session information before handling each request.
    Sets g.user_id, g.session_token, g.user_role.
    """
    g.user_id = None         # Default to None (no user)
    g.session_token = None   # Default session token
    g.user_role = 'guest'    # Default role

    # Enforce HTTPS in production 
    if not request.is_secure and not app.debug:
        # Redirect HTTP requests to HTTPS
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

    # Clean up expired sessions
    session_manager.cleanup_sessions()

    # Get session token from cookies
    token = request.cookies.get("session_token")
    if token:
        # Validate session token
        session_data = session_manager.validate_session(token)
        if session_data:
            g.user_id = session_data["user_id"]  # Store user ID in global context
            g.session_token = token             # Keep token to refresh cookie later

            # Retrieve user's role from database
            user = get_user_by_id(g.user_id)
            if user:
                g.user_role = user.get('role', 'guest')


@app.after_request
def refresh_session_cookie(response):
    """
    Refresh session cookie and set security headers after each request.
    """
    if getattr(g, "session_token", None):
        # Set session cookie in response
        response.set_cookie(
            "session_token",
            g.session_token,
            httponly=True,     # Prevent JavaScript from accessing cookie
            secure=True,       # Only send cookie over HTTPS
            samesite="Strict", # Mitigate CSRF
            max_age=session_manager.timeout
        )

    # Security headers 
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


# TEMP USER STATUS FILE 
# Used to store temporary user states (e.g., during OTP verification)
TEMP_STATUS_FILE = os.path.join(DATA_DIR, "temp_status.json")

# Ensure DATA_DIR exists
os.makedirs(DATA_DIR, exist_ok=True)

# Helper function again starts here 
def load_temp_status():
    """
    Load temporary user status from TEMP_STATUS_FILE.
    Returns empty dict if file does not exist or JSON is invalid.
    """
    if not os.path.exists(TEMP_STATUS_FILE):
        return {}
    with open(TEMP_STATUS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_temp_status(temp_status):
    """
    Save temporary user status to TEMP_STATUS_FILE.
    """
    with open(TEMP_STATUS_FILE, "w") as f:
        json.dump(temp_status, f, indent=2)
# Helper fucntion again ends here


# Registration route for registering as a user/guest 
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handles user registration functionality.
    GET: Simply renders the registration form.
    POST: Validates input data, hashes password securely,
          saves new user info, sets approval status, and logs events.
    """
    error = None    # Stores error messages to display to the user
    success = None  # Stores success messages to display to the user

    if request.method == "POST":
        # Sanitize and retrieve form data 
        # Sanitizing input prevents XSS attacks and strips unwanted spaces
        username = sanitize_input(request.form.get("username", ""))
        email = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")       # Password is raw, not yet hashed
        confirm = request.form.get("confirm", "")         # Password confirmation field
        role = request.form.get("role", "guest")          # Default role: guest; other roles may need approval

        users = load_users()  # Load current users from JSON file

        # Validation 
        if not validate_username(username):
            # Username must be 3-20 chars, letters, numbers, underscores
            # Prevents injection of weird characters or too short/long names
            error = "Invalid username! 3-20 chars, alphanumeric + underscore."

        elif not validate_email(email):
            # Ensures user enters a valid email
            # Prevents bad data in system and enables communication (OTP, notifications)
            error = "Invalid email format."

        elif password != confirm:
            # Check if password matches confirmation to avoid typos
            error = "Passwords do not match."

        elif not validate_password_strength(password):
            # Enforce strong passwords to reduce risk of brute force attacks
            error = ("Password too weak! Must be 12+ chars, "
                     "include uppercase, lowercase, number, and special char.")

        elif any(u["username"] == username or u["email"] == email for u in users.values()):
            # Prevent duplicate accounts to maintain unique identity for each user
            error = "Username or email already exists."

        if error:
            # Log failed registration attempt for security auditing
            security_log.log_event(
                'REGISTRATION_FAILED',
                user_id=None,  # No user ID yet
                details={'username': username, 'email': email, 'reason': error},
                severity='WARNING'  # Warning severity indicates suspicious or invalid behavior
            )
        else:
            # Hash password securely 
            # bcrypt automatically generates salt and is computationally expensive, deterring brute-force
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

            # Determine approval status 
            # Guests are automatically approved; other roles (like "user") need admin approval
            approved = True if role == "guest" else False

            # Generate unique user ID and save user 
            import uuid
            user_id = str(uuid.uuid4())  # UUID ensures unique identifier even across systems
            users[user_id] = {
                "username": username,
                "email": email,
                "password_hash": hashed,
                "created_at": time.time(),  # Store epoch time for record keeping
                "role": role,
                "approved": approved,
                "failed_attempts": 0,       # Start with zero failed login attempts
                "locked_until": None        # No lock initially
            }

            save_users(users)  # Persist data to file

            # Log successful registration
            security_log.log_event(
                'REGISTRATION_SUCCESS',
                user_id=user_id,
                details={'username': username, 'email': email},
                severity='INFO'
            )

            # Provide feedback message depending on role
            if role == "user":
                success = "Registration successful! Waiting for admin approval."
            else:
                success = "Registration successful! You can now log in."

    # Render registration template with any feedback
    return render_template("register.html", error=error, success=success)


# Login route 
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user login functionality.
    GET: Display login form.
    POST: Authenticate user, enforce rate limiting, account lockout, and session management.
    """
    error = None  # Store error messages to display to user

    if request.method == "POST":
        ip = request.remote_addr  # Client IP used for rate-limiting and security logging
        now = time.time()         # Current time in epoch seconds

        # Sanitize input 
        # Prevent injection attacks; username can be email or actual username
        username_input = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        # Fetch user from database
        user_id, user = get_user_by_username(username_input)

        # Account lock check 
        if user and user.get("locked_until") and now < user["locked_until"]:
            # Account is temporarily locked due to repeated failed login attempts
            error = "Account is locked. Try again later."

            # Log failed login due to account lock
            security_log.log_event(
                'LOGIN_FAILED',
                user_id=user_id,
                details={'reason': 'Account locked', 'username': username_input},
                severity='WARNING'
            )

            # Stop processing and render login template
            return render_template("login.html", error=error)

        # Rate limiting by IP 
        # Keep only recent login attempts within WINDOW_SECONDS
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < WINDOW_SECONDS]

        if len(login_attempts[ip]) >= MAX_ATTEMPTS_PER_MINUTE:
            # Too many attempts from same IP, prevent brute-force attacks
            security_log.log_event(
                'RATE_LIMIT_EXCEEDED',
                user_id=None,
                details={'ip_address': ip},
                severity='WARNING'
            )
            return "Too many login attempts. Try again in 1 minute.", 429

        # Record current attempt
        login_attempts[ip].append(now)

        # Check credentials 
        if not user:
            # No matching user found
            error = "Invalid username or password."
            security_log.log_event(
                'LOGIN_FAILED',
                user_id=None,
                details={'username': username_input, 'reason': 'Username not found'},
                severity='WARNING'
            )

        elif bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            # Correct password

            # Check for admin approval 
            if user.get("role") == "user" and not user.get("approved", False):
                return render_template(
                    "login.html",
                    error="Your account is waiting for admin approval."
                )

            # Reset failed attempts after successful login 
            user["failed_attempts"] = 0
            user["locked_until"] = None
            users = load_users()
            users[user_id] = user
            save_users(users)

            # Log successful login
            security_log.log_event(
                'LOGIN_SUCCESS',
                user_id=user_id,
                details={'username': username_input}
            )

            # Create session and set secure cookie 
            token = session_manager.create_session(user_id=user_id)
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(
                "session_token",
                token,
                httponly=True,   # Protect cookie from JS access (XSS protection)
                secure=True,     # Only send over HTTPS
                samesite="Strict",  # Prevent CSRF
                max_age=session_manager.timeout
            )
            return resp

        else:
            # Incorrect password handling 
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1

            if user["failed_attempts"] >= config.MAX_FAILED_ATTEMPTS:
                # Lock account to prevent brute-force
                user["locked_until"] = time.time() + config.ACCOUNT_LOCK_TIME
                error = "Too many failed attempts. Account locked 15 minutes."

                security_log.log_event(
                    'ACCOUNT_LOCKED',
                    user_id=user_id,
                    details={'username': username_input},
                    severity='ERROR'
                )
            else:
                # General invalid credentials message
                error = "Invalid username or password."

            # Save updated user data
            users = load_users()
            users[user_id] = user
            save_users(users)

            # Log failed login attempt
            security_log.log_event(
                'LOGIN_FAILED',
                user_id=user_id,
                details={'username': username_input, 'failed_attempts': user["failed_attempts"]},
                severity='WARNING'
            )

    # Render login template with error messages
    return render_template("login.html", error=error)


# Approve a user (admin only) 
@app.route("/approve_user/<user_id>", methods=["POST"])
@require_role("admin")  # Only admins can approve users
def approve_user(user_id):
    """
    Marks a user as approved so they can log in.
    Also resets the 'denied' flag if it was set before.
    """
    users = load_users()  # Load all users from storage

    if user_id in users:
        users[user_id]["approved"] = True   # Allow this user to log in
        users[user_id]["denied"] = False    # Make sure denial is removed
        save_users(users)                   # Save changes back to storage
        return jsonify({"success": True})   # Tell client it worked

    return jsonify({"success": False}), 400  # Return error if user not found


# Deny a user (admin only) 
@app.route("/deny_user/<user_id>", methods=["POST"])
@require_role("admin")  # Only admins can deny users
def deny_user(user_id):
    """
    Marks a user as denied so they cannot log in.
    Updates both 'approved' and 'denied' flags and saves changes.
    """
    users = load_users()

    if user_id in users:
        users[user_id]["approved"] = False  # Prevent login
        users[user_id]["denied"] = True     # Mark as denied
        save_users(users)                   # Save changes
        return jsonify({"success": True})

    return jsonify({"success": False}), 400  # User not found


# Dashboard route 
@app.route("/dashboard")
@require_role("admin", "user", "guest")  # All roles can access dashboard
def dashboard():
    """
    Shows the dashboard page:
    - User's own files
    - Files shared with user
    - Pending user approvals (for admins)
    - File version information
    """
    if not g.user_id:
        # User not logged in, redirect to login page
        return redirect(url_for("login"))

    users = load_users()  # Load all users
    user_id = g.user_id
    user = users.get(user_id)

    if not user:
        # If user does not exist, force login again
        return redirect(url_for("login"))

    g.user_id = user_id
    versions = load_versions()  # Load file version data
    shares = load_shares()      # Load shared files data
    role = current_user_role()  # Get current user's role

    my_files = []               # Files uploaded by this user
    shared_files = []           # Files shared with this user

    # FILES LOGIC
    if role == "admin":
        # Admins see their files separately from other users' files
        files_uploaded_by_admin = []
        files_uploaded_by_users = []

        for filename, file_versions in versions.items():
            uploader_id = file_versions[0]["uploaded_by"]  # First uploader of file
            uploader = users.get(uploader_id, {})
            uploader_role = uploader.get("role")

            if uploader_role == "admin":
                files_uploaded_by_admin.append(filename)  # Admin's files
            else:
                files_uploaded_by_users.append(filename)  # Users' files

        my_files = files_uploaded_by_admin
        shared_files = files_uploaded_by_users
    else:
        # For normal users or guests
        for filename, file_versions in versions.items():
            # Add files uploaded by this user
            if any(v["uploaded_by"] == g.user_id for v in file_versions):
                my_files.append(filename)
            # Add files shared with this user
            elif g.user_id in shares.get(filename, {}).get("shared_with", {}):
                shared_files.append(filename)


    # TEMP STATUS (for pending approvals)
    temp_status_dict = load_temp_status()  # Tracks temporary approve/deny actions


    # PENDING USERS (admin view)
    pending_users = []

    for uid, u in users.items():
        if u.get("role") == "user":
            # Show temp status if admin just clicked approve/deny
            if uid in temp_status_dict:
                pending_users.append({
                    "id": uid,
                    "username": u["username"],
                    "email": u["email"],
                    "status": temp_status_dict[uid]  # approved/denied
                })
            # Otherwise show only real pending users
            elif u.get("approved") == False and not u.get("denied", False):
                pending_users.append({
                    "id": uid,
                    "username": u["username"],
                    "email": u["email"],
                    "status": "pending"
                })

    
    # RENDER DASHBOARD PAGE
    return render_template(
        "dashboard.html",
        username=user["username"],
        my_files=my_files,
        shared_files=shared_files,
        shares=shares,
        versions=versions,
        pending_users=pending_users,
        current_user_role=current_user_role,
        get_user_by_id=get_user_by_id,
        g=g
    )


# File upload route 
@app.route("/upload", methods=["GET", "POST"])
@require_role("admin", "user")  # Guests cannot upload files
def upload():
    """
    Allows users to upload files:
    - Checks file type
    - Encrypts files
    - Keeps track of versions
    - Logs upload activity
    """
    if not g.user_id:
        return redirect(url_for("login"))  # Must be logged in

    role = current_user_role()
    if role == "guest":
        # Guests are not allowed to upload
        return "Access denied: upload not allowed for your role.", 403

    error = None
    success = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "No file part in request."  # File field missing
        else:
            file = request.files["file"]
            if file.filename == "":
                error = "No file selected."  # No file chosen
            elif not allowed_file(file.filename):
                error = "File type not allowed."  # Extension check
            elif not file.mimetype.startswith(('image/','application/pdf','text/')):
                error = "Invalid file content type."  # Check MIME type
            else:
                filename = secure_filename(file.filename)  # Prevent dangerous filenames

                # Versioning logic 
                versions = load_versions()
                file_versions = versions.get(filename, [])
                version_number = len(file_versions) + 1
                versioned_filename = f"{filename}_v{version_number}.enc"  # Save encrypted version

                #  Encrypt and save file 
                file_bytes = file.read()
                encrypted_bytes = encrypt_file(file_bytes)  # Encrypt content
                filepath = os.path.join(UPLOAD_DIR, versioned_filename)
                with open(filepath, "wb") as f:
                    f.write(encrypted_bytes)

                # Update versions.json 
                file_versions.append({
                    "version": version_number,
                    "uploaded_by": g.user_id,
                    "timestamp": time.time()
                })
                versions[filename] = file_versions
                save_versions(versions)

                # Update shares.json (set owner if first upload) 
                shares = load_shares()
                if filename not in shares:
                    shares[filename] = {
                        "owner": g.user_id,
                        "shared_with": {}
                    }
                save_shares(shares)

                # Log the upload in audit 
                log_audit(g.user_id, "upload", filename)

                success = f"File '{filename}' uploaded successfully! (version {version_number})"

    # Render upload page with feedback messages
    return render_template(
        "upload.html",
        error=error,
        success=success,
        current_user_role=current_user_role
    )


# Route to list uploaded files 
@app.route("/files")  # Define route /files to handle GET requests
@require_role("admin", "user")  # Only users with role admin or user can access
def files():
    if not g.user_id:  # Check if user is not logged in
        return redirect(url_for("login"))  # If not logged in, redirect to login page

    role = current_user_role()  # Get the role of the current logged-in user
    versions = load_versions()  # Load all file versions from versions.json

    if role == "admin":  # If user is an admin
        # Admin can see all files, so pass all filenames to template
        return render_template("files.html", files=list(versions.keys()))

    # For regular users, create a list to hold their files
    user_files = []  
    for filename, file_versions in versions.items():  # Loop through all files
        for v in file_versions:  # Loop through all versions of this file
            if v["uploaded_by"] == g.user_id:  # Check if current user uploaded this version
                user_files.append(filename)  # Add file to user_files list
                break  # Stop checking other versions once file is confirmed owned by user

    # Render files.html and pass only the files uploaded by this user
    return render_template("files.html", files=user_files)


# Route to share a file with other users 
@app.route("/share/<filename>", methods=["GET", "POST"])  # Route /share/<filename> for GET/POST
@require_role("admin", "user")  # Only admin or user can access
def share_file(filename):
    if not g.user_id:  # If user not logged in
        return redirect(url_for("login"))  # Redirect to login

    safe_name = secure_filename(filename)  # Remove unsafe characters from filename
    versions = load_versions()  # Load all file versions
    if safe_name not in versions:  # Check if file exists
        return "File not found.", 404  # Return 404 if file does not exist

    shares = load_shares()  # Load sharing information from shares.json
    # Get share info for this file, default owner = current user, empty shared_with dict
    file_share_info = shares.get(safe_name, {"owner": g.user_id, "shared_with": {}})

    role = current_user_role()  # Get role of current user
    # Only owner or admin can share the file
    if role != "admin" and g.user_id != file_share_info.get("owner"):
        return "Access denied: only owner or admin can share this file.", 403

    users = load_users()  # Load all users from users.json
    # Create list of all users except current one, with their id, username, role
    all_users = [
        {"id": uid, "username": u["username"], "role": u["role"]}
        for uid, u in users.items() if uid != g.user_id
    ]

    error = None  # Initialize error message as None
    success = None  # Initialize success message as None

    if request.method == "POST":  # Check if request is a form submission
        # Check if the request data is JSON (AJAX request)
        if request.is_json:
            data = request.get_json()  # Parse JSON data
        else:
            data = request.form.to_dict()  # Parse form data into dictionary

        # Handle revoke access using AJAX
        if "revoke_user_id" in data:  # If AJAX request contains revoke_user_id
            revoke_user_id = data["revoke_user_id"]  # Get user id to revoke
            if revoke_user_id in file_share_info.get("shared_with", {}):  # Check if user has access
                file_share_info["shared_with"].pop(revoke_user_id)  # Remove user from shared list
                shares[safe_name] = file_share_info  # Update shares dictionary
                save_shares(shares)  # Save updated shares.json
                return jsonify(success=True, username=users[revoke_user_id]["username"])  # Return success JSON
            else:
                return jsonify(success=False, error="User does not have access.")  # Return error if user not in shared list

        # Handle normal share via form
        target_user_id = sanitize_input(data.get("user_id"))  # Sanitize input from form
        if not target_user_id or target_user_id not in users:  # Check if valid user id
            error = "Invalid user selected."  # Set error message
        elif target_user_id in file_share_info.get("shared_with", {}):  # Check if user already has access
            error = f"{users[target_user_id]['username']} already has access!"  # Set error
        else:
            # Add user to shared_with dictionary with current timestamp
            file_share_info.setdefault("shared_with", {})[target_user_id] = time.time()
            shares[safe_name] = file_share_info  # Update shares dict
            save_shares(shares)  # Save updated shares.json
            # Log sharing action for audit
            log_audit(g.user_id, f"share with {users[target_user_id]['username']}", safe_name)
            # Set success message for user
            success = f"File '{safe_name}' shared with {users[target_user_id]['username']}!"

    # Render share.html with all required info for template
    return render_template(
        "share.html",
        filename=safe_name,  # Current filename
        users=all_users,  # List of all other users for dropdown
        all_users=all_users,  # Same list for JS dropdown
        error=error,  # Error message if any
        success=success,  # Success message if any
        shares=shares,  # Current shares info
        versions=versions,  # Current versions info
        get_user_by_id=get_user_by_id,  # Helper function for template
        current_user_role=current_user_role  # Helper function for template
    )


# Download a file 
@app.route("/download/<filename>")  # Route for downloading files
def download(filename):
    if not g.user_id:  # Check if user logged in
        return redirect(url_for("login"))  # Redirect if not

    safe_name = secure_filename(filename)  # Clean filename to prevent directory traversal
    versions = load_versions()  # Load file versions
    file_versions = versions.get(safe_name)  # Get versions of this file

    if not file_versions:  # If file does not exist
        return "File not found.", 404

    role = current_user_role()  # Get current user role
    shares = load_shares()  # Load share info
    file_share_info = shares.get(safe_name)  # Get share info for this file

    if role != "admin":  # If user is not admin
        if not file_share_info:  # No sharing info exists
            return "Access denied.", 403
        elif g.user_id == file_share_info["owner"]:  # Owner allowed
            pass
        elif g.user_id in file_share_info["shared_with"]:  # Shared user allowed
            pass
        else:  # Other users denied
            return "Access denied.", 403

    # Get latest version number of file
    latest_version = len(file_versions)
    versioned_filename = config.FILE_VERSION_FORMAT.format(filename=safe_name, version=latest_version)
    enc_path = os.path.join(config.UPLOAD_DIR, versioned_filename)  # Full path to encrypted file

    if not os.path.exists(enc_path):  # If encrypted file missing
        return "File not found on server.", 404

    with open(enc_path, "rb") as f:  # Open encrypted file in binary mode
        encrypted_bytes = f.read()  # Read all bytes

    decrypted_bytes = decrypt_file(encrypted_bytes)  # Decrypt the file bytes

    log_audit(g.user_id, "download", safe_name)  # Log download action in audit

    return send_file(
        io.BytesIO(decrypted_bytes),  # Send decrypted bytes as a file
        as_attachment=True,  # Force download
        download_name=safe_name  # Set filename in download
    )


# List users for admin view only 
@app.route("/users")
@require_role("admin")  # Only admin can access
def list_users():
    if not g.user_id:  # Check login
        return redirect(url_for("login"))

    if current_user_role() != "admin":  # Check admin role
        return "Access denied", 403

    users = load_users()  # Load all users
    approved_users = []  # List for approved users
    guests = []  # List for guest users

    for uid, u in users.items():  # Loop through all users
        role = u.get("role")  # Get user's role
        if role == "user" and u.get("approved", False) and not u.get("denied", False):
            # Add approved regular users
            approved_users.append({
                "id": uid,
                "username": u["username"],
                "email": u["email"]
            })
        elif role == "guest":  # Add all guest users
            guests.append({
                "id": uid,
                "username": u["username"],
                "email": u["email"]
            })

    return render_template(
        "users.html",
        users=approved_users,
        guests=guests
    )


# Delete a user for admin access only 
@app.route("/delete_user/<user_id>", methods=["POST"])
@require_role("admin")
def delete_user(user_id):
    if not g.user_id or current_user_role() != "admin":  # Ensure admin access
        return jsonify(success=False, error="Access denied."), 403

    users = load_users()  # Load all users
    if user_id not in users:  # Check if user exists
        return jsonify(success=False, error="User not found."), 404

    username = users[user_id]["username"]  # Store username for response

    versions = load_versions()  # Load all file versions
    shares = load_shares()  # Load all shares
    filenames_to_delete = []  # List to track files to delete

    for filename, file_versions in versions.items():  # Loop all files
        if any(v["uploaded_by"] == user_id for v in file_versions):  # If user uploaded any version
            filenames_to_delete.append(filename)  # Add to delete list

    for filename in filenames_to_delete:  # Delete each file
        file_versions = versions.get(filename, [])  # Get all versions
        versions.pop(filename, None)  # Remove from versions.json
        shares.pop(filename, None)  # Remove share info
        for v in range(1, len(file_versions)+1):  # Delete actual encrypted files
            filepath = os.path.join(config.UPLOAD_DIR, config.FILE_VERSION_FORMAT.format(filename=filename, version=v))
            if os.path.exists(filepath):
                os.remove(filepath)

    save_versions(versions)  # Save updated versions.json
    save_shares(shares)      # Save updated shares.json

    users.pop(user_id)  # Remove user from users.json
    save_users(users)   # Save updated users.json

    return jsonify(success=True, username=username)  # Return success response


# Delete a file by owner or admin only 
@app.route("/delete_file/<filename>", methods=["POST"])
@require_role("admin", "user")  # Owner or admin can delete
def delete_file(filename):
    if not g.user_id:  # Check login
        return redirect(url_for("login"))

    safe_name = secure_filename(filename)  # Clean filename
    versions = load_versions()  # Load all file versions
    shares = load_shares()      # Load all share info

    if safe_name not in versions:  # Check file exists
        return jsonify(success=False, error="File not found."), 404

    role = current_user_role()  # Get role
    file_share_info = shares.get(safe_name)  # Get share info

    if role != "admin":  # If not admin
        if not file_share_info or g.user_id != file_share_info.get("owner"):  # Check owner
            return jsonify(success=False, error="Access denied: only owner or admin can delete this file."), 403

    file_versions = versions.pop(safe_name, [])  # Remove file versions
    shares.pop(safe_name, None)  # Remove share info

    for v in range(1, len(file_versions)+1):  # Delete actual encrypted files
        filepath = os.path.join(UPLOAD_DIR, f"{safe_name}_v{v}.enc")
        if os.path.exists(filepath):
            os.remove(filepath)

    save_versions(versions)  # Save updated versions.json
    save_shares(shares)      # Save updated shares.json

    log_audit(g.user_id, "delete", safe_name)  # Log deletion action

    return jsonify(success=True, filename=safe_name)  # Return success response


# Delete a specific version of a file 
@app.route("/delete_version/<filename>/<int:version>", methods=["POST"])
# Defines a route to delete a specific version of a file.

@require_role("admin", "user")
# Only users with role "admin" or "user" can access this route.

def delete_version(filename, version):
    # Function to handle deleting a specific file version.
    
    if not g.user_id:
        # If user is not logged in
        return jsonify(success=False, error="Not logged in"), 403
        # Return JSON error with HTTP 403 Forbidden

    safe_name = secure_filename(filename)
    # Sanitize the filename to prevent unsafe characters or directory traversal

    versions = load_versions()
    # Load all file versions from storage (versions.json)

    shares = load_shares()
    # Load file sharing info (shares.json)

    file_versions = versions.get(safe_name)
    # Get the list of versions for this file

    if not file_versions:
        # If the file does not exist
        return jsonify(success=False, error="File not found"), 404
        # Return 404 error

    #  Permission check 
    role = current_user_role()
    # Get the current user's role

    owner_id = shares.get(safe_name, {}).get("owner")
    # Get the owner of the file (if exists)

    if role != "admin" and g.user_id != owner_id:
        # If the user is not admin and not the owner
        return jsonify(success=False, error="Access denied"), 403
        # Deny access

    # Find the version object 
    version_obj = next((v for v in file_versions if v["version"] == version), None)
    # Look for the version object that matches the requested version
    # Returns None if not found

    if not version_obj:
        # If the requested version does not exist
        return jsonify(success=False, error="Version not found"), 404
        # Return 404 error

    # Delete encrypted file from disk 
    file_path = os.path.join(
        config.UPLOAD_DIR,
        config.FILE_VERSION_FORMAT.format(filename=safe_name, version=version)
    )
    # Build the path to the encrypted file using config

    if os.path.exists(file_path):
        # Check if the file exists on disk
        os.remove(file_path)
        # Delete the file

    # Remove version from versions.json 
    versions[safe_name] = [v for v in file_versions if v["version"] != version]
    # Keep all other versions, remove this one

    # If no versions left, remove the file entry entirely
    if not versions[safe_name]:
        versions.pop(safe_name)
        shares.pop(safe_name, None)
        # Remove file completely from versions and shares

    save_versions(versions)
    # Save updated versions.json

    save_shares(shares)
    # Save updated shares.json

    # Log the deletion for audit
    log_audit(g.user_id, f"delete version {version}", safe_name)
    # Track who deleted what for auditing

    return jsonify(success=True, filename=safe_name, version=version)
    # Return success response including filename and version


# Logout route 
@app.route("/logout", methods=["POST"])
# Route to log out the current user

@require_role("admin", "user", "guest")
# Any logged-in role can access logout

def logout():
    token = request.cookies.get("session_token")
    # Get session token from cookies

    if token:
        # If session exists
        session_manager.destroy_session(token)
        # Destroy session on server

    session_manager.cleanup_sessions()
    # Remove expired sessions

    resp = make_response(redirect(url_for("login")))
    # Prepare response to redirect to login page

    resp.set_cookie("session_token", "", expires=0, httponly=True, samesite="Strict")
    # Clear session cookie from client

    g.user_id = None
    # Clear global user ID

    g.session_token = None
    # Clear global session token

    return resp
    # Send the response back to the client


# Reset Password Route 
@app.route("/reset_password", methods=["GET", "POST"])
# Route to start the password reset process

def reset_password():
    if request.method == "POST":
        # Handle form submission

        username = sanitize_input(request.form.get("username"))
        # Get username from form and sanitize

        email = sanitize_input(request.form.get("email"))
        # Get email from form and sanitize

        if not validate_email(email):
            # Validate email format
            flash("Enter a valid email address.", "error")
            # Show error message
            return redirect(url_for("reset_password"))
            # Redirect back to reset password page

        users = load_users()
        # Load all users

        user_id = None
        # Initialize variable to store matching user ID

        for uid, u in users.items():
            # Loop through users
            if u["username"] == username and u["email"] == email:
                # Match both username and email
                user_id = uid
                break
                # Stop loop after match

        if not user_id:
            # If no matching user
            flash("Invalid username/email combination.", "error")
            return redirect(url_for("reset_password"))

        otp = str(random.randint(100000, 999999))
        # Generate 6-digit OTP

        OTP_STORE[user_id] = (otp, time.time())
        # Store OTP with timestamp

        if send_email(email, config.OTP_EMAIL_SUBJECT, f"Your OTP is: {otp}\nValid for 10 minutes."):
            # Send OTP email
            flash("OTP sent to your email.", "success")
            return redirect(url_for("verify_otp", user_id=user_id))
        else:
            flash("Failed to send OTP. Try again later.", "error")
            return redirect(url_for("reset_password"))

    return render_template("reset_password.html")
    # Render reset password form for GET request


# Verify OTP Route 
@app.route("/verify_otp/<user_id>", methods=["GET", "POST"])
# Route to verify OTP sent to user's email

def verify_otp(user_id):
    if request.method == "POST":
        # Handle OTP submission

        entered_otp = request.form.get("otp")
        # Get OTP entered by user

        otp_data = OTP_STORE.get(user_id)
        # Get stored OTP and timestamp

        if not otp_data:
            # If OTP not found or expired
            flash("OTP expired or invalid. Please request a new one.", "error")
            return redirect(url_for("reset_password"))

        otp, timestamp = otp_data
        # Extract OTP and creation time

        if time.time() - timestamp > config.OTP_EXPIRY_SECONDS:
            # Check if OTP expired (10 minutes)
            OTP_STORE.pop(user_id, None)
            flash("OTP expired. Please request a new one.", "error")
            return redirect(url_for("reset_password"))

        if entered_otp != otp:
            # If OTP does not match
            flash("Incorrect OTP. Try again.", "error")
            return redirect(url_for("verify_otp", user_id=user_id))

        flash("OTP verified. You can now set a new password.", "success")
        return redirect(url_for("set_new_password", user_id=user_id))
        # Redirect to set new password page

    return render_template("verify_otp.html", user_id=user_id)
    # Render OTP verification form on GET


# Set New Password Route 
@app.route("/set_new_password/<user_id>", methods=["GET", "POST"])
# Route to set a new password after OTP verification

def set_new_password(user_id):
    users = load_users()
    # Load all users

    user_data = users.get(user_id)
    # Get data for the specific user

    if not user_data:
        flash("User not found. Please try again.", "error")
        return redirect(url_for("reset_password"))

    if request.method == "POST":
        # Handle form submission

        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        # Get both password fields

        if not password1 or not password2:
            flash("Please fill in both password fields.", "error")
            return redirect(url_for("set_new_password", user_id=user_id))

        if password1 != password2:
            flash("Passwords do not match. Try again.", "error")
            return redirect(url_for("set_new_password", user_id=user_id))

        if not validate_password_strength(password1):
            flash("Password too weak. Must be 12+ chars with upper, lower, number, special.", "error")
            return redirect(url_for("set_new_password", user_id=user_id))

        hashed_pw = bcrypt.hashpw(password1.encode(), bcrypt.gensalt()).decode()
        # Hash password using bcrypt

        user_data["password_hash"] = hashed_pw
        users[user_id] = user_data
        save_users(users)
        # Save updated password

        OTP_STORE.pop(user_id, None)
        # Remove OTP from store

        flash("Password updated successfully! You can now log in.", "success")
        return redirect(url_for("login"))
        # Redirect to login page

    return render_template("set_new_password.html", user_id=user_id)
    # Render set new password form for GET


# Home redirects 
@app.route("/")
# Home route

def home():
    return redirect(url_for("dashboard") if g.user_id else url_for("login"))
    # If logged in, go to dashboard, otherwise go to login


# --- Run server ---
if __name__ == "__main__":
    app.run(debug=False, ssl_context=(config.SSL_CERT, config.SSL_KEY))
    # Run Flask server with debug mode and SSL certificates