# utils/auth.py
import secrets
import time
import json
import os
import tempfile
from flask import request

SESSIONS_FILE = "data/sessions.json" # Path to store session data persistently in JSON file

os.makedirs("data", exist_ok=True) # Ensure the 'data' directory exists; create if missing

class SessionManager:
    def __init__(self, timeout=1800):  # 30 minutes default
        self.timeout = timeout # Default session timeout in seconds (30 minutes)
        self.sessions_file = SESSIONS_FILE # File to persist session data
        # Ensure sessions.json exists
        if not os.path.exists(self.sessions_file):
            with open(self.sessions_file, "w") as f:
                json.dump({}, f) # Ensure the sessions file exists; if missing, create an empty JSON object

    def load_sessions(self):
        """Load all sessions from sessions.json safely"""
        # Safely load session data; if file is missing or corrupted, return empty dict
        try:
            with open(self.sessions_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_sessions(self, sessions):
        """Atomically save all sessions to sessions.json to avoid corruption"""
        dirpath = os.path.dirname(self.sessions_file) # Directory where sessions.json resides
        # Write to a temp file first to ensure atomic save
        # Flush and fsync guarantee data is physically written to disk
        with tempfile.NamedTemporaryFile("w", delete=False, dir=dirpath) as tmp_file:
            json.dump(sessions, tmp_file, indent=2)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            temp_path = tmp_file.name
        os.replace(temp_path, self.sessions_file)

    def create_session(self, user_id):
        """Create a new session for a user"""
        token = secrets.token_urlsafe(32) # Generate a secure random session token
        # Build session dictionary with all relevant info
        # Tracks IP and User-Agent for extra security
        session = {
            "token": token,
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip_address": request.remote_addr if request else None,
            "user_agent": request.headers.get("User-Agent") if request else None
        }
        sessions = self.load_sessions()
        sessions[token] = session
        self.save_sessions(sessions) # Save the new session to sessions.json
        return token # Return the session token to the caller (usually set in cookie)

    def validate_session(self, token):
        """Validate an existing session and update last_activity"""
        sessions = self.load_sessions()
        if token not in sessions:
            return None # Session does not exist
        session = sessions[token]

        # Expired session
        if time.time() - session["last_activity"] > self.timeout:
            self.destroy_session(token) # Session expired; remove immediately
            return None

        # Update last_activity (only if >5 seconds to reduce frequent writes)
        if time.time() - session["last_activity"] > 5:
            session["last_activity"] = time.time()
            sessions[token] = session
            self.save_sessions(sessions)
        return session# Return session info if valid

# Remove the session and persist changes
    def destroy_session(self, token):
        """Delete a session immediately"""
        sessions = self.load_sessions()
        if token in sessions:
            del sessions[token]
            self.save_sessions(sessions)

    def cleanup_sessions(self):
        """Remove all expired sessions automatically"""
        sessions = self.load_sessions()
        now = time.time()
        removed = False # Track whether any sessions were removed

        for token in list(sessions.keys()):
            last_activity = sessions[token].get("last_activity", 0)
            if now - last_activity > self.timeout:
                sessions.pop(token)
                removed = True # Iterate over sessions and remove expired ones

        if removed:
            self.save_sessions(sessions) # Save only if any sessions were removed