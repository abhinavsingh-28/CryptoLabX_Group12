"""
session.py - Session management for Online Banking Application.

Provides a simple in-memory session store.
Session tokens are predictable sequential integers (intentionally weak).
"""

import logging

logger = logging.getLogger("online_banking.session")

# ---------------------------------------------------------------------------
# In-memory session store
# ---------------------------------------------------------------------------
_sessions = {}          # token -> user dict
_next_token = 1000      # predictable, sequential token


def create_session(user_row) -> str:
    """
    Create a session for the given user row and return a token string.

    VULNERABILITY NOTE (Sensitive Data Exposure — CWE-532):
        The session token AND password are logged in plaintext.
    """
    global _next_token
    token = str(_next_token)
    _next_token += 1

    user_data = {
        "id": user_row["id"],
        "username": user_row["username"],
        "full_name": user_row["full_name"],
        "balance": user_row["balance"],
        "password": user_row["password"],   # stored in session (intentional)
    }
    _sessions[token] = user_data

    # ⚠️ VULNERABLE — logging sensitive data in plaintext (CWE-532)
    logger.info(
        "Session created — token=%s, user=%s, password=%s, balance=%.2f",
        token,
        user_data["username"],
        user_data["password"],
        user_data["balance"],
    )
    return token


def get_session(token: str):
    """Return the user data dict for a token, or None if invalid."""
    return _sessions.get(token)


def destroy_session(token: str):
    """Remove a session."""
    if token in _sessions:
        logger.info("Session destroyed — token=%s, user=%s", token, _sessions[token]["username"])
        del _sessions[token]
        return True
    return False


def list_sessions():
    """Return all active sessions (for debugging / demonstration)."""
    return dict(_sessions)
