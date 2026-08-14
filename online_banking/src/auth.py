"""
auth.py - Authentication module for Online Banking Application.

VULNERABILITIES:
    1. SQL Injection (CWE-89) — login delegates to db.vulnerable_login()
       which uses f-string SQL.
    2. Sensitive Data Exposure in Logs (CWE-532) — passwords and tokens
       are logged in plaintext.
"""

import logging
from src.db import vulnerable_login, register_user
from src.session import create_session

logger = logging.getLogger("online_banking.auth")


def login(username: str, password: str):
    """
    Authenticate a user and return (token, user_data) on success,
    or (None, None) on failure.

    VULNERABLE:
        - SQL Injection via vulnerable_login()
        - Password logged in plaintext
    """
    # ⚠️ VULNERABLE — password logged in cleartext (CWE-532)
    logger.info("Login attempt — username=%s, password=%s", username, password)

    user = vulnerable_login(username, password)

    if user:
        token = create_session(user)
        logger.info("Login successful — user=%s, token=%s", username, token)
        return token, dict(user)
    else:
        logger.warning("Login failed — username=%s, password=%s", username, password)
        return None, None


def register(username: str, password: str, full_name: str):
    """
    Register a new user. Returns the new user id or None if username taken.

    VULNERABLE:
        - Password logged in plaintext (CWE-532)
    """
    # ⚠️ VULNERABLE — password logged in cleartext
    logger.info("Registration attempt — username=%s, password=%s, name=%s", username, password, full_name)

    uid = register_user(username, password, full_name)

    if uid:
        logger.info("Registration successful — user_id=%d, username=%s, password=%s", uid, username, password)
    else:
        logger.warning("Registration failed (duplicate username) — username=%s", username)

    return uid
