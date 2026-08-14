"""
db.py - Database setup and helper functions for Online Banking Application.

VULNERABILITY: SQL Injection (CWE-89)
    - Several functions build SQL queries using Python string formatting (f-strings)
      instead of parameterised queries.  This allows an attacker to inject
      arbitrary SQL through user-controlled input.
"""

import sqlite3
import os
import logging

# ---------------------------------------------------------------------------
# Logging setup  (writes to outputs/app.log)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("online_banking.db")

DB_PATH = os.path.join(BASE_DIR, "outputs", "banking.db")


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------
def get_connection():
    """Return a new SQLite connection (with row_factory for dict-like access)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema creation & seed data
# ---------------------------------------------------------------------------
def init_db():
    """Create tables and seed sample data if the database does not exist."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,          -- stored in PLAINTEXT (intentional)
            full_name   TEXT    NOT NULL,
            balance     REAL    DEFAULT 10000.00
        );

        CREATE TABLE IF NOT EXISTS beneficiaries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id    INTEGER NOT NULL,
            name        TEXT    NOT NULL,
            account_no  TEXT    NOT NULL,
            bank_name   TEXT    NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user   INTEGER NOT NULL,
            to_user     INTEGER,
            amount      REAL    NOT NULL,
            txn_type    TEXT    NOT NULL,          -- TRANSFER / DEPOSIT / WITHDRAWAL
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            FOREIGN KEY (from_user) REFERENCES users(id),
            FOREIGN KEY (to_user)   REFERENCES users(id)
        );
    """)

    # Seed two sample users if the table is empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        seed_users = [
            ("alice", "password123", "Alice Johnson", 15000.00),
            ("bob",   "bob@2024",    "Bob Williams",  8000.00),
            ("admin", "admin",       "Administrator", 50000.00),
        ]
        cur.executemany(
            "INSERT INTO users (username, password, full_name, balance) VALUES (?, ?, ?, ?)",
            seed_users,
        )

        # Seed a beneficiary for alice
        cur.execute(
            "INSERT INTO beneficiaries (owner_id, name, account_no, bank_name) VALUES (1, 'Bob Williams', 'ACC-002', 'National Bank')"
        )

        # Seed a transaction
        cur.execute(
            "INSERT INTO transactions (from_user, to_user, amount, txn_type, description) "
            "VALUES (1, 2, 500.00, 'TRANSFER', 'Seed transfer from Alice to Bob')"
        )

        logger.info("Database seeded with sample users: alice/password123, bob/bob@2024, admin/admin")

    conn.commit()
    conn.close()
    logger.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# VULNERABLE query helpers  (SQL Injection — CWE-89)
# ---------------------------------------------------------------------------

def vulnerable_login(username: str, password: str):
    """
    VULNERABLE: Uses f-string to build the SQL query.
    An attacker can bypass authentication with input like:
        username: ' OR '1'='1' --
        password: anything
    """
    conn = get_connection()
    cur = conn.cursor()
    # ⚠️ VULNERABLE — raw string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    logger.debug("Executing login query: %s", query)      # logs the raw SQL (Vuln 3)
    cur.execute(query)
    user = cur.fetchone()
    conn.close()
    return user


def vulnerable_search_user(search_term: str):
    """
    VULNERABLE: Uses f-string for a LIKE search.
    Allows injection through the search_term parameter.
    """
    conn = get_connection()
    cur = conn.cursor()
    # ⚠️ VULNERABLE — raw string interpolation
    query = f"SELECT id, username, full_name FROM users WHERE username LIKE '%{search_term}%'"
    logger.debug("Executing search query: %s", query)
    cur.execute(query)
    results = cur.fetchall()
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Safe query helpers  (used where injection isn't the intended vuln)
# ---------------------------------------------------------------------------

def get_user_by_id(user_id: int):
    """Fetch a user row by primary key (safe — parameterised)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def update_balance(user_id: int, new_balance: float):
    """Update a user's balance (safe — parameterised)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user_id))
    conn.commit()
    conn.close()


def insert_transaction(from_user: int, to_user, amount: float, txn_type: str, description: str = ""):
    """Record a transaction row."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO transactions (from_user, to_user, amount, txn_type, description) VALUES (?, ?, ?, ?, ?)",
        (from_user, to_user, amount, txn_type, description),
    )
    conn.commit()
    conn.close()


def get_transactions(user_id: int):
    """Fetch all transactions involving a user."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY timestamp DESC",
        (user_id, user_id),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def register_user(username: str, password: str, full_name: str, initial_balance: float = 10000.0):
    """Insert a new user. Returns the new user id or None on failure."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password, full_name, balance) VALUES (?, ?, ?, ?)",
            (username, password, full_name, initial_balance),
        )
        conn.commit()
        uid = cur.lastrowid
        conn.close()
        return uid
    except sqlite3.IntegrityError:
        conn.close()
        return None
