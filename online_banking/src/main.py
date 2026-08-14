"""
main.py - Console entry point for the Online Banking Application.

Run with:
    cd online_banking
    python3 -m src.main
"""

import sys
import os

# Ensure the online_banking/ directory is on the path so `src.*` imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db import init_db, vulnerable_search_user
from src.auth import login, register
from src.session import get_session, destroy_session
from src.banking import check_balance, transfer_funds, transaction_history
from src.beneficiary import add_beneficiary, list_beneficiaries, delete_beneficiary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def print_header(text: str):
    width = 50
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


def print_menu(options: list):
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    print()


# ---------------------------------------------------------------------------
# Pre-login menu
# ---------------------------------------------------------------------------
def pre_login_menu():
    while True:
        print_header("ONLINE BANKING SYSTEM")
        print_menu(["Login", "Register", "Exit"])
        choice = input("Select option: ").strip()

        if choice == "1":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            token, user = login(username, password)
            if token:
                print(f"\n✓ Welcome, {user['full_name']}!")
                main_menu(token)
            else:
                print("\n✗ Invalid credentials. Please try again.")

        elif choice == "2":
            print_header("REGISTRATION")
            username = input("Choose a username: ").strip()
            password = input("Choose a password: ").strip()
            full_name = input("Full name: ").strip()
            uid = register(username, password, full_name)
            if uid:
                print(f"\n✓ Registration successful! Your user ID is {uid}.")
                print("  You can now login with your credentials.")
            else:
                print("\n✗ Username already taken. Try a different one.")

        elif choice == "3":
            print("\nGoodbye!")
            sys.exit(0)

        else:
            print("\n✗ Invalid option.")


# ---------------------------------------------------------------------------
# Post-login menu
# ---------------------------------------------------------------------------
def main_menu(token: str):
    while True:
        session = get_session(token)
        if not session:
            print("\n✗ Session expired. Please login again.")
            return

        print_header(f"MAIN MENU — {session['full_name']}")
        print(f"  Logged in as: {session['username']} (ID: {session['id']})")
        print()
        print_menu([
            "Check Balance",
            "Transfer Funds",
            "Transaction History",
            "Manage Beneficiaries",
            "Search Users",
            "Logout",
        ])
        choice = input("Select option: ").strip()

        if choice == "1":
            handle_check_balance(session)
        elif choice == "2":
            handle_transfer(session)
        elif choice == "3":
            handle_history(session)
        elif choice == "4":
            handle_beneficiaries(session, token)
        elif choice == "5":
            handle_search()
        elif choice == "6":
            destroy_session(token)
            print("\n✓ Logged out successfully.")
            return
        else:
            print("\n✗ Invalid option.")


# ---------------------------------------------------------------------------
# Feature handlers
# ---------------------------------------------------------------------------

def handle_check_balance(session):
    """
    VULNERABILITY DEMO — Broken Access Control (CWE-284):
    The user is asked for a user ID.  They can enter ANY user's ID
    to see that user's balance, not just their own.
    """
    print_header("CHECK BALANCE")
    user_id_input = input(f"Enter user ID to check (yours is {session['id']}): ").strip()
    try:
        user_id = int(user_id_input)
    except ValueError:
        print("\n✗ Invalid user ID.")
        return

    balance = check_balance(user_id)
    if balance is not None:
        print(f"\n  Account balance for user {user_id}: ${balance:,.2f}")
    else:
        print(f"\n✗ User ID {user_id} not found.")


def handle_transfer(session):
    """
    VULNERABILITY DEMO — Broken Access Control (CWE-284):
    The 'from' account ID is taken from user input, not forced to the
    session user.  An attacker can transfer FROM any account.
    """
    print_header("TRANSFER FUNDS")
    print(f"  Your user ID: {session['id']}")

    try:
        from_id = int(input("From user ID: ").strip())
        to_id = int(input("To user ID: ").strip())
        amount = float(input("Amount ($): ").strip())
    except ValueError:
        print("\n✗ Invalid input. Please enter numeric values.")
        return

    result = transfer_funds(from_id, to_id, amount, logged_in_user_id=session["id"])
    if result["status"] == "success":
        print(f"\n✓ {result['message']}")
        print(f"  Your new balance: ${result['sender_balance']:,.2f}")
    else:
        print(f"\n✗ {result['message']}")


def handle_history(session):
    """
    VULNERABILITY DEMO — Broken Access Control (CWE-284):
    User can enter any user ID to view that user's transaction history.
    """
    print_header("TRANSACTION HISTORY")
    user_id_input = input(f"Enter user ID (yours is {session['id']}): ").strip()
    try:
        user_id = int(user_id_input)
    except ValueError:
        print("\n✗ Invalid user ID.")
        return

    history = transaction_history(user_id)
    if not history:
        print("\n  No transactions found.")
        return

    print(f"\n  {'ID':<5} {'Type':<12} {'Amount':>10} {'From':>6} {'To':>6} {'Timestamp':<20}")
    print("  " + "-" * 65)
    for txn in history:
        to_str = str(txn['to_user']) if txn['to_user'] else "N/A"
        print(f"  {txn['id']:<5} {txn['type']:<12} ${txn['amount']:>9,.2f} {txn['from_user']:>6} {to_str:>6} {txn['timestamp']:<20}")


def handle_beneficiaries(session, token):
    """Beneficiary management sub-menu."""
    while True:
        print_header("MANAGE BENEFICIARIES")
        print_menu(["List Beneficiaries", "Add Beneficiary", "Delete Beneficiary", "Back"])
        choice = input("Select option: ").strip()

        if choice == "1":
            # VULNERABLE — user can enter any owner_id
            owner_input = input(f"Enter owner user ID (yours is {session['id']}): ").strip()
            try:
                owner_id = int(owner_input)
            except ValueError:
                print("\n✗ Invalid user ID.")
                continue
            bens = list_beneficiaries(owner_id)
            if not bens:
                print("\n  No beneficiaries found.")
            else:
                print(f"\n  {'ID':<5} {'Name':<20} {'Account No':<15} {'Bank':<20}")
                print("  " + "-" * 60)
                for b in bens:
                    print(f"  {b['id']:<5} {b['name']:<20} {b['account_no']:<15} {b['bank_name']:<20}")

        elif choice == "2":
            name = input("Beneficiary name: ").strip()
            account_no = input("Account number: ").strip()
            bank_name = input("Bank name: ").strip()
            bid = add_beneficiary(session["id"], name, account_no, bank_name)
            print(f"\n✓ Beneficiary added (ID: {bid}).")

        elif choice == "3":
            # VULNERABLE — no ownership check on delete
            try:
                bid = int(input("Beneficiary ID to delete: ").strip())
            except ValueError:
                print("\n✗ Invalid ID.")
                continue
            if delete_beneficiary(bid, requesting_user_id=session["id"]):
                print("\n✓ Beneficiary deleted.")
            else:
                print("\n✗ Beneficiary not found.")

        elif choice == "4":
            return
        else:
            print("\n✗ Invalid option.")


def handle_search():
    """
    VULNERABILITY DEMO — SQL Injection (CWE-89):
    Search term is passed directly into a vulnerable LIKE query.
    """
    print_header("SEARCH USERS")
    term = input("Enter search term: ").strip()
    results = vulnerable_search_user(term)
    if not results:
        print("\n  No users found.")
    else:
        print(f"\n  {'ID':<5} {'Username':<15} {'Full Name':<25}")
        print("  " + "-" * 45)
        for r in results:
            print(f"  {r['id']:<5} {r['username']:<15} {r['full_name']:<25}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\nInitialising database...")
    init_db()
    print("Database ready.\n")
    print("Sample accounts: alice/password123, bob/bob@2024, admin/admin\n")
    pre_login_menu()
