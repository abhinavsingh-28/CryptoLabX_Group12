"""
banking.py - Core banking operations for Online Banking Application.

VULNERABILITY: Broken Access Control (CWE-284)
    - check_balance(), transfer_funds(), and transaction_history() accept
      an arbitrary user_id parameter without verifying that the currently
      logged-in user owns that account.  Any authenticated user can view
      or manipulate another user's data by supplying a different user_id.
"""

import logging
from src.db import get_user_by_id, update_balance, insert_transaction, get_transactions

logger = logging.getLogger("online_banking.banking")


def check_balance(user_id: int):
    """
    Return the balance for the given user_id.

    VULNERABLE — Broken Access Control (CWE-284):
        No check that the caller actually owns this user_id.
        Any logged-in user can query any other user's balance.
    """
    user = get_user_by_id(user_id)
    if user:
        # ⚠️ VULNERABLE — balance of ANY user logged (CWE-532)
        logger.info("Balance inquiry — user_id=%d, balance=%.2f", user_id, user["balance"])
        return user["balance"]
    return None


def transfer_funds(from_user_id: int, to_user_id: int, amount: float, logged_in_user_id: int = None):
    """
    Transfer *amount* from one user to another.

    Returns a dict with status and message.

    VULNERABLE — Broken Access Control (CWE-284):
        - `from_user_id` is taken from user input, NOT enforced to match
          the session's user.  An attacker can transfer funds FROM any account.
        - `logged_in_user_id` is accepted but NEVER checked against from_user_id.
    """
    # ⚠️ NOTE: logged_in_user_id is intentionally IGNORED — this is the vulnerability
    if amount <= 0:
        return {"status": "error", "message": "Amount must be positive."}

    sender = get_user_by_id(from_user_id)
    receiver = get_user_by_id(to_user_id)

    if not sender:
        return {"status": "error", "message": f"Sender account (id={from_user_id}) not found."}
    if not receiver:
        return {"status": "error", "message": f"Receiver account (id={to_user_id}) not found."}
    if sender["balance"] < amount:
        return {"status": "error", "message": "Insufficient funds."}

    # Perform the transfer
    new_sender_balance = sender["balance"] - amount
    new_receiver_balance = receiver["balance"] + amount

    update_balance(from_user_id, new_sender_balance)
    update_balance(to_user_id, new_receiver_balance)
    insert_transaction(from_user_id, to_user_id, amount, "TRANSFER",
                       f"Transfer from user {from_user_id} to user {to_user_id}")

    # ⚠️ VULNERABLE — sensitive financial data logged (CWE-532)
    logger.info(
        "Transfer executed — from_user=%d (new_bal=%.2f), to_user=%d (new_bal=%.2f), amount=%.2f",
        from_user_id, new_sender_balance, to_user_id, new_receiver_balance, amount,
    )

    return {
        "status": "success",
        "message": f"Successfully transferred ${amount:.2f} to user {to_user_id}.",
        "sender_balance": new_sender_balance,
        "receiver_balance": new_receiver_balance,
    }


def transaction_history(user_id: int):
    """
    Fetch the transaction history for a given user_id.

    VULNERABLE — Broken Access Control (CWE-284):
        No ownership check.  Any authenticated user can view
        another user's transaction history by supplying their user_id.
    """
    rows = get_transactions(user_id)
    logger.info("Transaction history requested — user_id=%d, count=%d", user_id, len(rows))

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "from_user": row["from_user"],
            "to_user": row["to_user"],
            "amount": row["amount"],
            "type": row["txn_type"],
            "timestamp": row["timestamp"],
            "description": row["description"],
        })
    return history
