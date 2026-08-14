"""
beneficiary.py - Beneficiary management for Online Banking Application.

VULNERABILITY: Broken Access Control (CWE-284)
    - list_beneficiaries() and delete_beneficiary() accept an arbitrary
      owner_id without verifying that the caller is the actual owner.
"""

import sqlite3
import logging
from src.db import get_connection

logger = logging.getLogger("online_banking.beneficiary")


def add_beneficiary(owner_id: int, name: str, account_no: str, bank_name: str):
    """
    Add a beneficiary for the given owner_id.
    Returns the new beneficiary id.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO beneficiaries (owner_id, name, account_no, bank_name) VALUES (?, ?, ?, ?)",
        (owner_id, name, account_no, bank_name),
    )
    conn.commit()
    bid = cur.lastrowid
    conn.close()
    logger.info("Beneficiary added — id=%d, owner_id=%d, name=%s, account=%s, bank=%s",
                bid, owner_id, name, account_no, bank_name)
    return bid


def list_beneficiaries(owner_id: int):
    """
    List all beneficiaries for a given owner_id.

    VULNERABLE — Broken Access Control (CWE-284):
        Any authenticated user can list another user's beneficiaries
        by supplying a different owner_id.
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM beneficiaries WHERE owner_id = ?", (owner_id,))
    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "owner_id": row["owner_id"],
            "name": row["name"],
            "account_no": row["account_no"],
            "bank_name": row["bank_name"],
        })
    logger.info("Beneficiaries listed — owner_id=%d, count=%d", owner_id, len(results))
    return results


def delete_beneficiary(beneficiary_id: int, requesting_user_id: int = None):
    """
    Delete a beneficiary by id.

    VULNERABLE — Broken Access Control (CWE-284):
        `requesting_user_id` is accepted but NEVER checked.
        Any user can delete any beneficiary from any account.
    """
    # ⚠️ requesting_user_id is intentionally IGNORED
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM beneficiaries WHERE id = ?", (beneficiary_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()

    if deleted:
        logger.info("Beneficiary deleted — id=%d (requested by user_id=%s)", beneficiary_id, requesting_user_id)
    else:
        logger.warning("Beneficiary not found — id=%d", beneficiary_id)

    return deleted > 0
