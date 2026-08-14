# Online Banking Application

**Lab Assignment 3 — Group 12**
**Course:** Cryptography & Network Security Lab

---

## Overview

A console-based **Online Banking** application built with Python and SQLite. The application demonstrates five core banking functionalities along with **three intentional security vulnerabilities** for educational analysis.

> ⚠️ **Disclaimer:** This application contains intentional vulnerabilities for academic purposes. Do NOT deploy in any production environment.

---

## Core Functionalities

| # | Feature | Description |
|---|---|---|
| 1 | **User Login / Registration** | Register new accounts and authenticate with username/password |
| 2 | **Check Balance** | View current account balance |
| 3 | **Transfer Funds** | Send money from one account to another |
| 4 | **Manage Beneficiaries** | Add, list, and delete payment beneficiaries |
| 5 | **Transaction History** | View past transactions for an account |

---

## Intentional Vulnerabilities

| # | Vulnerability | CWE | Primary File(s) |
|---|---|---|---|
| 1 | SQL Injection | CWE-89 | `src/db.py` |
| 2 | Broken Access Control | CWE-284 | `src/banking.py`, `src/beneficiary.py` |
| 3 | Sensitive Data Exposure in Logs | CWE-532 | `src/auth.py`, `src/session.py` |

See [`reports/vulnerability_report.md`](reports/vulnerability_report.md) for detailed analysis, proof-of-concept, impact, and remediation.

---

## Technology Stack

- **Language:** Python 3
- **Database:** SQLite (via `sqlite3` standard library)
- **Dependencies:** None — uses only Python standard library

---

## Folder Structure

```
online_banking/
├── src/                          # Application source code
│   ├── __init__.py
│   ├── main.py                   # Console entry point (menu loop)
│   ├── db.py                     # Database setup & vulnerable SQL helpers
│   ├── auth.py                   # Authentication (login / register)
│   ├── banking.py                # Balance, transfer, history
│   ├── beneficiary.py            # Beneficiary management
│   └── session.py                # Session management
├── reports/                      # Vulnerability reports
│   └── vulnerability_report.md
├── screenshots/                  # SAST scan screenshots (populated later)
├── sast/                         # SAST tool configuration & results
├── outputs/                      # Runtime outputs (DB, logs)
│   ├── banking.db                # SQLite database (auto-created)
│   └── app.log                   # Application log file (auto-created)
├── testcases/                    # Test scripts
│   ├── __init__.py
│   └── test_vulnerabilities.py   # Demonstrates all 3 vulnerabilities
├── Assignment_3.pdf              # Assignment specification
└── README.md                     # This file
```

---

## How to Run

### Prerequisites
- Python 3.6 or higher

### Running the Application

```bash
cd online_banking
python3 -m src.main
```

The application will:
1. Create the SQLite database (`outputs/banking.db`) automatically
2. Seed three sample accounts
3. Display an interactive console menu

### Sample Accounts

| Username | Password | Balance |
|---|---|---|
| `alice` | `password123` | $15,000.00 |
| `bob` | `bob@2024` | $8,000.00 |
| `admin` | `admin` | $50,000.00 |

---

## Running Test Cases

The test suite demonstrates all three vulnerabilities programmatically:

```bash
cd online_banking
python3 -m testcases.test_vulnerabilities
```

### What the Tests Demonstrate

1. **SQL Injection:** Login bypass using `' OR '1'='1' --` and data extraction via UNION injection
2. **Broken Access Control:** Bob accessing Alice's balance, history, beneficiaries, and transferring funds from her account
3. **Sensitive Data Exposure:** Passwords and session tokens found in plaintext in `outputs/app.log`

---

## Log File

All application activity (including sensitive data — intentionally) is logged to:
```
outputs/app.log
```

---

## Authors

Group 12 — CryptoLabX
