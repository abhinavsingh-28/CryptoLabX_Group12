<h1 align="center">🔐 CryptoLabX — Group 12</h1>

<p align="center">
  <strong>Cryptography &amp; Network Security Laboratory</strong><br>
  A comprehensive toolkit covering classical cipher implementations, cryptanalysis attacks, security vulnerability analysis, and file analysis utilities.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-3776AB?logo=python&logoColor=white" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/C++-17-00599C?logo=cplusplus&logoColor=white" alt="C++17">
  <img src="https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Group-12-orange" alt="Group 12">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Active">
</p>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Project Architecture](#-project-architecture)
- [Assignments Completed](#-assignments-completed)
  - [Assignment 1 — Project Setup & File Analysis](#assignment-1--project-setup--file-analysis)
  - [Assignment 3 — Online Banking Vulnerability Analysis](#assignment-3--online-banking-vulnerability-analysis)
  - [Assignment 4 — Shift Cipher Cryptanalysis](#assignment-4--shift-cipher-cryptanalysis)
  - [Assignment 5 — Monoalphabetic Substitution Cryptanalysis](#assignment-5--monoalphabetic-substitution-cryptanalysis)
  - [Assignment 6 — Vigenère Cipher Cryptanalysis](#assignment-6--vigenère-cipher-cryptanalysis)
- [How to Run](#-how-to-run)
- [Technology Stack](#-technology-stack)
- [Code Statistics](#-code-statistics)
- [Authors](#-authors)

---

## 🔎 Overview

**CryptoLabX** is a semester-long, incrementally-built laboratory project that explores both the **construction** and **destruction** of cryptographic systems. The repository is organized into modular components spanning:

| Domain | What We Built |
|---|---|
| **Classical Ciphers** | Shift (Caesar) cipher, Monoalphabetic substitution cipher, Vigenère cipher |
| **Cryptanalysis Attacks** | Brute-force, dictionary attack, chi-squared analysis, frequency analysis, Kasiski examination, Index of Coincidence |
| **Security Analysis** | Intentionally vulnerable banking app with SQL injection, broken access control, and sensitive data exposure — plus automated exploit test suites |
| **Utility Tooling** | File analyzer, frequency counter, interactive CLI menus |

Each assignment builds on the previous one, progressing from basic text analysis → classical encryption → attack techniques → real-world vulnerability analysis.

---

## 🏗 Project Architecture

```
CryptoLabX_Group12/
│
├── main.py                          # 🎯 Root CLI entry point (CryptoLabX Toolkit menu)
├── requirements.txt                 # Python dependencies (stdlib-only project)
├── .gitignore
│
├── utils/                           # 🔧 Shared CLI utilities
│   ├── banner.py                    #    ASCII banner display
│   ├── menu.py                      #    Main menu renderer
│   └── input_handler.py             #    Input validation helper
│
├── analysis/                        # 📊 Assignment 1 — File analysis tools
│   └── file_analyzer.py             #    Character/word/line counts, letter frequency
│
├── datasets/                        # 📁 Sample text files for analysis
│   ├── sample.txt
│   ├── sample1.txt ... sample5.txt  #    Test inputs for file_analyzer
│
├── attacks/                         # ⚔️ Cryptanalysis attack modules
│   │
│   ├── shift_cipher_attack/         # Assignment 4 — Shift cipher attacks
│   │   ├── src/
│   │   │   ├── shift_cipher.py      #    Caesar encrypt/decrypt
│   │   │   ├── brute_force_dictionary.py  # Brute-force + dictionary scoring
│   │   │   ├── chi_square_attack.py       # Chi-squared frequency attack
│   │   │   └── main.py              #    Test harness comparing both attacks
│   │   └── Dictionary/
│   │       └── english_words.txt    #    100 common English words
│   │
│   ├── monoalphabetic_cryptanalysis.cpp  # Assignment 5 — Interactive C++ tool
│   │
│   └── vigenere_cryptanalysis/      # Assignment 6 — Vigenère cryptanalysis
│       ├── src/
│       │   ├── kasiski.py           #    Kasiski examination (5 functions)
│       │   ├── frequency.py         #    Frequency analysis & IC (4 functions)
│       │   ├── vigenere.py          #    Encrypt/decrypt/verify (4 functions)
│       │   └── main.py              #    Full pipeline driver
│       ├── data/
│       │   └── ciphertext.txt       #    Ciphertext-2 (Even Groups)
│       ├── outputs/
│       │   └── analysis_output.txt  #    Generated results
│       └── README.md
│
├── online_banking/                  # 🏦 Assignment 3 — Vulnerable banking app
│   ├── src/
│   │   ├── main.py                  #    Console UI with interactive menus
│   │   ├── db.py                    #    SQLite DB setup + vulnerable SQL helpers
│   │   ├── auth.py                  #    Authentication (login/register)
│   │   ├── banking.py               #    Balance, transfers, transaction history
│   │   ├── beneficiary.py           #    Beneficiary management (CRUD)
│   │   └── session.py               #    In-memory session management
│   ├── testcases/
│   │   └── test_vulnerabilities.py  #    Automated exploit demonstrations
│   ├── reports/
│   │   └── vulnerability_report.md  #    Detailed vulnerability write-up
│   ├── outputs/                     #    Runtime: banking.db, app.log
│   ├── screenshots/                 #    SAST scan evidence (placeholder)
│   ├── sast/                        #    SAST tool configs (placeholder)
│   ├── Assignment_3.pdf
│   └── README.md
│
├── classical/                       # 📜 Reserved for classical cipher implementations
├── modern/                          # 🔑 Reserved for modern cipher implementations
├── math/                            # 🧮 Reserved for mathematical foundations
├── tests/                           # 🧪 Reserved for unit tests
├── outputs/                         # 📤 Global output directory
└── docs/                            # 📝 Documentation
    └── cryptanalysis_decisions.md   #    Substitution decision matrix (Assignment 5)
```

---

## 📝 Assignments Completed

### Assignment 1 — Project Setup & File Analysis

**Objective:** Set up the repository structure and build a file analysis tool.

| Component | Description |
|---|---|
| `main.py` | Interactive CLI toolkit with Encrypt / Decrypt / Attack / Analyze / Exit menu |
| `analysis/file_analyzer.py` | Reads files from `datasets/`, computes character count, word count, line count, unique characters, and letter frequency distribution |
| `datasets/` | Six sample text files on cryptography topics for analysis testing |
| `utils/` | Shared banner, menu, and input validation utilities |

**Run:**
```bash
python3 main.py
# Select option 4 (Analyze) → enter filename (e.g., sample1.txt)
```

---

### Assignment 3 — Online Banking Vulnerability Analysis

**Objective:** Build a console banking application with **3 intentional security vulnerabilities**, document them, write automated exploit tests, and analyze with SAST tools.

#### Banking Features
| Feature | Description |
|---|---|
| Login / Register | Username + password authentication |
| Check Balance | View account balance |
| Transfer Funds | Send money between accounts |
| Manage Beneficiaries | Add, list, delete beneficiaries |
| Transaction History | View past transactions |
| Search Users | Search by username |

#### Intentional Vulnerabilities

| # | Vulnerability | CWE | Severity | Primary File | Attack Vector |
|---|---|---|---|---|---|
| 1 | **SQL Injection** | CWE-89 | 🔴 Critical | `db.py` | `' OR '1'='1' --` bypasses login; `UNION SELECT` extracts passwords |
| 2 | **Broken Access Control** | CWE-284 | 🟠 High | `banking.py`, `beneficiary.py` | Any user can access/modify another user's data by entering their ID |
| 3 | **Sensitive Data Exposure in Logs** | CWE-532 | 🟠 High | `auth.py`, `session.py` | Passwords, tokens, and balances logged in plaintext to `app.log` |

#### Sample Accounts (auto-seeded)
| Username | Password | Balance |
|---|---|---|
| `alice` | `password123` | $15,000.00 |
| `bob` | `bob@2024` | $8,000.00 |
| `admin` | `admin` | $50,000.00 |

**Run the app:**
```bash
cd online_banking
python3 -m src.main
```

**Run exploit test suite:**
```bash
cd online_banking
python3 -m testcases.test_vulnerabilities
```

> 📄 Full analysis: [`online_banking/reports/vulnerability_report.md`](online_banking/reports/vulnerability_report.md)

---

### Assignment 4 — Shift Cipher Cryptanalysis

**Objective:** Implement a Caesar (shift) cipher and break it using two different attack methods.

| Module | Description |
|---|---|
| `shift_cipher.py` | Caesar cipher encrypt/decrypt with arbitrary integer key |
| `brute_force_dictionary.py` | Tries all 26 shifts, scores each against an English word dictionary |
| `chi_square_attack.py` | Computes chi-squared statistic against standard English letter frequencies for each shift |
| `main.py` | Test harness comparing both methods on two sample plaintexts |

**How it works:**
```
Plaintext → Caesar Encrypt (key=7) → Ciphertext → Attack → Recovered Key
```

Both attacks correctly recover the key for all test cases.

**Run:**
```bash
cd attacks/shift_cipher_attack/src
python3 main.py
```

---

### Assignment 5 — Monoalphabetic Substitution Cryptanalysis

**Objective:** Break a monoalphabetic substitution cipher through interactive frequency analysis.

| Feature | Description |
|---|---|
| Frequency Analysis | Counts and ranks letter frequencies against known English distribution |
| Word Pattern Analysis | Identifies short repeated words (1–3 letter patterns like "THE", "OF") |
| Interactive Substitution | User proposes letter mappings one at a time |
| Partial Plaintext Display | Shows current decryption state with unresolved letters in uppercase |

The program encrypts a known plaintext (about indistinguishability and perfect secrecy) with the key `QWERTYUIOPASDFGHJKLZXCVBNM` and challenges the user to recover it manually.

**Decision matrix documented in:** [`docs/cryptanalysis_decisions.md`](docs/cryptanalysis_decisions.md)

**Compile and run:**
```bash
cd attacks
g++ -std=c++17 -o monoalphabetic monoalphabetic_cryptanalysis.cpp
./monoalphabetic
```

---

### Assignment 6 — Vigenère Cipher Cryptanalysis

**Objective:** Break a Vigenère cipher using the Kasiski Examination and Frequency Analysis.

**Ciphertext:** Ciphertext-2 (assigned to even-numbered groups)

#### Pipeline

```
Raw Ciphertext
     │
     ▼
┌─────────────────────┐
│  1. Preprocessing    │  clean_ciphertext()
│     Remove spaces    │
│     Normalize A–Z    │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  2. Kasiski Test     │  find_repeated_patterns() → calculate_distances()
│     Find repeated    │  → find_factors() → kasiski_analysis()
│     trigrams, factor │
│     their distances  │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  3. IC Validation    │  calculate_ic()
│     Confirm key len  │  English IC ≈ 0.0667
│     via Index of     │
│     Coincidence      │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  4. Frequency        │  split_into_groups() → frequency_analysis()
│     Analysis         │  → find_shift()
│     Chi-squared per  │
│     column group     │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  5. Key Recovery     │  find_key()
│     Combine shifts   │
│     into key word    │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  6. Decrypt          │  vigenere_decrypt()
│     P = (C-K) mod 26 │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  7. Verify           │  vigenere_encrypt() → verify()
│     Re-encrypt and   │  Confirm match with original
│     compare          │
└─────────────────────┘
```

#### Results

| Item | Value |
|---|---|
| **Estimated Key Length** | 12 |
| **Recovered Key** | `UNITEDSTATES` |
| **Plaintext** | US Declaration of Independence excerpt ("We the representatives of the United States of America...") |
| **Verification** | ✅ Re-encryption matches original ciphertext |

#### All 13 User-Defined Functions

| Function | Module | Purpose |
|---|---|---|
| `clean_ciphertext()` | `kasiski.py` | Remove spaces/special chars, normalize to uppercase |
| `find_repeated_patterns()` | `kasiski.py` | Identify repeated trigrams and longer sequences |
| `calculate_distances()` | `kasiski.py` | Find distances between repeated occurrences |
| `find_factors()` | `kasiski.py` | Factorize distances for candidate key lengths |
| `kasiski_analysis()` | `kasiski.py` | Full Kasiski pipeline combining all steps |
| `calculate_ic()` | `frequency.py` | Compute Index of Coincidence |
| `split_into_groups()` | `frequency.py` | Divide ciphertext into columns by key length |
| `frequency_analysis()` | `frequency.py` | Calculate A–Z frequency counts and percentages |
| `find_shift()` | `frequency.py` | Estimate Caesar shift per group (chi-squared) |
| `find_key()` | `vigenere.py` | Combine shifts into the Vigenère key |
| `vigenere_decrypt()` | `vigenere.py` | Decrypt ciphertext with recovered key |
| `vigenere_encrypt()` | `vigenere.py` | Re-encrypt plaintext for verification |
| `verify()` | `vigenere.py` | Confirm re-encryption matches original |

**Run:**
```bash
cd attacks/vigenere_cryptanalysis/src
python3 main.py
```

> 📄 Detailed docs: [`attacks/vigenere_cryptanalysis/README.md`](attacks/vigenere_cryptanalysis/README.md)

---

## 🚀 How to Run

### Prerequisites
- **Python 3.6+** (standard library only — no `pip install` required)
- **g++** with C++17 support (for Assignment 5 only)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/abhinavsingh-28/CryptoLabX_Group12.git
cd CryptoLabX_Group12

# Run the main CryptoLabX toolkit
python3 main.py

# Run individual assignments
cd attacks/shift_cipher_attack/src && python3 main.py          # Assignment 4
cd attacks && g++ -std=c++17 -o mono monoalphabetic_cryptanalysis.cpp && ./mono  # Assignment 5
cd attacks/vigenere_cryptanalysis/src && python3 main.py       # Assignment 6
cd online_banking && python3 -m src.main                       # Assignment 3 (app)
cd online_banking && python3 -m testcases.test_vulnerabilities # Assignment 3 (tests)
```

---

## 🛠 Technology Stack

| Technology | Usage |
|---|---|
| **Python 3** | Core language for all assignments (analysis, attacks, banking app) |
| **C++ 17** | Monoalphabetic substitution cipher cryptanalysis (Assignment 5) |
| **SQLite 3** | Embedded database for the online banking application |
| **Standard Libraries Only** | No external dependencies — `collections`, `sqlite3`, `re`, `os`, `logging` |

---

## 📊 Code Statistics

| Metric | Value |
|---|---|
| **Total Python files** | 29 |
| **Total C++ files** | 1 |
| **Total Python LoC** | ~2,016 |
| **Total C++ LoC** | ~93 |
| **Combined LoC** | **~2,109** |
| **Assignments completed** | 5 |
| **Cryptanalysis techniques** | 6 (brute-force, dictionary, chi-squared, frequency analysis, Kasiski, IC) |
| **Vulnerabilities documented** | 3 (SQL injection, broken access control, log exposure) |

---

## 👥 Authors

**Group 12** — CryptoLabX  
*Cryptography & Network Security Laboratory*
