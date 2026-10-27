
| Member Name | Roll Number | Category | Variant Implemented |
| :--- | :--- | :--- | :--- |
| *Jalendu Pandey* | *IIB2024034* | SQL Injection | Variant 1: Authentication Bypass |

---

## Quick Setup & Running

This project is built using **Node.js** with zero external database setup required (utilizes built-in SQLite).

### Prerequisites
- Node.js (v18+ or v24+)

### Installation & Launch
```bash
# Install dependencies
npm install

# Start the server
npm start
```
The server will start at: **`http://localhost:3000`**

---

## Architecture & Core Implementation

### (a) Vulnerable Implementation 
In `database.js`, user input is concatenated directly into SQL text strings:
```javascript
// Vulnerable Authentication (database.js)
const sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
const rows = db.prepare(sql).all();
```

### Working Exploit Payloads
- **Payload 1 (Comment Bypass):** `admin'--`
  - **Rewritten SQL:** `SELECT id, username, role FROM users WHERE username = 'admin'--' AND password = '...'`
  - **Result:** The single quote `'` terminates the username literal early, and `--` comments out the password verification logic. The attacker gains administrator access with an arbitrary dummy password.
- **Payload 2 (Tautology Bypass):** `' OR '1'='1'--`
  - **Rewritten SQL:** `SELECT id, username, role FROM users WHERE username = '' OR '1'='1'--' AND password = '...'`
  - **Result:** Forces the `WHERE` condition to evaluate to true for all rows, logging the attacker into the first returned user account.


### Implemented Mitigation: Parameterized Queries 
The primary fix is **Parameterized Queries (Prepared Statements)** with placeholders (`?`):
```javascript
// Mitigated Authentication (database.js)
const stmt = db.prepare("SELECT id, username, role FROM users WHERE username = ? AND password = ?");
const rows = stmt.all(username, password);
```
- **Why it works:** The query structure is pre-compiled by the database engine beforehand. User input is supplied strictly as parameter values across a separate data channel, completely preventing user input from being evaluated as executable SQL syntax.
- **Proof of defense:** Submitting `admin'--` in Mitigated Mode fails safely because the database searches literally for a user whose username equals `"admin'--"`.

---

## Theory: SQL Injection Techniques

Required knowledge for the viva oral examination:

1. **Authentication Bypass:**
   - Alters the `WHERE` clause in login logic using comment characters (`--`, `/* */`) or tautologies (`' OR '1'='1'`) so credential checks are circumvented.
2. **UNION-based Data Extraction:**
   - Appends rows from arbitrary tables into an existing query output using `UNION SELECT`.
   - Requires matching column counts and compatible data types.

---

## 5. Theory: Other Defense Alternatives 


1. **Allow-List Validation:**
   - **Why needed:** Placeholders (`?`) only work for literal data *values*, not SQL identifiers (table names, column names, or sort orders like `ASC/DESC`).
   - **Mechanism:** Dynamically constructed queries must check identifiers against a strict server-side whitelist before query execution.
2. **Least-Privilege Database Accounts :**
   - Configure the database user with minimal necessary permissions (e.g., `SELECT`, `INSERT`, `UPDATE` only on required tables). Revoke administrative rights, `DROP`, and filesystem/OS command access (`xp_cmdshell`, `LOAD_FILE()`).
3. **Safe Error Handling:**
   - Never leak detailed SQL exception messages or database stack traces to clients. Always catch database errors and return generic error messages.

---

