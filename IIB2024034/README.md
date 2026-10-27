# Web Server Security: SQL Injection Demonstration
**Course:** IT-30001 (Cyber Security) | Autumn Semester 2026  
**Institution:** Indian Institute of Information Technology Allahabad  
**Instructor:** Dr. Soumyadev Maity  

---

## 1. Ownership Declaration (Assignment Table 3)

| Member Name | Roll Number | Category | Variant Implemented |
| :--- | :--- | :--- | :--- |
| *(Your Name)* | *(Your Roll Number)* | SQL Injection | Variant 1: Authentication Bypass |

---

## 2. Quick Setup & Running

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

## 3. Architecture & Core Implementation (Table 2 Requirements)

### (a) Vulnerable Implementation (Slide 6)
In `database.js`, user input is concatenated directly into SQL text strings:
```javascript
// Vulnerable Authentication (database.js)
const sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
const rows = db.prepare(sql).all();
```

### (b) Working Exploit Payloads
- **Payload 1 (Comment Bypass):** `admin'--`
  - **Rewritten SQL:** `SELECT id, username, role FROM users WHERE username = 'admin'--' AND password = '...'`
  - **Result:** The single quote `'` terminates the username literal early, and `--` comments out the password verification logic. The attacker gains administrator access with an arbitrary dummy password.
- **Payload 2 (Tautology Bypass):** `' OR '1'='1'--`
  - **Rewritten SQL:** `SELECT id, username, role FROM users WHERE username = '' OR '1'='1'--' AND password = '...'`
  - **Result:** Forces the `WHERE` condition to evaluate to true for all rows, logging the attacker into the first returned user account.

### (c) Root Cause (Slide 5)
**Mixing Code and Data:** The application concatenates fixed SQL grammar with dynamic user input into a single string sent to the database parser. The database engine cannot distinguish between the developer's command logic and the user's data values, allowing special metacharacters like `'` and `--` to alter query execution flow.

### (d) Implemented Mitigation: Parameterized Queries (Slide 14)
The primary fix is **Parameterized Queries (Prepared Statements)** with placeholders (`?`):
```javascript
// Mitigated Authentication (database.js)
const stmt = db.prepare("SELECT id, username, role FROM users WHERE username = ? AND password = ?");
const rows = stmt.all(username, password);
```
- **Why it works:** The query structure is pre-compiled by the database engine beforehand. User input is supplied strictly as parameter values across a separate data channel, completely preventing user input from being evaluated as executable SQL syntax.
- **Proof of defense:** Submitting `admin'--` in Mitigated Mode fails safely because the database searches literally for a user whose username equals `"admin'--"`.

---

## 4. Theory: The 4 SQL Injection Techniques (Slide 9)

Required knowledge for the viva oral examination:

1. **Authentication Bypass (Slides 6–7):**
   - Alters the `WHERE` clause in login logic using comment characters (`--`, `/* */`) or tautologies (`' OR '1'='1'`) so credential checks are circumvented.
2. **UNION-based Data Extraction (Slide 10):**
   - Appends rows from arbitrary tables into an existing query output using `UNION SELECT`.
   - Requires matching column counts and compatible data types.
3. **Error-based Injection (Slides 9, 15, 18):**
   - Forces database runtime errors (e.g., divide-by-zero or illegal type conversions) that leak schema details, table names, or values within verbose error traces returned to the client.
4. **Blind SQL Injection (Slide 11):**
   - Used when no data and no error messages are displayed on the page:
     - **Boolean-based:** Injects boolean tests (e.g., testing character substrings). The attacker infers characters by observing differential page responses (true vs. false).
     - **Time-based:** Injects sleep functions (e.g., `pg_sleep(5)`). A slow response confirms that a guessed character or condition was true.

---

## 5. Theory: Other Defense Alternatives (Slides 15–18)

Required theoretical answers for Table 2(e):

1. **Allow-List Validation (Slides 15–16):**
   - **Why needed:** Placeholders (`?`) only work for literal data *values*, not SQL identifiers (table names, column names, or sort orders like `ASC/DESC`).
   - **Mechanism:** Dynamically constructed queries must check identifiers against a strict server-side whitelist before query execution.
2. **Least-Privilege Database Accounts (Slide 15):**
   - Configure the database user with minimal necessary permissions (e.g., `SELECT`, `INSERT`, `UPDATE` only on required tables). Revoke administrative rights, `DROP`, and filesystem/OS command access (`xp_cmdshell`, `LOAD_FILE()`).
3. **Safe Error Handling (Slides 15, 18):**
   - Never leak detailed SQL exception messages or database stack traces to clients. Always catch database errors and return generic error messages.

---

## 6. Video Demonstration & Presentation Script (2.5 – 3.5 Minutes)

Use this synchronized walkthrough when recording your screen demonstration or presenting live to an evaluator:

### Pre-Recording Setup:
- **Left Half of Screen:** VS Code with `database.js` visible (lines 35–85).
- **Right Half of Screen:** Browser open at `http://localhost:3000`.
- **Initial State:** Click **"Reset Database"** once, and ensure server mode is set to **🔴 Vulnerable**.

---

### Step-by-Step Script & Actions:

#### 1. Introduction (0:00 – 0:30)
* **What to Show:** Split screen with the web interface and VS Code.
* **What to Say:**
  > *"Hello. My name is [Your Name], roll number [Your Roll Number]. Today I am demonstrating Web Server Security for Course IT-30001 (Cyber Security). My assigned category is SQL Injection, and I have implemented Variant 1: Authentication Bypass. In this presentation, I will show the vulnerable code, execute the live exploit, explain the root cause, walk through the parameterized prepared statement mitigation, and demonstrate the defense in action."*

#### 2. Backend Vulnerable Code Walkthrough (0:30 – 1:00)
* **What to Show:** In VS Code, highlight lines 38–42 in `database.js`:
  ```javascript
  const sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  ```
* **What to Say:**
  > *"Let's look at the vulnerable backend implementation in `database.js`. In `loginVulnerable`, the SQL query is constructed using direct string concatenation. The server inserts untrusted user input directly into the SQL command text. Because the database engine receives this entire concatenated string as a single command, untrusted characters like single quotes allow an attacker to escape literal data boundaries and inject arbitrary SQL syntax."*

#### 3. Live Exploit Demonstration (1:00 – 1:45)
* **What to Show:**
  1. In the browser, verify **Current Mode: Vulnerable** (red banner).
  2. Click the sample button **`admin'--`**.
  3. Point to the fields: Username is `admin'--`, password is `anything`.
  4. Click **"Submit Authentication Query"**.
  5. Point to the **Exploit Succeeded** badge and the executed query display in the inspector box.
* **What to Say:**
  > *"Now let's test this against the live application. With the server in Vulnerable Mode, I supply the username `admin'--` and an arbitrary dummy password. Upon submission, we see: Exploit Succeeded: Unauthorized Access Granted! We are logged in as the Administrator without knowing the password. Looking at the executed query below, the single quote closed the username string literal early, and the double dash `--` commented out the rest of the query, including the password check. The database only checked `WHERE username = 'admin'`, so access was immediately granted."*

#### 4. Root Cause Explanation (1:45 – 2:05)
* **What to Show:** Point to the highlighted injected snippet in the inspector box.
* **What to Say:**
  > *"The root cause is the fundamental mixing of code and data. Because user input is concatenated into the raw query string, the SQL parser cannot differentiate between the developer’s SQL command grammar and the user’s input values, allowing metacharacters to rewrite the query's execution logic."*

#### 5. Backend Mitigation Walkthrough (2:05 – 2:35)
* **What to Show:** In VS Code, highlight `loginMitigated` in `database.js`:
  ```javascript
  const sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
  const stmt = db.prepare(sql);
  const rows = stmt.all(username, password);
  ```
* **What to Say:**
  > *"Now, let's examine the mitigation. The gold-standard fix for SQL injection is Parameterized Queries using Prepared Statements with `?` placeholders. Notice that the SQL command structure is compiled by the database beforehand. When `stmt.all(...)` runs, user inputs are transmitted over a separate data channel. The database treats the inputs strictly as literal values, never as executable code."*

#### 6. Live Mitigation Demonstration (2:35 – 3:05)
* **What to Show:**
  1. Click the **"Mitigated (Secure)"** toggle button at the top banner (banner turns green).
  2. With the exact same `admin'--` payload in the username field, click **"Submit Authentication Query"**.
  3. Point to the green **Exploit Mitigated: Access Denied** status tag and the parameter bindings display.
* **What to Say:**
  > *"Let's test this live. I switch the server configuration to Mitigated Mode and submit the exact same payload: `admin'--`. The exploit is completely blocked: Exploit Mitigated: Access Denied. In the query inspector, you can see the database executed the query with parameter placeholders, and bound `admin'--` strictly as literal string data. The database searched for a user whose literal username equals `admin'--`. Since no such user exists, the attempt fails safely."*

#### 7. Conclusion & Defense-in-Depth (3:05 – 3:25)
* **What to Show:** Show the clean web application or VS Code workspace.
* **What to Say:**
  > *"In conclusion: Parameterized queries enforce strict separation between code execution and data values, eliminating SQL injection. For defense-in-depth, parameterization should be paired with server-side allow-lists for SQL identifiers like column names, least-privilege database user accounts, and safe error handling that never exposes raw SQL exceptions. Thank you."*

---

## 7. Evaluator Viva Q&A (Preparation Cheat Sheet)

Be prepared to answer these technical questions during your evaluation:

### Q1: "Why does parameterization work? What happens inside the database?"
> **Answer:** *"When a query is parameterized, the database parser compiles the query structure into an Abstract Syntax Tree (AST) before user input is supplied. When user values are bound later, they are treated strictly as literal scalar values in memory. Because the parsing and compilation phase has already completed, user input cannot alter the query grammar or execution tree."*

### Q2: "Can prepared statements be used for all dynamic SQL operations?"
> **Answer:** *"No. Parameter placeholders (`?`) can only represent literal data values (e.g., in `WHERE`, `VALUES`, `HAVING`). They cannot be used for SQL identifiers, such as table names, column names, or sort orders (`ASC`/`DESC`). For identifiers, applications must use strict **server-side allow-lists** to validate inputs before concatenating them."*

### Q3: "What are the four primary SQL injection techniques?"
> **Answer:**
> 1. **Authentication Bypass:** Injects comments (`--`) or tautologies (`' OR '1'='1'`) to skip credential checks in `WHERE` clauses.
> 2. **UNION-Based Data Extraction:** Appends `UNION SELECT` to an existing query to extract records from arbitrary tables into the application's output.
> 3. **Error-Based Injection:** Triggers deliberate database errors (e.g., illegal type conversions) that leak schema or data inside verbose error messages returned to the client.
> 4. **Blind SQL Injection:** Exploited when the server reveals neither data nor errors:
>    - **Boolean-Based:** Evaluates true/false statements; attacker infers data by observing differential page responses.
>    - **Time-Based:** Injects delay functions (e.g., `pg_sleep(5)`); a slow response confirms the guessed condition was true.

### Q4: "What defense-in-depth practices should be implemented alongside parameterization?"
> **Answer:**
> * **Least-Privilege Database Accounts:** Run the web application using a database role restricted only to necessary tables and operations (`SELECT`, `INSERT`), with administrative rights, `DROP`, and OS command execution (`xp_cmdshell`) revoked.
> * **Safe Error Handling:** Catch all database exceptions on the server and return generic error messages to clients, preventing database fingerprints or schema disclosure.
> * **Input Validation:** Enforce strict type, length, and format validation before data reaches backend services.
