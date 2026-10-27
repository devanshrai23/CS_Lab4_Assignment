# SQL Injection (Authentication Bypass): Video Presentation Script & Viva Guide

This document is your complete, synchronized guide for recording your video presentation and defending your submission in the evaluator viva.

---

## 1. Pre-Recording Setup & Checklist

* **Screen Layout (Split-Screen Recommended):**
  * **Left Half:** VS Code with [database.js](file:///home/jalendu/CS_Lab/database.js) open.
  * **Right Half:** Browser open to `http://localhost:3000`.
* **Before Hitting Record:**
  1. Ensure the server is running: `npm start` (or `node server.js`).
  2. Click the **"Reset Database"** button in the header once to confirm clean seed data.
  3. Ensure the server configuration toggle is set to **"Vulnerable"** (the red banner).
  4. In VS Code, position your editor view on lines **35 to 85** of `database.js`.

---

## 2. Synchronized Video Recording Script

Target Duration: **2.5 to 3.5 Minutes**

### Part 1: Introduction (0:00 – 0:30)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **0:00 – 0:30** | Split screen: Browser showing clean application at `http://localhost:3000` on the right; VS Code on the left. | *"Hello. My name is [Your Name], roll number [Your Roll Number]. Today I am demonstrating Web Server Security for Course IT-30001.<br><br>My assigned category is **SQL Injection**, and I have implemented **Variant 1: Authentication Bypass**.<br><br>In this presentation, I will explain the root cause in the backend code, execute the live exploit against the vulnerable server, demonstrate how the attack is mitigated using parameterized prepared statements, and show the live defense in action."* |

---

### Part 2: Backend Code Walkthrough – Vulnerable Implementation (0:30 – 1:00)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **0:30 – 1:00** | On the left half (VS Code), highlight lines in [database.js](file:///home/jalendu/CS_Lab/database.js):<br>`const sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";` | *"Let's look at the vulnerable backend implementation in `database.js`. In `loginVulnerable`, the SQL statement is constructed using direct string concatenation.<br><br>The server incorporates user-supplied strings directly into the SQL command text. Because the SQL engine receives the entire concatenated string as a single command, untrusted characters like single quotes allow an attacker to escape the literal data boundary and inject arbitrary SQL syntax."* |

---

### Part 3: Live Exploit – Authentication Bypass (1:00 – 1:45)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **1:00 – 1:20** | In the browser (right side):<br>1. Confirm banner is **Current Mode: Vulnerable**.<br>2. Click the sample payload button **`admin'--`**.<br>3. Point to the populated fields: username has `admin'--` and password has `anything`. | *"Now let's switch to the running application in Vulnerable Mode. I'll test an authentication bypass targeting the administrator account.<br><br>I input the username `admin'--` and provide an arbitrary dummy password."* |
| **1:20 – 1:45** | Click **"Submit Authentication Query"**.<br>Point to the result box and the query display. | *"When I submit, we see **Exploit Succeeded: Unauthorized Access Granted**! The application logs us directly in as the Administrator without validating the password.<br><br>Looking at the executed query below, we can see the exact mechanics: the single quote closes the username string literal early, and the double dash `--` comments out the remainder of the query, including `AND password = '...'`. The database executes only `SELECT ... WHERE username = 'admin'`, so authentication succeeds immediately."* |

---

### Part 4: Root Cause Explanation (1:45 – 2:05)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **1:45 – 2:05** | Point to the highlighted query in the inspector box. | *"The fundamental root cause is the **mixing of code and data**. When user data is concatenated directly into the command string, the database parser cannot differentiate between the developer’s instructions and the attacker’s input. This allows metacharacters to alter the query's Abstract Syntax Tree."* |

---

### Part 5: Backend Defense Walkthrough – Parameterized Query (2:05 – 2:35)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **2:05 – 2:35** | In VS Code, highlight the `loginMitigated` function in [database.js](file:///home/jalendu/CS_Lab/database.js):<br>`const sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";`<br>`const stmt = db.prepare(sql);`<br>`const rows = stmt.all(username, password);` | *"Now, let's examine the mitigation. The gold standard defense against SQL injection is **Parameterized Queries using Prepared Statements**.<br><br>Here, the SQL command structure is pre-defined using question mark (`?`) placeholders. The database pre-compiles the command structure before receiving user data. When `stmt.all(...)` executes, user inputs are transmitted over a separate data channel. The database treats the inputs strictly as literal values, never as executable code."* |

---

### Part 6: Live Mitigation Demonstration (2:35 – 3:05)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **2:35 – 3:05** | In the browser:<br>1. Click the toggle button **"Mitigated (Secure)"** at the top.<br>2. Banner switches to green.<br>3. With `admin'--` in the username field, click **"Submit Authentication Query"**.<br>4. Point to the green status tag and query inspector. | *"Let's test this defense live on the application. I switch the server configuration to **Mitigated Mode** and submit the exact same payload: `admin'--`.<br><br>Notice the result: **Exploit Mitigated: Access Denied**.<br>In the query inspector, you can see the database executed the query with parameter placeholders `?`, and bound `admin'--` strictly as literal string data. The database searched for a user whose literal username equals `admin'--`. Because no such user exists, authentication fails safely."* |

---

### Part 7: Conclusion & Defense-in-Depth (3:05 – 3:25)

| Time | What to Show on Screen | What to Say (Word-for-Word Script) |
| :--- | :--- | :--- |
| **3:05 – 3:25** | Show the full application screen or project structure in VS Code. | *"To summarize: Parameterized queries completely prevent SQL injection by enforcing a strict separation between code execution and data values.<br><br>As part of defense-in-depth, parameterization should be complemented by strict server-side allow-listing for SQL identifiers like table or column names, least-privilege database user permissions, and safe error handling that never exposes raw database exceptions to users.<br><br>Thank you."* |

---

## 3. Evaluator Viva Q&A (Preparation Cheat Sheet)

The assignment requires you to be able to explain the theoretical concepts and alternatives covered in the lecture during the viva. Use these concise answers:

### Q1: "Why does parameterization work? What does the database engine actually do internally?"
> **Answer:** *"When a query uses prepared statements with parameter placeholders (`?`), the database parser compiles the query structure into an Abstract Syntax Tree (AST) before user input is supplied. When user values are subsequently bound, they are placed in separate memory buffers and treated purely as literal scalar values. Because compilation has already completed, user input can never alter query grammar or logic."*

### Q2: "Can prepared statements be used everywhere in dynamic SQL queries?"
> **Answer:** *"No. Parameter placeholders (`?`) can only be used for literal data values (e.g. values in `WHERE`, `VALUES`, `HAVING`). They cannot be used for SQL identifiers, such as column names, table names, or sort directions (`ASC`/`DESC`). For identifiers, applications must use strict **server-side allow-lists** (e.g., verifying against an array of permitted column names) before incorporating them into queries."*

### Q3: "What are the four primary SQL injection techniques covered in lecture?"
> **Answer:**
> 1. **Authentication Bypass:** Injects comments (`--`, `/* */`) or tautologies (`' OR '1'='1'`) to circumvent credential checks in `WHERE` clauses.
> 2. **UNION-Based Data Extraction:** Appends `UNION SELECT` to an existing query to extract records from arbitrary tables into the application's output (requires matching column counts and compatible data types).
> 3. **Error-Based Injection:** Deliberately triggers database runtime errors (e.g., illegal type conversions) that leak table names, column names, or values inside verbose database error traces.
> 4. **Blind SQL Injection:** Exploited when the server reveals neither data nor errors:
>    - **Boolean-Based:** Evaluates true/false statements; attacker observes differential page behavior.
>    - **Time-Based:** Injects delay primitives (e.g., `pg_sleep(5)` or `WAITFOR DELAY`); a delayed server response proves the guessed condition is true.

### Q4: "What defense-in-depth measures should be used alongside parameterization?"
> **Answer:**
> * **Least-Privilege Database Accounts:** Run the web application using a database role restricted only to necessary tables and operations (`SELECT`, `INSERT`), with administrative rights, `DROP`, and OS command execution (`xp_cmdshell`) revoked.
> * **Safe Error Handling:** Catch all database exceptions and return generic messages to clients, preventing database fingerprints or schema disclosure.
> * **Input Validation:** Enforce strict type, length, and format validation before data reaches backend services.
