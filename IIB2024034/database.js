const { DatabaseSync } = require('node:sqlite');
const path = require('path');

// Initialize database (file allows inspection; recreated on reset)
const dbPath = path.join(__dirname, 'vulnerable_app.db');
const db = new DatabaseSync(dbPath);

function initDatabase() {
  // Drop table if existing to ensure a clean state
  db.exec(`DROP TABLE IF EXISTS users;`);

  // Create Users table
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );
  `);

  // Insert seed users (using values directly from lecture slides, e.g. asha/s3cret)
  const insertUser = db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`);
  insertUser.run('admin', 'sup3r_s3cr3t_admin_pass!#', 'Administrator');
  insertUser.run('asha', 's3cret', 'User');
  insertUser.run('john', 'john@2026', 'User');
  insertUser.run('Mr Sabir', 'prof_secure_99$', 'Faculty');

  console.log('Database initialized with seed users data.');
}

// ----------------------------------------------------
// SQL INJECTION: AUTHENTICATION BYPASS
// ----------------------------------------------------

/**
 * Vulnerable Login Implementation (Slide 6)
 * Direct string concatenation where untrusted input escapes into SQL syntax.
 */
function loginVulnerable(username, password) {
  const sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  try {
    const rows = db.prepare(sql).all();
    return {
      success: rows.length > 0,
      user: rows.length > 0 ? rows[0] : null,
      executedQuery: sql,
      rowsMatched: rows.length,
      mode: 'vulnerable'
    };
  } catch (err) {
    return {
      success: false,
      error: err.message,
      executedQuery: sql,
      mode: 'vulnerable'
    };
  }
}

/**
 * Mitigated Login Implementation (Slide 14)
 * Uses Parameterized Queries (Prepared Statements) with placeholders.
 * The database engine treats user input strictly as literal values, never executable code.
 */
function loginMitigated(username, password) {
  const sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
  try {
    const stmt = db.prepare(sql);
    const rows = stmt.all(username, password);
    return {
      success: rows.length > 0,
      user: rows.length > 0 ? rows[0] : null,
      executedQuery: sql,
      boundParameters: [username, password],
      rowsMatched: rows.length,
      mode: 'mitigated'
    };
  } catch (err) {
    // Safe error handling: Do not leak internal DB errors to user
    return {
      success: false,
      error: 'An unexpected authentication error occurred.',
      executedQuery: sql,
      mode: 'mitigated'
    };
  }
}

module.exports = {
  initDatabase,
  loginVulnerable,
  loginMitigated
};
