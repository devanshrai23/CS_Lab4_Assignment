let currentMode = 'vulnerable'; // 'vulnerable' or 'mitigated'

function setMode(mode) {
  currentMode = mode;
  const banner = document.getElementById('modeBanner');
  const btnVuln = document.getElementById('btnModeVulnerable');
  const btnMit = document.getElementById('btnModeMitigated');
  const title = document.getElementById('modeTitle');
  const desc = document.getElementById('modeDesc');

  if (mode === 'vulnerable') {
    banner.className = 'mode-banner vulnerable';
    btnVuln.className = 'toggle-btn active';
    btnMit.className = 'toggle-btn';
    title.innerText = 'Current Mode: Vulnerable';
    desc.innerText = 'Direct string concatenation. User input escapes into raw SQL syntax.';
  } else {
    banner.className = 'mode-banner mitigated';
    btnVuln.className = 'toggle-btn';
    btnMit.className = 'toggle-btn active';
    title.innerText = 'Current Mode: Mitigated (Secure)';
    desc.innerText = 'Parameterized prepared statements. User input is bound separately as literal data.';
  }

  // Clear previous outputs on mode switch
  document.getElementById('authResultBox').style.display = 'none';
}

// Quick Fill Helper for Authentication payloads
function fillAuth(username, password) {
  document.getElementById('authUsername').value = username;
  document.getElementById('authPassword').value = password;
}

// ----------------------------------------------------
// AUTHENTICATION BYPASS HANDLER
// ----------------------------------------------------
async function handleAuthSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('authUsername').value;
  const password = document.getElementById('authPassword').value;

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, mode: currentMode })
    });
    const data = await res.json();

    const resultBox = document.getElementById('authResultBox');
    const badge = document.getElementById('authBadge');
    const message = document.getElementById('authMessage');
    const queryDisplay = document.getElementById('authQueryDisplay');
    const explanation = document.getElementById('authExplanation');

    resultBox.style.display = 'block';

    const isInjectionPayload = username.includes("'") || username.includes("--");

    if (data.success) {
      if (currentMode === 'vulnerable' && isInjectionPayload) {
        badge.className = 'status-tag success-exploit';
        badge.innerText = 'Exploit Succeeded: Unauthorized Access Granted';
        message.innerText = `Bypassed authentication! Logged in as ${data.user.username} (${data.user.role}) without a valid password.`;
      } else {
        badge.className = 'status-tag normal-login';
        badge.innerText = 'Authentication Succeeded';
        message.innerText = `Valid credentials accepted for ${data.user.username} (${data.user.role}).`;
      }
    } else {
      if (currentMode === 'mitigated' && isInjectionPayload) {
        badge.className = 'status-tag blocked';
        badge.innerText = 'Exploit Mitigated: Access Denied';
        message.innerText = 'Query executed safely. The payload was evaluated strictly as a literal username string rather than SQL code.';
      } else {
        badge.className = 'status-tag normal-login';
        badge.innerText = 'Authentication Failed';
        message.innerText = data.error || 'Invalid credentials provided.';
      }
    }

    if (currentMode === 'vulnerable') {
      queryDisplay.innerHTML = highlightSql(data.executedQuery, username);
      explanation.innerHTML = `<strong>Mechanism:</strong> The single quote (<code>'</code>) breaks out of the string literal, and the SQL comment delimiter (<code>--</code>) discards the password check (<code>AND password = '...'</code>).`;
    } else {
      queryDisplay.innerHTML = `${escapeHtml(data.executedQuery)}\n\n// Parameter bindings:\n// ? (1) = "${escapeHtml(username)}"\n// ? (2) = "${escapeHtml(password)}"`;
      explanation.innerHTML = `<strong>Mitigation:</strong> Parameterized queries compile the SQL command structure first. The database engine treats the input strictly as literal values in a separate data channel.`;
    }

  } catch (err) {
    alert('Request failed: ' + err.message);
  }
}

// Reset Database to Seed State
async function resetDb() {
  try {
    const res = await fetch('/api/reset-db', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('Database restored to initial seed state.');
      document.getElementById('authResultBox').style.display = 'none';
    }
  } catch (err) {
    alert('Database reset failed: ' + err.message);
  }
}

// Utility: HTML escaping & Query highlighting
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function highlightSql(query, userInput) {
  if (!query) return '';
  const escapedQuery = escapeHtml(query);
  const escapedInput = escapeHtml(userInput);
  if (escapedInput && escapedQuery.includes(escapedInput)) {
    return escapedQuery.replace(escapedInput, `<span class="injected">${escapedInput}</span>`);
  }
  return escapedQuery;
}
