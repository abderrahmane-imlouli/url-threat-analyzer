// ===========================
// SCAN FLOW
// ===========================

async function startScan() {
  const input = document.getElementById('urlInput');
  const errorEl = document.getElementById('inputError');
  let url = input.value.trim();

  // Basic validation
  if (!url) {
    showInputError('Please enter a URL');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
    input.value = url;
  }

  hideInputError();
  showProgress();

  try {
    setProgress(10, 1, 'Running static analysis...');
    await delay(300);
    setProgress(25, 2, 'Querying WHOIS...');
    await delay(200);
    setProgress(40, 3, 'Resolving DNS...');
    await delay(200);
    setProgress(55, 4, 'Scanning with VirusTotal...');

    // Start the actual API call
    const fetchPromise = fetchScan(url);

    setProgress(70, 5, 'Waiting for urlscan.io sandbox (30-60s)...');

    const data = await fetchPromise;
    setProgress(100, 5, 'Scan complete!');

    await delay(400);
    hideProgress();
    renderResults(data);

  } catch (err) {
    hideProgress();
    showInputError('Scan failed: ' + err.message);
    document.getElementById('scanBtn').disabled = false;
  }
}

async function fetchScan(url) {
  const resp = await fetch('/api/scan/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  if (!resp.ok) throw new Error(`Server error ${resp.status}`);
  return resp.json();
}

function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function resetScan() {
  document.getElementById('resultsSection').classList.add('hidden');
  document.getElementById('urlInput').value = '';
  document.getElementById('urlInput').focus();
  document.getElementById('scanBtn').disabled = false;
}

// ===========================
// PROGRESS UI
// ===========================

function showProgress() {
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('progressSection').classList.remove('hidden');
  document.getElementById('resultsSection').classList.add('hidden');
  // Reset steps
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById('step' + i);
    el.classList.remove('active', 'done');
  }
}

function hideProgress() {
  document.getElementById('progressSection').classList.add('hidden');
}

function setProgress(pct, activeStep, msg) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressMsg').textContent = msg;

  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById('step' + i);
    el.classList.remove('active', 'done');
    if (i < activeStep) el.classList.add('done');
    else if (i === activeStep) el.classList.add('active');
  }
}

// ===========================
// RESULTS RENDERING
// ===========================

function renderResults(data) {
  document.getElementById('resultsSection').classList.remove('hidden');

  renderThreatBanner(data);
  renderStatic(data.static);
  renderWhois(data.whois);
  renderDns(data.dns);
  renderVirusTotal(data.virustotal);
  renderUrlscan(data.urlscan);

  document.getElementById('scanBtn').disabled = false;
}

// ── Threat Banner ──────────────────────────────────────
function renderThreatBanner(data) {
  const banner = document.getElementById('threatBanner');
  const vt = data.virustotal;
  const us = data.urlscan;

  let level = 'low';
  let msg = '✅ URL appears CLEAN — No major threats detected';

  if (vt && vt.status === 'success') {
    if (vt.threat_level === 'high') { level = 'high'; msg = '🚨 HIGH RISK — Multiple engines flagged this URL as MALICIOUS'; }
    else if (vt.threat_level === 'medium') { level = 'medium'; msg = '⚠️ MEDIUM RISK — Some suspicious activity detected'; }
  }

  if (us && us.status === 'success' && us.malicious && level !== 'high') {
    level = 'high';
    msg = '🚨 HIGH RISK — urlscan.io marked this URL as MALICIOUS';
  }

  banner.className = 'threat-banner ' + level;
  banner.innerHTML = `<span>${msg}</span><span style="margin-left:auto;font-size:0.7rem;opacity:0.6;">${data.timestamp}</span>`;
}

// ── Static Analysis ────────────────────────────────────
function renderStatic(items) {
  const el = document.getElementById('staticBody');
  el.innerHTML = '';
  if (!items || !items.length) { el.innerHTML = errorCard('No data'); return; }

  items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'result-item ' + (item.type || 'info');
    const icons = { error: '❌', warning: '⚠️', safe: '✅', info: 'ℹ️' };
    div.textContent = (icons[item.type] || '•') + '  ' + item.message;
    el.appendChild(div);
  });
}

// ── WHOIS ──────────────────────────────────────────────
function renderWhois(items) {
  const el = document.getElementById('whoisBody');
  el.innerHTML = '';
  if (!items || !items.length) { el.innerHTML = errorCard('No data'); return; }

  const data = items[0];

  if (data.status === 'error') {
    el.innerHTML = errorCard(data.message);
    return;
  }

  const rows = [
    ['DOMAIN',      data.domain,          'accent'],
    ['REGISTRAR',   data.registrar,        ''],
    ['CREATED',     data.creation_date,    ''],
    ['EXPIRES',     data.expiration_date,  ''],
    ['COUNTRY',     data.country,          ''],
  ];

  rows.forEach(([k, v, cls]) => {
    el.appendChild(kvRow(k, v || 'N/A', cls));
  });

  if (data.age_warning) {
    const warn = document.createElement('div');
    warn.className = 'result-item warning';
    warn.style.marginTop = '0.5rem';
    warn.textContent = data.age_warning;
    el.appendChild(warn);
  }

  if (data.name_servers && data.name_servers.length) {
    const ns = document.createElement('div');
    ns.className = 'kv-row';
    ns.innerHTML = `<span class="kv-key">NAME SERVERS</span>
      <span class="kv-val" style="font-family:var(--mono);font-size:0.72rem;">
        ${[...data.name_servers].slice(0,3).join('<br>')}
      </span>`;
    el.appendChild(ns);
  }
}

// ── DNS ────────────────────────────────────────────────
function renderDns(data) {
  const el = document.getElementById('dnsBody');
  el.innerHTML = '';
  if (!data) { el.innerHTML = errorCard('No data'); return; }

  if (data.status === 'error') {
    el.innerHTML = errorCard(data.message);
    return;
  }

  el.appendChild(kvRow('DOMAIN', data.domain, 'accent'));
  el.appendChild(kvRow('RESOLVED IP', data.ip, 'accent'));
}

// ── VirusTotal ─────────────────────────────────────────
function renderVirusTotal(data) {
  const el = document.getElementById('vtBody');
  el.innerHTML = '';
  if (!data) { el.innerHTML = errorCard('No data'); return; }

  if (data.status === 'error') {
    el.innerHTML = errorCard(data.message);
    return;
  }

  // Stats grid
  const stats = document.createElement('div');
  stats.className = 'vt-stats';
  const cols = [
    { label: 'MALICIOUS',  num: data.malicious,  color: data.malicious  > 0 ? 'var(--danger)'  : 'var(--safe)' },
    { label: 'SUSPICIOUS', num: data.suspicious, color: data.suspicious > 0 ? 'var(--warning)' : 'var(--safe)' },
    { label: 'HARMLESS',   num: data.harmless,   color: 'var(--safe)' },
    { label: 'UNDETECTED', num: data.undetected, color: 'var(--text-dim)' },
  ];
  cols.forEach(c => {
    stats.innerHTML += `
      <div class="vt-stat">
        <div class="vt-stat-num" style="color:${c.color}">${c.num}</div>
        <div class="vt-stat-label">${c.label}</div>
      </div>`;
  });
  el.appendChild(stats);

  // Threat level
  const tlColors = { high: 'danger', medium: 'warning', low: 'safe' };
  el.appendChild(kvRow('THREAT LEVEL', data.threat_level.toUpperCase(), tlColors[data.threat_level]));

  // External link
  if (data.vt_link) {
    const linkRow = document.createElement('div');
    linkRow.style.marginTop = '0.8rem';
    linkRow.innerHTML = `<a class="ext-link" href="${data.vt_link}" target="_blank" rel="noopener">
      ↗ VIEW FULL REPORT ON VIRUSTOTAL
    </a>`;
    el.appendChild(linkRow);
  }
}

// ── urlscan.io ─────────────────────────────────────────
function renderUrlscan(data) {
  const el = document.getElementById('urlscanBody');
  el.innerHTML = '';
  if (!data) { el.innerHTML = errorCard('No data'); return; }

  if (data.status === 'error') {
    el.innerHTML = errorCard(data.message);
    return;
  }

  const layout = document.createElement('div');
  layout.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:1rem;';

  // Left: info
  const left = document.createElement('div');
  const verdict = data.malicious;
  left.appendChild(kvRow('VERDICT',       verdict ? 'MALICIOUS' : 'CLEAN',   verdict ? 'danger' : 'safe'));
  left.appendChild(kvRow('SCORE',         data.score ?? 'N/A',              data.score > 50 ? 'danger' : 'safe'));
  left.appendChild(kvRow('FINAL URL',     truncate(data.final_url, 45),     'accent'));
  left.appendChild(kvRow('SERVER',        data.server || 'N/A',             ''));
  left.appendChild(kvRow('IP',            data.ip || 'N/A',                 ''));
  left.appendChild(kvRow('COUNTRY',       data.country || 'N/A',            ''));
  left.appendChild(kvRow('REQUESTS',      data.total_requests ?? 'N/A',     ''));

  if (data.categories && data.categories.length) {
    const tags = document.createElement('div');
    tags.style.marginTop = '0.6rem';
    data.categories.forEach(c => {
      tags.innerHTML += `<span class="tag">${c}</span>`;
    });
    left.appendChild(tags);
  }

  if (data.report_url) {
    const link = document.createElement('div');
    link.style.marginTop = '1rem';
    link.innerHTML = `<a class="ext-link" href="${data.report_url}" target="_blank" rel="noopener">
      ↗ FULL REPORT ON URLSCAN.IO
    </a>`;
    left.appendChild(link);
  }

  // Right: screenshot
  const right = document.createElement('div');
  if (data.screenshot_url) {
    right.innerHTML = `
      <div style="font-family:var(--mono);font-size:0.68rem;color:var(--text-dim);letter-spacing:0.1em;margin-bottom:0.4rem;">SCREENSHOT</div>
      <div class="screenshot-wrap">
        <img src="${data.screenshot_url}" alt="Screenshot" onload="this.classList.add('loaded')" />
      </div>`;
  } else {
    right.innerHTML = `<div style="color:var(--text-dim);font-family:var(--mono);font-size:0.8rem;">No screenshot available</div>`;
  }

  layout.appendChild(left);
  layout.appendChild(right);
  el.appendChild(layout);
}

// ===========================
// HELPERS
// ===========================

function kvRow(key, val, cls) {
  const div = document.createElement('div');
  div.className = 'kv-row';
  div.innerHTML = `<span class="kv-key">${key}</span>
    <span class="kv-val ${cls ? cls : ''}">${val}</span>`;
  return div;
}

function errorCard(msg) {
  return `<div class="error-card">⚠ ${msg}</div>`;
}

function truncate(str, n) {
  if (!str) return 'N/A';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

function showInputError(msg) {
  const el = document.getElementById('inputError');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideInputError() {
  document.getElementById('inputError').classList.add('hidden');
}

// Enter key support
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
