const API = '/api';

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

async function loadOverview() {
  const res = await fetch(`${API}/overview`);
  const data = await res.json();
  const stats = data.stats;
  const period = data.period_stats;
  const grid = document.getElementById('period-stats');
  grid.innerHTML = [
    `<div class="stat-card"><div class="stat-label">Allowlist Entries</div><div class="stat-value">${stats.allowlist_entries}</div></div>`,
    `<div class="stat-card"><div class="stat-label">Network Events</div><div class="stat-value">${period.network_events_total}</div><div class="stat-sub">${period.network_events_flagged} flagged</div></div>`,
    `<div class="stat-card"><div class="stat-label">Alerts Fired</div><div class="stat-value">${period.alerts_total}</div><div class="stat-sub">${period.alerts_critical} critical, ${period.alerts_log_only} log-only</div></div>`,
    `<div class="stat-card"><div class="stat-label">Next Reset</div><div class="stat-value">${formatDuration(data.time_until_reset_seconds)}</div></div>`,
  ].join('');
}

function formatDuration(seconds) {
  if (seconds <= 0) return 'Now';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

async function loadPeriods() {
  const res = await fetch(`${API}/period_history`);
  const data = await res.json();
  const tbody = document.getElementById('periods-table');
  tbody.innerHTML = data.map(p => `<tr><td>${p.period_type}</td><td>${p.period_start}</td><td>${p.period_end}</td><td>${p.network_events_total}</td><td>${p.network_events_flagged}</td><td>${p.alerts_total}</td><td>${p.alerts_critical}</td><td>${p.alerts_log_only}</td></tr>`).join('');
}

async function loadAllowlist() {
  const res = await fetch(`${API}/allowlist`);
  const data = await res.json();
  const tbody = document.getElementById('allowlist-table');
  tbody.innerHTML = data.map(e => {
    const process = String(e.process_name || '').replace(/</g, '&lt;');
    const path = String(e.executable_path || '').replace(/</g, '&lt;');
    const signer = String(e.signer || '').replace(/</g, '&lt;');
    const firstSeen = String(e.first_seen || '').slice(0, 19);
    const btnName = String(e.process_name || '').replace(/"/g, '&quot;');
    return `<tr><td>${process}</td><td>${path}</td><td>${signer}</td><td>${firstSeen}</td><td>${e.connection_count || 0}</td><td><button class="btn btn-danger" data-remove-allowlist="${btnName}">Revoke</button></td></tr>`;
  }).join('');
}

async function removeAllowlist(name) {
  await fetch(`${API}/allowlist/remove`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ process_name: name }),
  });
  loadAllowlist();
}

document.addEventListener('click', e => {
  const btn = e.target.closest('button[data-remove-allowlist]');
  if (!btn) return;
  removeAllowlist(btn.getAttribute('data-remove-allowlist'));
});

async function loadEvents() {
  const params = new URLSearchParams({ limit: 50, offset: 0 });
  const process = document.getElementById('evt-process').value;
  const ip = document.getElementById('evt-ip').value;
  if (process) params.set('process_name', process);
  if (ip) params.set('remote_ip', ip);
  if (document.getElementById('evt-flagged').checked) params.set('flagged_only', '1');
  const res = await fetch(`${API}/network_events?${params}`);
  const data = await res.json();
  const tbody = document.getElementById('events-table');
  tbody.innerHTML = data.map(e => {
    const timestamp = String(e.timestamp || '').slice(0, 19);
    const processName = String(e.process_name || '').replace(/</g, '&lt;');
    const local = `${String(e.local_ip || '')}:${String(e.local_port || '')}`;
    const remote = `${String(e.remote_ip || '')}:${String(e.remote_port || '')}`;
    const protocol = String(e.protocol || '').replace(/</g, '&lt;');
    const status = String(e.status || '').replace(/</g, '&lt;');
    const flagged = e.is_flagged ? 'YES' : 'no';
    return `<tr><td>${timestamp}</td><td>${processName}</td><td>${local}</td><td>${remote}</td><td>${protocol}</td><td>${status}</td><td>${flagged}</td></tr>`;
  }).join('');
}

async function loadSnapshots() {
  const res = await fetch(`${API}/snapshots`);
  const data = await res.json();
  const tbody = document.getElementById('snapshots-table');
  tbody.innerHTML = data.map(s => {
    const encoded = encodeURIComponent(String(s.timestamp || ''));
    return `<tr><td>${s.timestamp}</td><td>${s.item_count}</td><td><button class="btn" data-view-snapshot="${encoded}">View</button></td></tr>`;
  }).join('');
}

async function viewSnapshot(timestamp) {
  const res = await fetch(`${API}/snapshots/${encodeURIComponent(timestamp)}`);
  const data = await res.json();
  alert(JSON.stringify(data, null, 2));
}

document.addEventListener('click', e => {
  const btn = e.target.closest('button[data-view-snapshot]');
  if (!btn) return;
  viewSnapshot(decodeURIComponent(btn.getAttribute('data-view-snapshot')));
});

async function loadAlerts() {
  const params = new URLSearchParams({ limit: 50, offset: 0 });
  const severity = document.getElementById('alert-severity').value;
  const type = document.getElementById('alert-type').value;
  if (severity) params.set('severity', severity);
  if (type) params.set('alert_type', type);
  const res = await fetch(`${API}/alerts?${params}`);
  const data = await res.json();
  const tbody = document.getElementById('alerts-table');
  tbody.innerHTML = data.map(a => {
    const timestamp = String(a.timestamp || '').slice(0, 19);
    const severityClass = String(a.severity || '') === 'critical' ? 'critical' : 'log-only';
    const alertType = String(a.alert_type || '').replace(/</g, '&lt;');
    const targetItem = String(a.target_item || '').replace(/</g, '&lt;');
    const message = String(a.message || '').replace(/</g, '&lt;');
    const resolution = String(a.resolution || 'Unresolved').replace(/</g, '&lt;');
    return `<tr><td>${timestamp}</td><td><span class="badge badge-${severityClass}">${a.severity}</span></td><td>${alertType}</td><td>${targetItem}</td><td>${message}</td><td>${resolution}</td></tr>`;
  }).join('');
}

async function loadApps() {
  const filter = document.getElementById('app-filter').value;
  const search = document.getElementById('app-search').value.toLowerCase();
  const res = await fetch(`${API}/apps`);
  const apps = await res.json();
  const filtered = apps.filter(a => {
    if (search && !String(a.name || '').toLowerCase().includes(search)) return false;
    if (filter === 'running' && a.status !== 'Running') return false;
    if (filter === 'trusted' && !a.trusted) return false;
    if (filter === 'protected' && !a.protected) return false;
    if (filter === 'unclassified' && (a.trusted || a.protected)) return false;
    return true;
  });
  const tbody = document.getElementById('apps-table');
  tbody.innerHTML = filtered.map(a => {
    const name = String(a.name || '').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    const publisher = String(a.publisher || '').replace(/</g, '&lt;');
    const encodedName = encodeURIComponent(String(a.name || ''));
    return `<tr><td>${name}</td><td>${publisher}</td><td>${a.status}</td><td><label class="toggle"><input type="checkbox" ${a.trusted ? 'checked' : ''} data-toggle-app="${encodedName}" data-toggle-type="trusted"><span class="slider"></span></label></td><td><label class="toggle"><input type="checkbox" ${a.protected ? 'checked' : ''} data-toggle-app="${encodedName}" data-toggle-type="protected" ${a.protected ? 'disabled' : ''}><span class="slider"></span></label></td></tr>`;
  }).join('');
}

async function toggleApp(encodedName, type, checked) {
  const name = decodeURIComponent(encodedName);
  await fetch(`${API}/apps/toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, type, checked }),
  });
  loadApps();
}

document.addEventListener('change', e => {
  const input = e.target.closest('input[data-toggle-app]');
  if (!input) return;
  toggleApp(input.getAttribute('data-toggle-app'), input.getAttribute('data-toggle-type'), input.checked);
});

function init() {
  loadOverview();
  loadPeriods();
  loadAllowlist();
  loadEvents();
  loadSnapshots();
  loadAlerts();
  loadApps();
}
init();
