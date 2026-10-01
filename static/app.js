const state = { dashboard: null, module: 'overview' };

const moduleLabels = {
  overview: 'Overview',
  'threat-intelligence': 'Threat intelligence',
  'attack-investigation': 'Attack investigation',
  'blockchain-explorer': 'Blockchain explorer',
  'node-management': 'Node management',
  'wallet-intelligence': 'Wallet intelligence',
  'incident-response': 'Incident response',
  'attack-dna': 'Attack DNA',
  'ai-copilot': 'AI copilot',
};

const actionLabels = {
  'run-scan': 'Run integrity scan',
  'isolate-wallet': 'Isolate wallet group',
  'freeze-node': 'Prepare node freeze',
  'escalate-incident': 'Escalate priority incident',
  'generate-report': 'Export security report',
};

const ANALYSIS_ENDPOINTS = {
  url: '/api/analyze/url',
  email: '/api/analyze/email',
  password: '/api/analyze/password',
};

const $ = (selector) => document.querySelector(selector);
const localHosts = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const isLocalFrontend = window.location.protocol === 'file:'
  || (localHosts.has(window.location.hostname) && window.location.port !== '8000');
const API_BASE = isLocalFrontend ? 'http://127.0.0.1:8000' : '';
const apiUrl = (path) => `${API_BASE}${path}`;

function describeFetchError(error) {
  if (error instanceof TypeError && error.message === 'Failed to fetch') {
    return 'Backend is not running. Please start the CyberSathi backend with "start.bat" or "uvicorn app.main:app --reload".';
  }
  return error.message;
}

async function readJsonResponse(response) {
  const body = await response.text();
  if (!body.trim()) throw new Error(`Server returned an empty response (HTTP ${response.status})`);
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`Server returned invalid JSON (HTTP ${response.status})`);
  }
}

function setStatus(message, tone = 'info') {
  $('#statusText').textContent = message;
  $('#statusBanner').className = `status-banner ${tone}`;
}

function showToast(message, tone = 'success') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast ${tone}`;
  window.setTimeout(() => toast.classList.add('hidden'), 4200);
}

function setLoading(isLoading) {
  document.body.classList.toggle('is-loading', isLoading);
}

function renderTrend(trend) {
  $('#trendChart').innerHTML = trend.values.map((value) => `<div class="bar-wrap"><span class="bar-value">${value}</span><div class="trend-bar" style="height:${value}%"></div></div>`).join('');
  $('#trendLabels').innerHTML = trend.labels.map((label) => `<span>${label}</span>`).join('');
}

function renderSignals(signals, selector = '#signalList') {
  $(selector).innerHTML = signals.map((signal) => `<div class="signal-item"><div class="signal-row"><strong>${signal.name}</strong><span>${signal.score}%</span></div><div class="progress"><span style="width:${signal.score}%"></span></div><small>${signal.detail}</small></div>`).join('');
}

function renderNodes(nodes) {
  $('#nodeList').innerHTML = nodes.map((node) => `<div class="node-row"><div class="node-name"><span class="node-status ${node.status.toLowerCase()}"></span><div><strong>${node.name}</strong><small>${node.role}</small></div></div><div class="node-health"><strong>${node.health}%</strong><small>${node.latency}</small></div></div>`).join('');
}

function renderIncidents(incidents) {
  $('#incidentList').innerHTML = incidents.map((incident) => `<button class="incident-row" data-action="escalate-incident" data-target="${incident.id}"><div><span class="incident-id">${incident.id}</span><strong>${incident.title}</strong><small>${incident.owner} · ${incident.age}</small></div><span class="severity ${incident.severity.toLowerCase()}">${incident.severity}</span></button>`).join('');
  bindActionButtons();
}

function renderDashboard(data) {
  state.dashboard = data;
  const summary = data.summary;
  $('#threatLevel').textContent = summary.threat_level;
  $('#securityScore').textContent = summary.security_score;
  $('#blockchainHealth').textContent = `${summary.blockchain_health}%`;
  $('#predictionConfidence').textContent = `${summary.prediction_confidence}%`;
  $('#liveNodes').textContent = summary.live_nodes;
  $('#activeIncidents').textContent = summary.active_incidents;
  $('#flaggedWallets').textContent = summary.flagged_wallets;
  $('#monitoredWallets').textContent = summary.monitored_wallets;
  $('#briefCopy').textContent = data.executive_brief;
  $('#lastSync').textContent = `Synced ${new Date(data.generated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  $('#statusText').textContent = `Telemetry verified · ${summary.active_incidents} incidents require review`;
  renderTrend(data.risk_trend);
  renderSignals(data.signals);
  renderNodes(data.nodes);
  renderIncidents(data.incidents);
}

async function loadDashboard() {
  setLoading(true);
  try {
    let response = await fetch(apiUrl('/api/dashboard'), { cache: 'no-store' });
    if (!response.ok) {
      const dashboardError = await readJsonResponse(response).catch((error) => ({ detail: error.message }));
      response = await fetch(apiUrl('/api/telemetry'), { cache: 'no-store' });
      if (!response.ok) {
        const telemetryError = await readJsonResponse(response).catch((error) => ({ detail: error.message }));
        throw new Error(`Dashboard HTTP ${response.status}: ${telemetryError.detail || dashboardError.detail}`);
      }
      const legacyData = await readJsonResponse(response);
      renderDashboard(legacyData);
      setStatus(`Compatibility telemetry loaded · dashboard endpoint unavailable (${dashboardError.detail})`, 'warning');
      return;
    }
    renderDashboard(await readJsonResponse(response));
  } catch (error) {
    setStatus(`Unable to load telemetry · ${describeFetchError(error)}`, 'error');
  } finally {
    setLoading(false);
  }
}

async function openModule(moduleId) {
  state.module = moduleId;
  document.querySelectorAll('[data-module]').forEach((item) => item.classList.toggle('active', item.dataset.module === moduleId));
  $('#breadcrumb').textContent = moduleLabels[moduleId] || 'Overview';
  $('#pageTitle').textContent = moduleLabels[moduleId] || 'Command center';
  $('#sidebar').classList.remove('open');
  if (moduleId === 'overview') {
    $('#overviewView').classList.remove('hidden');
    $('#moduleView').classList.add('hidden');
    return;
  }
  try {
    const response = await fetch(apiUrl(`/api/modules/${moduleId}`));
    if (!response.ok) throw new Error('Module data unavailable');
    const result = await readJsonResponse(response);
    $('#overviewView').classList.add('hidden');
    $('#moduleView').classList.remove('hidden');
    $('#moduleEyebrow').textContent = result.module.eyebrow;
    $('#moduleTitle').textContent = result.module.label;
    $('#moduleDescription').textContent = result.module.description;
    $('#moduleMetrics').innerHTML = Object.entries(result.metrics).map(([key, value]) => `<div class="module-metric"><span>${key.replaceAll('_', ' ')}</span><strong>${value}${key.includes('confidence') || key.includes('integrity') ? '%' : ''}</strong></div>`).join('');
    renderSignals(result.signals, '#moduleSignals');
    $('#moduleActions').innerHTML = result.module.actions.map((action) => `<button class="action-card" data-action="${action}"><span>${action === 'generate-report' ? '↗' : '◎'}</span><div><strong>${actionLabels[action]}</strong><small>Execute with current evidence</small></div><b>→</b></button>`).join('');
    bindActionButtons();
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

async function executeAction(action, target = null) {
  if (action === 'generate-report') return downloadReport();
  try {
    const response = await fetch(apiUrl('/api/actions'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, target }) });
    const result = await readJsonResponse(response);
    if (!response.ok) throw new Error(result.detail || 'Action rejected');
    const scanMessage = result.scan ? ` Score ${result.scan.security_score}/100 · ${result.scan.findings} finding(s). ${result.scan.finding_summary}` : result.detail;
    showToast(`${result.title}: ${scanMessage}`);
    setStatus(`${result.title} · audit event recorded`, 'success');
  } catch (error) {
    showToast(error.message, 'error');
    setStatus(`Action failed · ${error.message}`, 'error');
  }
}

function bindActionButtons() {
  document.querySelectorAll('[data-action]').forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => executeAction(button.dataset.action, button.dataset.target || null));
  });
}

async function downloadReport() {
  try {
    const response = await fetch(apiUrl('/api/report'));
    if (!response.ok) throw new Error('Report service unavailable');
    const report = await readJsonResponse(response);
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    link.download = 'cybersathi-blockchain-security-report.json';
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Security report exported successfully');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function downloadPdfReport() {
  try {
    const response = await fetch(apiUrl('/api/report.pdf'));
    if (!response.ok) throw new Error(`PDF service returned HTTP ${response.status}`);
    const link = document.createElement('a');
    link.href = URL.createObjectURL(await response.blob());
    link.download = 'cybersathi-security-report.pdf';
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Graphical PDF report exported successfully');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function addShraviMessage(text, role) {
  const message = document.createElement('div');
  message.className = `shravi-message ${role}`;
  message.textContent = text;
  $('#shraviMessages').appendChild(message);
  $('#shraviMessages').scrollTop = $('#shraviMessages').scrollHeight;
}

function addShraviResult(result) {
  const card = document.createElement('div');
  card.className = 'shravi-result assistant';
  const evidence = result.evidence.map((item) => `<li>${item}</li>`).join('');
  const nextSteps = result.next_steps.map((item) => `<li>${item}</li>`).join('');
  card.innerHTML = `<div class="shravi-result-top"><span>${result.intent}</span><b>${result.confidence} confidence</b></div><p>${result.answer}</p><div class="shravi-result-grid"><div><small>Evidence</small><ul>${evidence}</ul></div><div><small>Next steps</small><ul>${nextSteps}</ul></div></div>`;
  if (result.suggested_action) {
    const action = document.createElement('button');
    action.className = 'shravi-action';
    action.textContent = `Run ${actionLabels[result.suggested_action]}`;
    action.addEventListener('click', () => executeAction(result.suggested_action));
    card.appendChild(action);
  }
  $('#shraviMessages').appendChild(card);
  $('#shraviMessages').scrollTop = $('#shraviMessages').scrollHeight;
}

async function askShravi(message) {
  addShraviMessage(message, 'user');
  try {
    const response = await fetch(apiUrl('/api/chat'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message }) });
    const result = await readJsonResponse(response);
    if (!response.ok) throw new Error(result.detail || 'Assistant unavailable');
    addShraviResult(result);
  } catch (error) {
    addShraviMessage(`I could not reach the security service: ${error.message}`, 'assistant');
  }
}

function renderAnalysisResult(container, result) {
  container.replaceChildren();
  container.classList.remove('hidden');
  const heading = document.createElement('div');
  heading.className = 'analysis-result-heading';
  heading.textContent = `${result.risk_level.toUpperCase()} risk · score ${result.score}/100`;
  container.appendChild(heading);
  const summary = document.createElement('p');
  summary.textContent = result.summary;
  container.appendChild(summary);
  const findings = document.createElement('ul');
  result.findings.forEach((finding) => {
    const item = document.createElement('li');
    item.textContent = finding;
    findings.appendChild(item);
  });
  container.appendChild(findings);
  if (result.recommendations.length) {
    const recommendations = document.createElement('p');
    recommendations.textContent = `Next step: ${result.recommendations[0]}`;
    container.appendChild(recommendations);
  }
}

async function submitAnalysis(form) {
  const type = form.dataset.analysisType;
  const input = form.elements[type];
  const button = form.querySelector('.analysis-submit');
  const status = form.querySelector('.analysis-status');
  const resultContainer = form.querySelector('.analysis-result');
  button.disabled = true;
  status.className = 'analysis-status loading';
  status.textContent = 'Checking locally...';
  resultContainer.classList.add('hidden');
  try {
    const response = await fetch(apiUrl(ANALYSIS_ENDPOINTS[type]), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [type]: input.value }),
    });
    const result = await readJsonResponse(response);
    if (!response.ok) {
      const detail = Array.isArray(result.detail)
        ? result.detail.map((item) => item.msg || 'Invalid input').join('; ')
        : result.detail;
      throw new Error(detail || 'Analysis request was rejected');
    }
    renderAnalysisResult(resultContainer, result);
    status.className = 'analysis-status success';
    status.textContent = 'Analysis complete.';
  } catch (error) {
    status.className = 'analysis-status error';
    status.textContent = `Analysis unavailable · ${describeFetchError(error)}`;
  } finally {
    button.disabled = false;
  }
}

function toggleCommandPalette(force) {
  const modal = $('#commandModal');
  modal.classList.toggle('hidden', force === undefined ? !modal.classList.contains('hidden') : !force);
  if (!modal.classList.contains('hidden')) $('#commandInput').focus();
}

function applyTheme(theme) {
  document.body.classList.toggle('light-theme', theme === 'light');
  localStorage.setItem('cybersathi-theme', theme);
}

document.addEventListener('DOMContentLoaded', async () => {
  applyTheme(localStorage.getItem('cybersathi-theme') || 'dark');
  document.querySelectorAll('[data-module]').forEach((button) => button.addEventListener('click', () => openModule(button.dataset.module)));
  $('#themeToggle').addEventListener('click', () => applyTheme(document.body.classList.contains('light-theme') ? 'dark' : 'light'));
  $('#reportButton').addEventListener('click', downloadReport);
  $('#pdfButton').addEventListener('click', downloadPdfReport);
  $('#commandToggle').addEventListener('click', () => toggleCommandPalette(true));
  $('#closeCommand').addEventListener('click', () => toggleCommandPalette(false));
  $('#commandModal').addEventListener('click', (event) => { if (event.target.id === 'commandModal') toggleCommandPalette(false); });
  $('#menuToggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#shraviLauncher').addEventListener('click', () => { $('#shraviPanel').classList.remove('hidden'); $('#shraviInput').focus(); });
  $('#closeShravi').addEventListener('click', () => $('#shraviPanel').classList.add('hidden'));
  $('#shraviForm').addEventListener('submit', (event) => { event.preventDefault(); const input = $('#shraviInput'); const message = input.value.trim(); if (!message) return; input.value = ''; askShravi(message); });
  document.querySelectorAll('[data-shravi-prompt]').forEach((button) => button.addEventListener('click', () => askShravi(button.dataset.shraviPrompt)));
  document.querySelectorAll('.analysis-card').forEach((form) => form.addEventListener('submit', (event) => { event.preventDefault(); submitAnalysis(form); }));
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); toggleCommandPalette(true); }
    if (event.key === 'Escape') toggleCommandPalette(false);
  });
  bindActionButtons();
  await loadDashboard();
  window.setInterval(loadDashboard, 30000);
});
