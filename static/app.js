/* ARC Blast Shield — front-end: upload, run, poll, approve, render. */
let runId = null;
let pollTimer = null;
let lastEventCount = 0;

const $ = (id) => document.getElementById(id);

async function health() {
  try {
    const r = await fetch('/api/health');
    const h = await r.json();
    $('health').textContent =
      `Backend OK · LLM: ${h.llm_mode} (${h.model}) · sandbox: ${h.sandbox ? 'ready' : 'NOT READY'}`;
    $('health').style.color = h.sandbox ? '#7ddf8e' : '#f08080';
  } catch (e) {
    $('health').textContent = 'Backend unreachable — is the server running?';
    $('health').style.color = '#f08080';
  }
}

async function uploadFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch('/api/upload', { method: 'POST', body: fd });
  const j = await r.json();
  if (j.error) { alert(j.error); return; }
  runId = j.run_id;
  $('fileinfo').textContent = `Loaded ${j.filename} (${j.bytes} bytes) — ready to run.`;
  $('run').disabled = false;
}

$('file').addEventListener('change', (e) => {
  if (e.target.files[0]) uploadFile(e.target.files[0]);
});
const drop = $('drop');
drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', (e) => {
  e.preventDefault(); drop.classList.remove('over');
  if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
});
$('sample').addEventListener('click', async () => {
  const r = await fetch('/static/sample_data.csv');
  const blob = await r.blob();
  uploadFile(new File([blob], 'sample_data.csv', { type: 'text/csv' }));
});

$('run').addEventListener('click', async () => {
  if (!runId) return;
  $('run').disabled = true;
  $('results').hidden = true;
  $('log').innerHTML = '';
  lastEventCount = 0;
  const mode = document.querySelector('input[name=mode]:checked').value;
  await fetch('/api/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_id: runId, task: $('task').value, policy_mode: mode }),
  });
  pollTimer = setInterval(poll, 1000);
});

async function poll() {
  const r = await fetch('/api/run/' + runId);
  const j = await r.json();
  for (let i = lastEventCount; i < j.events.length; i++) {
    const ev = j.events[i];
    const cls = ev.kind === 'deny' || ev.kind === 'contain' ? 'deny'
      : ev.kind === 'error' ? 'err'
      : ev.kind === 'approval' ? 'allow' : '';
    const div = document.createElement('div');
    div.className = cls;
    div.textContent = `[${ev.ts}] ${ev.kind.toUpperCase()} ${ev.text}`;
    $('log').appendChild(div);
    if (ev.kind === 'approval' && ev.data && ev.data.pending) {
      $('approval-text').textContent = ev.data.action + ' — ' + ev.data.detail;
      const code = (j.results && j.results.code_pending) || '';
      $('approval-code').textContent = code;
      $('approval-card').hidden = false;
    }
  }
  lastEventCount = j.events.length;
  $('log').scrollTop = $('log').scrollHeight;
  if (j.status === 'awaiting_approval') $('approval-card').hidden = false;
  else if (j.status !== 'running' && j.status !== 'starting') {
    $('approval-card').hidden = true;
  }
  if (j.status === 'done' || j.status === 'failed' || j.status === 'denied') {
    clearInterval(pollTimer);
    $('run').disabled = false;
    renderResults(j);
  }
}

function renderResults(j) {
  $('results').hidden = false;
  $('llm-mode').textContent = `Analyst: ${j.results.llm_mode || '?'} (${j.results.model || ''}) · policy mode recorded in the ledger below.`;
  $('summary').textContent = j.results.summary || '(no summary — run did not complete)';
  $('stats').textContent = JSON.stringify(j.results.stats || {}, null, 2);
  const charts = $('charts');
  charts.innerHTML = '';
  (j.results.charts || []).forEach((name) => {
    const img = document.createElement('img');
    img.src = '/api/artifact/' + runId + '/' + name;
    img.alt = name;
    charts.appendChild(img);
  });
  const c = j.results.containment || {};
  $('containment').textContent = (c.lines || []).join('\n') ||
    '(containment probe did not run)';
  $('ledger').textContent = (j.ledger || [])
    .map((e) => `[${e.ts}] ${e.decision} ${e.action} — ${e.reason}`).join('\n');
}

$('approve').addEventListener('click', () => answerApproval(true));
$('deny').addEventListener('click', () => answerApproval(false));

async function answerApproval(approved) {
  await fetch('/api/approve', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ run_id: runId, approved }),
  });
  $('approval-card').hidden = true;
}

health();
