(function () {
  let CONFIG = null;
  let CURRENT_VENDOR = null;
  let CURRENT_ROLE = 'internet-facing';
  let ROWS = [];
  let EXPANDED = new Set();
  let sortKey = 'default';
  let sortDir = 'asc';
  let showInactive = false;
  let riskOn = true;
  let INVENTORY = null;
  let activeTab = 'rules';
  let INV_EXPANDED = new Set();
  let GROUP_OPEN = new Set();

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const dropZoneContainer = document.getElementById('dropZoneContainer');
  const resultsContainer = document.getElementById('resultsContainer');
  const headerActions = document.getElementById('headerActions');
  const loadNewBtn = document.getElementById('loadNewBtn');
  const exportBtn = document.getElementById('exportBtn');
  const tbody = document.getElementById('ruleTableBody');
  const summaryEl = document.getElementById('summary');
  const filterBand = document.getElementById('filterBand');
  const filterAction = document.getElementById('filterAction');
  const filterImplicit = document.getElementById('filterImplicit');
  const filterLogging = document.getElementById('filterLogging');
  const showInactiveToggle = document.getElementById('showInactiveToggle');
  const roleSelect = document.getElementById('roleSelect');
  const filterPolicy = document.getElementById('filterPolicy');
  const riskToggle = document.getElementById('riskToggle');
  const tabBar = document.getElementById('tabBar');
  const rulesView = document.getElementById('rulesView');
  const inventoryView = document.getElementById('inventoryView');
  const invBody = document.getElementById('invBody');
  const invSearch = document.getElementById('invSearch');
  const searchBox = document.getElementById('searchBox');
  const footerNote = document.getElementById('footerNote');
  const fileInfoName = document.getElementById('fileInfoName');
  const fileInfoSub = document.getElementById('fileInfoSub');

  // ---- file loading ----
  browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) handleFile(e.target.files[0]);
  });
  loadNewBtn.addEventListener('click', () => {
    dropZoneContainer.style.display = '';
    resultsContainer.style.display = 'none';
    headerActions.style.display = 'none';
    fileInput.value = '';
    fileInfoName.textContent = '';
    fileInfoSub.textContent = '';
  });

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        processConfig(e.target.result, file);
      } catch (err) {
        alert('Failed to parse config: ' + err.message);
        console.error(err);
      }
    };
    reader.readAsText(file);
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function renderFileInfo(file, config, ruleCount) {
    fileInfoName.textContent = file.name;
    fileInfoName.title = file.name;
    const parts = [];
    if (CURRENT_VENDOR) parts.push(CURRENT_VENDOR.label);
    if (typeof file.size === 'number') parts.push(formatFileSize(file.size));
    const ifaceCount = Object.keys(config.interfaces || {}).length;
    parts.push(`${ifaceCount} interface${ifaceCount === 1 ? '' : 's'}`);
    parts.push(`${ruleCount} rule${ruleCount === 1 ? '' : 's'} analyzed`);
    fileInfoSub.innerHTML = parts.map(p => escapeHtml(p)).join('<span class="sep">&middot;</span>');
  }

  function processConfig(text, file) {
    const vendor = detectVendor(text);
    if (!vendor) {
      throw new Error('Could not recognize this file as a supported firewall config (Cisco ASA or FortiOS/FortiGate).');
    }
    CURRENT_VENDOR = vendor;
    CONFIG = vendor.parse(text);
    CURRENT_ROLE = vendor.detectRole ? vendor.detectRole(CONFIG) : 'internet-facing';
    if (roleSelect) roleSelect.value = CURRENT_ROLE;
    ROWS = vendor.buildRuleset(CONFIG, { firewallRole: CURRENT_ROLE });
    INVENTORY = vendor.buildInventory ? vendor.buildInventory(CONFIG, { firewallRole: CURRENT_ROLE }) : null;
    INV_EXPANDED = new Set();
    GROUP_OPEN = new Set();
    tabBar.style.display = INVENTORY ? '' : 'none';
    document.getElementById('inventoryTabBtn').textContent = INVENTORY ? INVENTORY.title : '';
    EXPANDED = new Set();
    sortKey = 'default';
    sortDir = 'asc';
    dropZoneContainer.style.display = 'none';
    resultsContainer.style.display = '';
    headerActions.style.display = 'flex';
    if (file) renderFileInfo(file, CONFIG, ROWS.filter(r => r.type === 'rule').length);
    renderSummary();
    markSortedHeader();
    renderTable();
    setTab('rules');
  }

  // ---- summary strip ----
  function renderSummary() {
    // Active (non-inactive) rules are what the firewall actually enforces, so the
    // summary strip counts those - inactive ACEs are visible in the table (when the
    // "Show inactive" toggle is on) but don't factor into these headline stats.
    const ruleRows = ROWS.filter(r => r.type === 'rule' && !r.inactive);
    const bands = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
    let implicitCount = 0;
    let unloggedCount = 0;
    let againstOpen = 0;
    let exceptions = 0;
    for (const r of ruleRows) {
      bands[r.scored.band.label] = (bands[r.scored.band.label] || 0) + 1;
      if (r.implicit) implicitCount++;
      if (r.scored.logging.flagged) unloggedCount++;
      const ev = effectiveVerdict(r);
      if (ev.state === 'open') againstOpen++;
      else if (ev.state === 'exception') exceptions++;
    }
    summaryEl.innerHTML = `
      <div class="cell"><div class="n">${ruleRows.length}</div><div class="l">Total rules</div></div>
      <div class="cell crit risk-only"><div class="n">${bands.Critical}</div><div class="l">Critical</div></div>
      <div class="cell high risk-only"><div class="n">${bands.High}</div><div class="l">High</div></div>
      <div class="cell med risk-only"><div class="n">${bands.Medium}</div><div class="l">Medium</div></div>
      <div class="cell low risk-only"><div class="n">${bands.Low}</div><div class="l">Low</div></div>
      <div class="cell risk-only"><div class="n" style="color:${againstOpen ? 'var(--c-critical)' : 'var(--text-bright)'}">${againstOpen}</div><div class="l">Against policy</div></div>
      <div class="cell risk-only"><div class="n" style="color:${exceptions ? 'var(--c-high)' : 'var(--text-bright)'}">${exceptions}</div><div class="l">Exceptions</div></div>
      <div class="cell"><div class="n" style="color:${implicitCount ? 'var(--c-critical)' : 'var(--text-bright)'}">${implicitCount}</div><div class="l">Implicit permits</div></div>
      <div class="cell"><div class="n" style="color:${unloggedCount ? 'var(--c-medium)' : 'var(--text-bright)'}">${unloggedCount}</div><div class="l">No logging</div></div>
    `;
  }

  // ---- sorting ----
  const resetOrderBtn = document.getElementById('resetOrderBtn');

  function markSortedHeader() {
    document.querySelectorAll('#ruleTable thead th').forEach(t => t.classList.remove('sorted', 'asc'));
    if (sortKey === 'default') {
      const th = document.querySelector('#ruleTable thead th[data-sort="ruleNumber"]');
      if (th) th.classList.add('sorted');
    } else {
      const th = document.querySelector(`#ruleTable thead th[data-sort="${sortKey}"]`);
      if (th) { th.classList.add('sorted'); if (sortDir === 'asc') th.classList.add('asc'); }
    }
    if (resetOrderBtn) resetOrderBtn.style.display = sortKey === 'default' ? 'none' : '';
  }

  document.querySelectorAll('#ruleTable thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) sortDir = sortDir === 'desc' ? 'asc' : 'desc';
      else { sortKey = key; sortDir = key === 'score' ? 'desc' : 'asc'; }
      markSortedHeader();
      renderTable();
    });
  });

  if (resetOrderBtn) {
    resetOrderBtn.addEventListener('click', () => {
      sortKey = 'default';
      sortDir = 'asc';
      markSortedHeader();
      renderTable();
    });
  }

  filterBand.addEventListener('change', renderTable);
  filterAction.addEventListener('change', renderTable);
  filterImplicit.addEventListener('change', renderTable);
  filterLogging.addEventListener('change', renderTable);
  if (filterPolicy) filterPolicy.addEventListener('change', renderTable);
  if (roleSelect) {
    // Changing the firewall role re-scores every rule (direction-aware
    // exposure), so rebuild the ruleset from the already-parsed config and
    // re-render — no re-parse needed.
    roleSelect.addEventListener('change', () => {
      if (!CONFIG || !CURRENT_VENDOR) return;
      CURRENT_ROLE = roleSelect.value;
      ROWS = CURRENT_VENDOR.buildRuleset(CONFIG, { firewallRole: CURRENT_ROLE });
      EXPANDED = new Set();
      renderSummary();
      renderTable();
    });
  }
  if (riskToggle) {
    // Pure presentation switch: scores stay computed, so flipping back is
    // instant. Hides every scoring-dependent element via body.no-risk.
    riskToggle.addEventListener('change', () => {
      riskOn = riskToggle.checked;
      document.body.classList.toggle('no-risk', !riskOn);
      if (!riskOn) {
        if (sortKey === 'score') { sortKey = 'default'; sortDir = 'asc'; }
        filterBand.value = 'all';
        if (filterPolicy) filterPolicy.value = 'all';
        markSortedHeader();
      }
      renderTable();
      if (INVENTORY) renderInventory();
    });
  }
  searchBox.addEventListener('input', debounce(renderTable, 150));
  if (showInactiveToggle) {
    showInactiveToggle.addEventListener('change', () => {
      showInactive = showInactiveToggle.checked;
      renderTable();
    });
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  function endpointText(resolved) {
    if (!resolved) return '?';
    return (resolved.negated ? 'NOT ' : '') + endpointTextBase(resolved);
  }

  function endpointTextBase(resolved) {
    switch (resolved.kind) {
      case 'any': return 'any';
      case 'host': return resolved.address + (resolved.name ? ` (${resolved.name})` : '');
      case 'subnet': return `${resolved.address}/${resolved.prefixLen ?? '?'}` + (resolved.name ? ` (${resolved.name})` : '');
      case 'range': return `${resolved.start}\u2013${resolved.end}`;
      case 'fqdn': return resolved.address;
      case 'group': return resolved.name
        ? `${resolved.name} [${resolved.members.length} members]`
        : `${resolved.members.length} addresses`;
      case 'literal': return resolved.address;
      default: return '?';
    }
  }

  function serviceText(services) {
    if (!services || !services.length) return 'any';
    return services.map(s => {
      const proto = (s.protocol || 'ip').toUpperCase();
      if (s.destPort) return s.isRange ? `${proto}/${s.destPort}-${s.destPortEnd}` : `${proto}/${s.destPort}`;
      return `${proto} (any port)`;
    }).join(', ');
  }

  function rowMatchesFilters(row) {
    if (row.type !== 'rule') return false;
    const s = row.scored;
    if (!showInactive && row.inactive) return false;
    if (riskOn && filterBand.value !== 'all' && s.band.label !== filterBand.value) return false;
    if (filterAction.value !== 'all' && s.action !== filterAction.value) return false;
    if (filterImplicit.value === 'implicit' && !row.implicit) return false;
    if (filterImplicit.value === 'explicit' && row.implicit) return false;
    if (filterLogging.value === 'unlogged' && !s.logging.flagged) return false;
    if (filterLogging.value === 'logged' && s.logging.flagged) return false;
    if (riskOn && filterPolicy && filterPolicy.value !== 'all') {
      const state = effectiveVerdict(row).state;
      if (filterPolicy.value === 'against' && state !== 'open') return false;
      if (filterPolicy.value === 'exception' && state !== 'exception') return false;
      if (filterPolicy.value === 'compliant' && state !== 'compliant') return false;
    }
    const q = searchBox.value.trim().toLowerCase();
    if (q) {
      const haystack = [
        endpointText(s.srcResolved), endpointText(s.dstResolved),
        serviceText(s.services), row.aclName || '', row.interface || '',
        s.service.name || ''
      ].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  }

  // Default order: rulebase order — rules exactly as they appear in the
  // configuration. `row.id` is assigned in parse/build order (per policy for
  // FortiOS/PAN-OS; per ACL then ACE for ASA, with any synthesized implicit
  // rules last), so it is the config's own ordering. This is what firewall
  // engineers reason about (first-match evaluation order), and it does not
  // regroup by interface/zone the way an earlier ASA-specific default did.
  function compareDefaultOrder(a, b) {
    return a.id - b.id;
  }

  function sortRows(rows) {
    if (sortKey === 'default') {
      return rows.slice().sort(compareDefaultOrder);
    }
    const dir = sortDir === 'asc' ? 1 : -1;
    return rows.slice().sort((a, b) => {
      let av, bv;
      switch (sortKey) {
        case 'ruleNumber': av = a.ruleNumber ?? 0; bv = b.ruleNumber ?? 0; break;
        case 'score': av = a.scored.score; bv = b.scored.score; break;
        case 'action': av = a.scored.action; bv = b.scored.action; break;
        case 'protocol': av = (a.scored.services[0] && a.scored.services[0].protocol) || ''; bv = (b.scored.services[0] && b.scored.services[0].protocol) || ''; break;
        case 'src': av = endpointText(a.scored.srcResolved); bv = endpointText(b.scored.srcResolved); break;
        case 'dst': av = endpointText(a.scored.dstResolved); bv = endpointText(b.scored.dstResolved); break;
        case 'service': av = serviceText(a.scored.services); bv = serviceText(b.scored.services); break;
        case 'iface': av = a.interface || ''; bv = b.interface || ''; break;
        case 'acl': av = a.aclName || ''; bv = b.aclName || ''; break;
        case 'logging': av = a.scored.logging.flagged ? 0 : 1; bv = b.scored.logging.flagged ? 0 : 1; break;
        default: av = a.scored.score; bv = b.scored.score;
      }
      if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }

  // ---- table rendering ----
  function renderTable() {
    const filtered = ROWS.filter(rowMatchesFilters);
    const sorted = sortRows(filtered);
    tbody.innerHTML = '';

    if (!sorted.length) {
      tbody.innerHTML = `<tr><td colspan="11"><div class="empty-state">No rules match the current filters.</div></td></tr>`;
      footerNote.textContent = '';
      return;
    }

    for (const row of sorted) {
      tbody.appendChild(buildRuleRow(row));
      if (EXPANDED.has(row.id)) {
        tbody.appendChild(buildDetailRow(row));
      }
    }

    const inactiveCount = ROWS.filter(r => r.type === 'rule' && r.inactive).length;
    const inactiveNote = inactiveCount
      ? (showInactive ? ` ${inactiveCount} inactive rule${inactiveCount === 1 ? '' : 's'} shown dimmed.` : ` ${inactiveCount} inactive rule${inactiveCount === 1 ? '' : 's'} hidden \u2014 toggle "Show inactive" to view.`)
      : '';
    footerNote.textContent = `Showing ${sorted.length} of ${ROWS.filter(r => r.type === 'rule').length} rules.${inactiveNote} Rules are listed in rulebase order \u2014 as they appear in the configuration \u2014 including inactive rules, which keep their position. ${riskOn ? 'Risk scoring is heuristic \u2014 use as a triage aid, not a compliance verdict.' : ''}`;
  }

  function buildRuleRow(row) {
    const tr = document.createElement('tr');
    tr.className = 'rule-row' + (EXPANDED.has(row.id) ? ' expanded' : '') + (row.inactive ? ' inactive-row' : '');
    tr.dataset.rowId = row.id;
    const s = row.scored;
    const band = s.band;
    const isOpen = EXPANDED.has(row.id);
    const log = s.logging;

    tr.innerHTML = `
      <td><span class="expand-caret ${isOpen ? 'open' : ''}">\u25B8</span></td>
      <td class="mono rule-number">${row.ruleNumber ?? '\u2014'}</td>
      <td class="risk-cell risk-only">
        <div class="risk-bar-wrap">
          <span class="risk-num" style="color:${band.color}">${s.score}</span>${s.buyback && s.buyback.credit > 0 && s.inContextScore < s.score ? `<span class="buyback-tag" title="Compensating controls in the rulebase reduce this to ${s.inContextScore} in-context (−${s.buyback.credit}). Expand for detail.">→ ${s.inContextScore}</span>` : ''}
        </div>
        <div class="risk-band-pill" style="background:${band.color}22; color:${band.color}; border:1px solid ${band.color}55;">${band.label}</div>
      </td>
      <td><span class="${s.action === 'permit' ? 'action-permit' : 'action-deny'}">${s.action}</span>${row.inactive ? '<span class="inactive-tag">INACTIVE</span>' : ''}${riskOn ? policyPill(row) : ''}</td>
      <td class="mono">${(s.services[0] && s.services[0].protocol ? s.services[0].protocol : 'ip').toUpperCase()}</td>
      <td class="mono">${escapeHtml(endpointText(s.srcResolved))}</td>
      <td class="mono">${escapeHtml(endpointText(s.dstResolved))}</td>
      <td class="mono">${escapeHtml(serviceText(s.services))}</td>
      <td>
        <span class="log-pill ${log.flagged ? 'log-flagged log-sev-' + log.severity : 'log-ok'}" title="${escapeHtml(log.detail)}">
          ${log.flagged ? '\u26A0 ' : ''}${escapeHtml(log.label)}
        </span>
      </td>
      <td><span class="iface-tag">${escapeHtml(row.interface || '\u2014')}</span>${row.implicit ? '<span class="implicit-tag">IMPLICIT</span>' : ''}</td>
      <td class="acl-name">${row.aclName ? escapeHtml(row.aclName) : '\u2014'}</td>
    `;
    tr.addEventListener('click', () => toggleExpand(row.id));
    return tr;
  }

  function toggleExpand(id) {
    if (EXPANDED.has(id)) EXPANDED.delete(id);
    else EXPANDED.add(id);
    renderTable();
  }

  // ---- policy verdict + exceptions (localStorage-backed, tri-state) ----
  // An `against-policy` finding is not a hard block: it can carry a documented,
  // time-bound exception (risk acceptance). Exceptions are stored locally,
  // keyed by a stable rule identity, and expire.
  const EXC_STORE_KEY = 'fwrra-policy-exceptions';
  function loadExceptions() {
    try { return JSON.parse(localStorage.getItem(EXC_STORE_KEY) || '{}'); } catch (e) { return {}; }
  }
  function saveExceptions(o) {
    try { localStorage.setItem(EXC_STORE_KEY, JSON.stringify(o)); } catch (e) { /* storage disabled */ }
  }
  function ruleKey(row) {
    const s = row.scored;
    const svc = (s.services || []).map(c => `${c.protocol}/${c.destPort || 'any'}`).join(',');
    return [CURRENT_VENDOR ? CURRENT_VENDOR.id : '', row.aclName || '', row.ruleNumber || '', s.direction || '', svc].join('|');
  }
  function getException(row) {
    const exc = loadExceptions()[ruleKey(row)];
    if (!exc) return null;
    const expired = exc.expiry && Date.parse(exc.expiry) < Date.now();
    return Object.assign({}, exc, { expired });
  }
  // Effective verdict state: 'compliant' | 'open' | 'exception'
  function effectiveVerdict(row) {
    const v = row.scored.policyVerdict;
    if (!v || v.verdict !== 'against-policy') return { state: 'compliant', matches: v ? v.matches : [] };
    const exc = getException(row);
    if (exc && !exc.expired) return { state: 'exception', matches: v.matches, exc };
    return { state: 'open', matches: v.matches, exc: exc || null, wasExpired: !!(exc && exc.expired) };
  }
  function recordException(row) {
    const justification = prompt('Exception — business justification for this against-policy rule:');
    if (!justification) return;
    const owner = prompt('Risk acceptor / owner (who signs off):') || '';
    const daysStr = prompt('Expires in how many days?', '90');
    const days = parseInt(daysStr, 10);
    const expiry = (!isNaN(days) && days > 0) ? new Date(Date.now() + days * 86400000).toISOString().slice(0, 10) : '';
    const store = loadExceptions();
    store[ruleKey(row)] = { justification, owner, created: new Date().toISOString().slice(0, 10), expiry };
    saveExceptions(store);
    renderSummary();
    renderTable();
  }
  function clearException(row) {
    const store = loadExceptions();
    delete store[ruleKey(row)];
    saveExceptions(store);
    renderSummary();
    renderTable();
  }
  function policyPill(row) {
    const ev = effectiveVerdict(row);
    if (ev.state === 'compliant') return '';
    if (ev.state === 'exception') {
      return `<span class="policy-pill policy-exc" title="Against policy, with an accepted exception${ev.exc && ev.exc.expiry ? ' (expires ' + escapeHtml(ev.exc.expiry) + ')' : ''}.">EXCEPTION</span>`;
    }
    const ids = ev.matches.map(m => m.id).join(', ');
    return `<span class="policy-pill policy-open" title="Against policy: ${escapeHtml(ids)}${ev.wasExpired ? ' (exception expired)' : ''}.">⚠ POLICY</span>`;
  }

  function renderPolicySection(row) {
    const v = row.scored.policyVerdict;
    if (!v) return '';
    const ev = effectiveVerdict(row);
    let inner = '';
    if (ev.state === 'compliant') {
      inner = '<div class="row"><span class="k">Verdict</span><span style="color:var(--c-low)">Compliant — no prohibited pattern matched.</span></div>';
    } else {
      const stds = ev.matches.map(m => `<div class="row"><span class="k">${escapeHtml(m.id)}</span><span>${escapeHtml(m.rationale)}</span></div>`).join('');
      if (ev.state === 'exception') {
        const e = ev.exc;
        inner =
          `<div class="row"><span class="k">Verdict</span><span style="color:var(--c-high)">Against policy — exception accepted${e.expiry ? ' (expires ' + escapeHtml(e.expiry) + ')' : ''}.</span></div>` +
          stds +
          `<div class="row"><span class="k">Justification</span><span>${escapeHtml(e.justification || '')}</span></div>` +
          `<div class="row"><span class="k">Risk acceptor</span><span>${escapeHtml(e.owner || '—')}</span></div>` +
          `<div class="row"><span class="k">Recorded</span><span>${escapeHtml(e.created || '—')}${e.expiry ? ' · expires ' + escapeHtml(e.expiry) : ' · no expiry'}</span></div>` +
          `<div class="row"><span class="k"></span><span><button class="exc-btn" data-exc-action="clear">Remove exception</button></span></div>`;
      } else {
        inner =
          `<div class="row"><span class="k">Verdict</span><span style="color:var(--c-critical)">Against policy — open${ev.wasExpired ? ' (exception expired)' : ''}. Remediate the rule, or record a risk-accepted exception.</span></div>` +
          stds +
          `<div class="row"><span class="k"></span><span><button class="exc-btn" data-exc-action="record">Record exception…</button></span></div>`;
      }
    }
    return '<div class="detail-section" style="margin-top:12px;"><h4>Policy compliance</h4><div class="score-explain">' + inner + '</div></div>';
  }

  function buildDetailRow(row) {
    const tr = document.createElement('tr');
    tr.className = 'detail-row';
    const td = document.createElement('td');
    td.colSpan = 11;
    const s = row.scored;

    let html = '<div class="detail-panel">';

    if (row.implicit) {
      html += `<div class="implicit-note"><strong>Implicit rule.</strong> ${escapeHtml(row.implicitNote)}</div>`;
    }
    if (row.inactive) {
      html += `<div class="implicit-note" style="color:var(--text-dim); background:rgba(122,129,148,0.08); border-color:var(--border);"><strong>Inactive ACE.</strong> This line carries the 'inactive' keyword in the config \u2014 the ASA skips it entirely, it is not enforced.</div>`;
    }
    if (s.logging.flagged) {
      const sevColor = s.logging.severity === 'high' ? 'var(--c-critical)' : 'var(--c-high)';
      html += `<div class="implicit-note" style="color:${sevColor}; background:${sevColor}14; border-color:${sevColor}55;"><strong>${escapeHtml(s.logging.label)}.</strong> ${escapeHtml(s.logging.detail)}</div>`;
    }

    html += '<div class="detail-grid">';

    // left: source/dest member trees
    html += '<div class="detail-section"><h4>Source</h4><div class="member-tree">' + renderMemberTree(s.srcResolved) + '</div></div>';
    html += '<div class="detail-section"><h4>Destination</h4><div class="member-tree">' + renderMemberTree(s.dstResolved) + '</div></div>';
    html += '</div>';

    // service breakdown
    html += '<div class="detail-section" style="margin-bottom:14px;"><h4>Service / Protocol</h4><div class="member-tree">' + renderServiceTree(row) + '</div></div>';

    // score explain
    if (riskOn) {
    html += '<div class="detail-section"><h4>Risk calculation</h4><div class="score-explain">';
    html += `<div class="row"><span class="k">Exposure (source/destination scope)</span><span>${s.exposure.label} \u2014 ${s.exposure.score}</span></div>`;
    html += `<div class="row"><span class="k">Service risk (worst-case port/protocol)</span><span>${escapeHtml(s.service.name)} \u2014 ${s.service.score}</span></div>`;
    if (s.service.note) html += `<div class="row"><span class="k" style="font-style:italic;">note</span><span style="font-style:italic;">${escapeHtml(s.service.note)}</span></div>`;
    html += `<div class="row"><span class="k">Combine</span><span>exposure + service − (exposure × service ⁄ 100)${s.subnetPenaltyApplied ? ` + ${s.subnetPenalty} (indiscriminate subnet penalty)` : ''}</span></div>`;
    html += `<div class="row total"><span class="k">Inherent score</span><span style="color:${s.band.color}">${s.score} / 100 \u2014 ${s.band.label}</span></div>`;
    // Buyback / hardening credit (in-context score) \u2014 only when a preceding
    // matching deny carves high-risk ports or threat-geo out of this permit.
    if (s.buyback && s.buyback.credit > 0) {
      const parts = [];
      if (s.buyback.blockedPorts && s.buyback.blockedPorts.length) {
        parts.push('ports ' + s.buyback.blockedPorts.map(p => escapeHtml(p.key)).join(', ') + ` (\u2212${s.buyback.portCredit})`);
      }
      if (s.buyback.blockedGeo && s.buyback.blockedGeo.length) {
        parts.push(`${s.buyback.blockedGeo.length} threat-geo block${s.buyback.blockedGeo.length === 1 ? '' : 's'} (\u2212${s.buyback.geoCredit})`);
      }
      if (s.buyback.blockedGeofence && s.buyback.blockedGeofence.length) {
        parts.push(`${s.buyback.blockedGeofence.length} geofence allow-list${s.buyback.blockedGeofence.length === 1 ? '' : 's'} (\u2212${s.buyback.geofenceCredit})`);
      }
      html += `<div class="row"><span class="k">Hardening buyback (compensating controls)</span><span>\u2212${s.buyback.credit}: ${parts.join('; ')}</span></div>`;
      const icBand = s.inContextBand || s.band;
      const floored = s.inContextScore >= s.score;
      html += `<div class="row total"><span class="k">In-context score</span><span style="color:${icBand.color}">${s.inContextScore} / 100 \u2014 ${icBand.label}</span></div>`;
      if (floored) {
        html += `<div class="row" style="font-style:italic; color:var(--text-dim);"><span class="k"></span><span>credit is capped at this rule's exposure floor (${s.exposure.score}) \u2014 source/destination breadth is not bought back, so the score is unchanged</span></div>`;
      }
      html += `<div class="row" style="font-style:italic; color:var(--text-dim);"><span class="k"></span><span>credit reflects that a matching block exists and precedes this rule; rule-order effectiveness (shadowing) is not verified</span></div>`;
    }
    html += `<div class="row" style="margin-top:6px; padding-top:6px; border-top:1px solid var(--border-soft);"><span class="k">Logging</span><span style="${s.logging.flagged ? 'color:' + (s.logging.severity === 'high' ? 'var(--c-critical)' : 'var(--c-high)') : ''}">${escapeHtml(s.logging.label)}</span></div>`;
    html += '</div></div>';

    // Policy compliance section (gate, independent of the score).
    html += renderPolicySection(row);
    }

    html += '</div>';
    td.innerHTML = html;
    // Wire exception buttons (delegated, stop row-collapse).
    td.addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-exc-action]');
      if (!btn) return;
      ev.stopPropagation();
      if (btn.getAttribute('data-exc-action') === 'record') recordException(row);
      else if (btn.getAttribute('data-exc-action') === 'clear') clearException(row);
    });
    tr.appendChild(td);
    return tr;
  }

  function renderMemberTree(resolved, depth) {
    depth = depth || 0;
    if (depth > 6) return '<ul><li class="tag">max depth</li></ul>';
    if (!resolved) return '<span class="tag">unknown</span>';
    // Negated endpoint (PAN-OS negate-source/destination): matches everything
    // EXCEPT the tree below — a geofence allow-list is really its complement.
    if (resolved.negated && depth === 0) {
      const inner = renderMemberTree(Object.assign({}, resolved, { negated: false }), depth);
      return `<span class="flag">⚠ NEGATED — matches everything EXCEPT:</span> ${inner}`;
    }
    if (resolved.kind === 'any') return '<span class="tag">scope</span> any (0.0.0.0/0)';
    if (resolved.kind === 'host') return `<span class="tag">host</span> ${escapeHtml(resolved.address)}${resolved.name ? ' <span class="tag">' + escapeHtml(resolved.name) + '</span>' : ''}`;
    if (resolved.kind === 'subnet') return `<span class="tag">subnet</span> ${escapeHtml(resolved.address)}/${resolved.prefixLen ?? '?'} (${escapeHtml(resolved.mask || '')})${resolved.name ? ' <span class="tag">' + escapeHtml(resolved.name) + '</span>' : ''}`;
    if (resolved.kind === 'range') return `<span class="tag">range</span> ${escapeHtml(resolved.start)} \u2013 ${escapeHtml(resolved.end)}`;
    if (resolved.kind === 'fqdn') return `<span class="tag">fqdn</span> ${escapeHtml(resolved.address)}`;
    if (resolved.kind === 'literal') return `<span class="tag">${resolved.unresolved ? 'unresolved' : 'literal'}</span> ${escapeHtml(resolved.address)}`;
    if (resolved.kind === 'group') {
      const groupLabel = resolved.name ? escapeHtml(resolved.name) : `<em>${resolved.members.length} addresses</em>`;
      let out = `<span class="tag">group</span> ${groupLabel} <ul>`;
      for (const mem of resolved.members) {
        out += `<li>${renderMemberTree(mem, depth + 1)}</li>`;
      }
      out += '</ul>';
      return out;
    }
    return '<span class="tag">?</span>';
  }

  const RISKY_PORT_NAMES = new Set(['FTP', 'FTP-DATA', 'TFTP', 'SSH', 'Telnet', 'SMB', 'NetBIOS-SSN', 'NetBIOS-NS', 'NetBIOS-DGM', 'RDP', 'VNC', 'MS-RPC']);

  function renderServiceTree(row) {
    const services = row.scored.services;
    if (!services || !services.length) return '<span class="tag">any</span> all protocols / ports';
    let out = '<ul>';
    for (const svc of services) {
      const proto = (svc.protocol || 'ip').toLowerCase();
      const portLabel = svc.destPort ? (svc.isRange ? `${svc.destPort}-${svc.destPortEnd}` : svc.destPort) : null;
      const lookup = lookupServiceRisk(proto, svc.destPort);
      const flagged = lookup.score >= 45;
      out += `<li><span class="tag">${proto.toUpperCase()}</span> ${portLabel ? 'port ' + escapeHtml(portLabel) + ' (' + escapeHtml(lookup.name) + ')' : '<em>any port</em>'}`;
      if (flagged && riskOn) out += `<span class="flag">\u26A0 risk ${lookup.score}${lookup.note ? ': ' + escapeHtml(lookup.note) : ''}</span>`;
      out += '</li>';
    }
    out += '</ul>';
    return out;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ---- tabs + vendor inventory (generic; see shared/registry.js) ----
  tabBar.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
  if (invSearch) invSearch.addEventListener('input', debounce(renderInventory, 150));

  function setTab(tab) {
    activeTab = tab;
    rulesView.style.display = tab === 'rules' ? '' : 'none';
    inventoryView.style.display = tab === 'inventory' ? '' : 'none';
    tabBar.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    if (tab === 'inventory') renderInventory();
  }

  function cellText(c) { return c && typeof c === 'object' ? c.text : (c ?? ''); }
  function cellHtml(c) {
    if (c && typeof c === 'object') {
      return `<span class="${c.tone ? 'tone-' + c.tone : ''}">${escapeHtml(c.text)}</span>` +
        (c.note ? `<span class="tag">${escapeHtml(c.note)}</span>` : '');
    }
    return escapeHtml(c);
  }

  function invRowMatches(row, q) {
    if (!q) return true;
    return Object.values(row.cells).map(cellText).join(' ').toLowerCase().includes(q);
  }

  function ruleRowMatchesQuery(row, q) {
    if (!q) return true;
    const s = row.scored;
    return [endpointText(s.srcResolved), endpointText(s.dstResolved), serviceText(s.services),
      row.aclName || '', (row.usedBy || []).join(' ')].join(' ').toLowerCase().includes(q);
  }

  function detailHtml(blocks) {
    const sec = (title, inner) => `<div class="detail-section" style="margin-bottom:12px;"><h4>${escapeHtml(title)}</h4>${inner}</div>`;
    return (blocks || []).map(b => {
      if (b.kind === 'kv') {
        return sec(b.title, '<div class="score-explain">' + b.pairs.map(([k, v]) =>
          `<div class="row"><span class="k">${escapeHtml(k)}</span><span>${cellHtml(v)}</span></div>`).join('') + '</div>');
      }
      if (b.kind === 'networks') {
        return sec(b.title, '<div class="member-tree"><ul>' + b.entries.map(e =>
          `<li><span class="tag">${escapeHtml(e.action)}</span> ${renderMemberTree(e.resolved)}</li>`).join('') + '</ul></div>');
      }
      if (b.kind === 'list') {
        return sec(b.title, '<div class="member-tree"><ul>' + b.items.map(x => `<li>${escapeHtml(x)}</li>`).join('') + '</ul></div>');
      }
      return '';
    }).join('');
  }

  function buildInvTable(sec, q) {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th style="width:20px;"></th>' +
      sec.columns.map(c => `<th>${escapeHtml(c.label)}</th>`).join('') + '</tr></thead>';
    const tb = document.createElement('tbody');
    const rows = sec.rows.filter(r => invRowMatches(r, q));
    if (!rows.length) {
      tb.innerHTML = `<tr><td colspan="${sec.columns.length + 1}"><div class="empty-state">No matching entries.</div></td></tr>`;
    }
    for (const row of rows) {
      const key = sec.id + ':' + sec.rows.indexOf(row);
      const open = !!row.detail && INV_EXPANDED.has(key);
      const tr = document.createElement('tr');
      tr.className = 'rule-row' + (open ? ' expanded' : '');
      tr.innerHTML = `<td><span class="expand-caret ${open ? 'open' : ''}">${row.detail ? '▸' : ''}</span></td>` +
        sec.columns.map(c => `<td class="mono">${cellHtml(row.cells[c.key])}</td>`).join('');
      if (row.detail) {
        tr.addEventListener('click', () => {
          if (INV_EXPANDED.has(key)) INV_EXPANDED.delete(key); else INV_EXPANDED.add(key);
          renderInventory();
        });
      }
      tb.appendChild(tr);
      if (open) {
        const dr = document.createElement('tr');
        dr.className = 'detail-row';
        const td = document.createElement('td');
        td.colSpan = sec.columns.length + 1;
        td.innerHTML = '<div class="detail-panel">' + detailHtml(row.detail) + '</div>';
        dr.appendChild(td);
        tb.appendChild(dr);
      }
    }
    table.appendChild(tb);
    wrap.appendChild(table);
    return wrap;
  }

  // Scored rule rows reuse the main table's row/detail builders (and therefore
  // the risk toggle); only the click handler is swapped so it re-renders here.
  function buildInvRuleTable(sec, q) {
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    const thead = document.querySelector('#ruleTable thead').cloneNode(true);
    thead.querySelectorAll('th').forEach(th => th.removeAttribute('data-sort'));
    thead.querySelector('tr').insertAdjacentHTML('beforeend', '<th>Used by</th>');
    table.appendChild(thead);
    const tb = document.createElement('tbody');
    const rows = sec.ruleRows.filter(r => ruleRowMatchesQuery(r, q));
    if (!rows.length) tb.innerHTML = '<tr><td colspan="12"><div class="empty-state">No matching entries.</div></td></tr>';
    for (const row of rows) {
      const tr = buildRuleRow(row).cloneNode(true); // cloneNode drops the rules-table click handler
      const used = document.createElement('td');
      used.className = 'mono';
      used.textContent = (row.usedBy || []).join(', ');
      tr.appendChild(used);
      tr.addEventListener('click', () => {
        if (EXPANDED.has(row.id)) EXPANDED.delete(row.id); else EXPANDED.add(row.id);
        renderInventory();
      });
      tb.appendChild(tr);
      if (EXPANDED.has(row.id)) {
        const dr = buildDetailRow(row);
        dr.firstChild.colSpan = 12;
        tb.appendChild(dr);
      }
    }
    table.appendChild(tb);
    wrap.appendChild(table);
    return wrap;
  }

  // Policy blocks: one collapsible block per group (see shared/registry.js
  // `groups` sections). Collapsed by default; a search forces matches open.
  function groupMatches(g, q) {
    if (!q) return true;
    if ([g.title].concat(g.summary.map(cellText)).join(' ').toLowerCase().includes(q)) return true;
    return g.sections.some(s => s.ruleRows
      ? s.ruleRows.some(r => ruleRowMatchesQuery(r, q))
      : s.rows.some(r => invRowMatches(r, q)));
  }

  function buildInvGroups(sec, q) {
    const wrap = document.createElement('div');
    const keys = sec.groups.map(g => sec.id + ':' + g.key);
    const bar = document.createElement('div');
    bar.className = 'grp-bar';
    bar.innerHTML = '<button class="exc-btn" data-grp-all="open">+ Expand all</button> ' +
      '<button class="exc-btn" data-grp-all="close">− Collapse all</button>';
    bar.querySelector('[data-grp-all="open"]').addEventListener('click', () => { keys.forEach(k => GROUP_OPEN.add(k)); renderInventory(); });
    bar.querySelector('[data-grp-all="close"]').addEventListener('click', () => { keys.forEach(k => GROUP_OPEN.delete(k)); renderInventory(); });
    wrap.appendChild(bar);
    for (const g of sec.groups) {
      if (!groupMatches(g, q)) continue;
      const key = sec.id + ':' + g.key;
      const open = !!q || GROUP_OPEN.has(key);
      const box = document.createElement('div');
      box.className = 'grp' + (open ? ' open' : '');
      const head = document.createElement('div');
      head.className = 'grp-head';
      head.innerHTML = `<button class="grp-toggle" aria-expanded="${open}">${open ? '−' : '+'}</button>` +
        `<span class="grp-title">${escapeHtml(g.title)}</span>` +
        g.summary.map(c => `<span class="grp-chip${c && c.risk ? ' risk-only' : ''}">${cellHtml(c)}</span>`).join('');
      head.addEventListener('click', () => {
        if (GROUP_OPEN.has(key)) GROUP_OPEN.delete(key); else GROUP_OPEN.add(key);
        renderInventory();
      });
      box.appendChild(head);
      if (open) {
        const body = document.createElement('div');
        body.className = 'grp-body';
        for (const s of g.sections) {
          const sub = Object.assign({}, s, { id: key + ':' + s.id }); // unique expand keys per policy
          const h = document.createElement('h4');
          h.className = 'grp-sub';
          h.textContent = s.heading;
          body.appendChild(h);
          body.appendChild(s.ruleRows ? buildInvRuleTable(sub, q) : buildInvTable(sub, q));
        }
        box.appendChild(body);
      }
      wrap.appendChild(box);
    }
    return wrap;
  }

  function renderInventory() {
    if (!INVENTORY) { invBody.innerHTML = ''; return; }
    const q = invSearch.value.trim().toLowerCase();
    invBody.innerHTML = '';
    for (const sec of INVENTORY.sections) {
      const box = document.createElement('div');
      box.className = 'inv-section';
      const h = document.createElement('h3');
      h.textContent = sec.heading;
      box.appendChild(h);
      box.appendChild(sec.groups ? buildInvGroups(sec, q) : sec.ruleRows ? buildInvRuleTable(sec, q) : buildInvTable(sec, q));
      invBody.appendChild(box);
    }
  }

  // ---- CSV export ----
  exportBtn.addEventListener('click', () => {
    if (activeTab === 'inventory' && INVENTORY) { exportInventoryCsv(); return; }
    const ruleRows = sortRows(ROWS.filter(rowMatchesFilters));
    const header = riskOn
      ? ['Rule #', 'Score', 'Band', 'Action', 'Inactive', 'Protocol', 'Source', 'Destination', 'Service', 'Interface', 'Direction', 'ACL', 'Implicit', 'Logging', 'Logging Flagged', 'Exposure Label', 'Exposure Score', 'Service Risk Name', 'Service Risk Score']
      : ['Rule #', 'Action', 'Inactive', 'Protocol', 'Source', 'Destination', 'Service', 'Interface', 'Direction', 'ACL', 'Implicit', 'Logging', 'Logging Flagged'];
    const lines = [header.join(',')];
    for (const row of ruleRows) {
      const s = row.scored;
      const fields = [
        row.ruleNumber ?? '',
        ...(riskOn ? [s.score, s.band.label] : []),
        s.action,
        row.inactive ? 'yes' : 'no',
        (s.services[0] && s.services[0].protocol) || 'ip',
        endpointText(s.srcResolved), endpointText(s.dstResolved), serviceText(s.services),
        row.interface || '', row.direction || '', row.aclName || '',
        row.implicit ? 'yes' : 'no',
        s.logging.label, s.logging.flagged ? 'yes' : 'no',
        ...(riskOn ? [s.exposure.label, s.exposure.score, s.service.name, s.service.score] : [])
      ].map(csvEscape);
      lines.push(fields.join(','));
    }
    downloadCsv(lines.join('\n'), 'asa-rule-risk-export.csv');
  });

  function downloadCsv(text, filename) {
    const blob = new Blob([text], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportInventoryCsv() {
    const q = invSearch.value.trim().toLowerCase();
    const out = [];
    // Emit one section as a CSV block; `policy` (optional) becomes a first column.
    const emit = (heading, s, policy, label) => {
      out.push(csvEscape('# ' + heading));
      const pre = policy === undefined ? [] : [policy];
      const preH = policy === undefined ? [] : [label || 'Group'];
      if (s.ruleRows) {
        out.push([...preH, 'ACL', 'Rule #', ...(riskOn ? ['Score', 'Band'] : []), 'Action', 'Inactive', 'Protocol',
          'Source', 'Destination', 'Service', 'Logging', 'Used by'].join(','));
        for (const row of s.ruleRows.filter(r => ruleRowMatchesQuery(r, q))) {
          const sc = row.scored;
          out.push([...pre, row.aclName, row.ruleNumber, ...(riskOn ? [sc.score, sc.band.label] : []), sc.action,
            row.inactive ? 'yes' : 'no', (sc.services[0] && sc.services[0].protocol) || 'ip',
            endpointText(sc.srcResolved), endpointText(sc.dstResolved), serviceText(sc.services),
            sc.logging.label, (row.usedBy || []).join('; ')].map(csvEscape).join(','));
        }
      } else {
        out.push([...preH, ...s.columns.map(c => c.label)].map(csvEscape).join(','));
        for (const row of s.rows.filter(r => invRowMatches(r, q))) {
          out.push([...pre, ...s.columns.map(c => {
            const v = row.cells[c.key];
            const n = v && typeof v === 'object' && v.note ? ` (${v.note})` : '';
            return cellText(v) + n;
          })].map(csvEscape).join(','));
        }
      }
      out.push('');
    };
    for (const sec of INVENTORY.sections) {
      if (sec.groups) {
        for (const g of sec.groups.filter(x => groupMatches(x, q))) {
          for (const s of g.sections) emit(`${g.title} / ${s.heading}`, s, g.title, sec.groupLabel);
        }
      } else {
        emit(sec.heading, sec);
      }
    }
    downloadCsv(out.join('\n'), 'asa-vpn-inventory.csv');
  }

  function csvEscape(v) {
    const s = String(v ?? '');
    if (s.includes(',') || s.includes('"') || s.includes('\n')) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
})();
