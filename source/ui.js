(function () {
  let CONFIG = null;
  let ROWS = [];
  let EXPANDED = new Set();
  let sortKey = 'default';
  let sortDir = 'asc';
  let showInactive = false;

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
    if (typeof file.size === 'number') parts.push(formatFileSize(file.size));
    const ifaceCount = Object.keys(config.interfaces).length;
    parts.push(`${ifaceCount} interface${ifaceCount === 1 ? '' : 's'}`);
    parts.push(`${ruleCount} rule${ruleCount === 1 ? '' : 's'} analyzed`);
    fileInfoSub.innerHTML = parts.map(p => escapeHtml(p)).join('<span class="sep">&middot;</span>');
  }

  function processConfig(text, file) {
    CONFIG = parseASAConfig(text);
    ROWS = buildRuleset(CONFIG);
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
    for (const r of ruleRows) {
      bands[r.scored.band.label] = (bands[r.scored.band.label] || 0) + 1;
      if (r.implicit) implicitCount++;
      if (r.scored.logging.flagged) unloggedCount++;
    }
    summaryEl.innerHTML = `
      <div class="cell"><div class="n">${ruleRows.length}</div><div class="l">Total rules</div></div>
      <div class="cell crit"><div class="n">${bands.Critical}</div><div class="l">Critical</div></div>
      <div class="cell high"><div class="n">${bands.High}</div><div class="l">High</div></div>
      <div class="cell med"><div class="n">${bands.Medium}</div><div class="l">Medium</div></div>
      <div class="cell low"><div class="n">${bands.Low}</div><div class="l">Low</div></div>
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
    switch (resolved.kind) {
      case 'any': return 'any';
      case 'host': return resolved.address + (resolved.name ? ` (${resolved.name})` : '');
      case 'subnet': return `${resolved.address}/${resolved.prefixLen ?? '?'}` + (resolved.name ? ` (${resolved.name})` : '');
      case 'range': return `${resolved.start}\u2013${resolved.end}`;
      case 'fqdn': return resolved.address;
      case 'group': return `${resolved.name} [${resolved.members.length} members]`;
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
    if (filterBand.value !== 'all' && s.band.label !== filterBand.value) return false;
    if (filterAction.value !== 'all' && s.action !== filterAction.value) return false;
    if (filterImplicit.value === 'implicit' && !row.implicit) return false;
    if (filterImplicit.value === 'explicit' && row.implicit) return false;
    if (filterLogging.value === 'unlogged' && !s.logging.flagged) return false;
    if (filterLogging.value === 'logged' && s.logging.flagged) return false;
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

  // Default order: most-secure interface first (desc security level), tie-broken by
  // interface name (asc), then by each rule's position within its ACL (asc).
  // This yields "inside -> outside" style blocks first, "outside -> inside" last,
  // matching how the ASA itself evaluates and how engineers reason about the ruleset.
  function compareDefaultOrder(a, b) {
    const ao = a.defaultOrder, bo = b.defaultOrder;
    if (ao.level !== bo.level) return bo.level - ao.level; // higher security level first
    if (ao.ifName !== bo.ifName) return ao.ifName.localeCompare(bo.ifName); // lowest-named interface first on ties
    return ao.ruleNumber - bo.ruleNumber; // original ACL order
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
      ? (showInactive ? ` ${inactiveCount} inactive ACE${inactiveCount === 1 ? '' : 's'} shown dimmed.` : ` ${inactiveCount} inactive ACE${inactiveCount === 1 ? '' : 's'} hidden \u2014 toggle "Show inactive" to view.`)
      : '';
    footerNote.textContent = `Showing ${sorted.length} of ${ROWS.filter(r => r.type === 'rule').length} rules.${inactiveNote} Rule # reflects position within its ACL in original config order (including inactive ACEs, matching 'show access-list'). Risk scoring is heuristic \u2014 use as a triage aid, not a compliance verdict.`;
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
      <td class="risk-cell">
        <div class="risk-bar-wrap">
          <span class="risk-num" style="color:${band.color}">${s.score}</span>
        </div>
        <div class="risk-band-pill" style="background:${band.color}22; color:${band.color}; border:1px solid ${band.color}55;">${band.label}</div>
      </td>
      <td><span class="${s.action === 'permit' ? 'action-permit' : 'action-deny'}">${s.action}</span>${row.inactive ? '<span class="inactive-tag">INACTIVE</span>' : ''}</td>
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
    html += '<div class="detail-section"><h4>Risk calculation</h4><div class="score-explain">';
    html += `<div class="row"><span class="k">Exposure (source/destination scope)</span><span>${s.exposure.label} \u2014 ${s.exposure.score}</span></div>`;
    html += `<div class="row"><span class="k">Service risk (worst-case port/protocol)</span><span>${escapeHtml(s.service.name)} \u2014 ${s.service.score}</span></div>`;
    if (s.service.note) html += `<div class="row"><span class="k" style="font-style:italic;">note</span><span style="font-style:italic;">${escapeHtml(s.service.note)}</span></div>`;
    html += `<div class="row"><span class="k">Combine</span><span>max(exposure, service)${s.bonusApplied ? ' + 10 (both elevated)' : ''}</span></div>`;
    html += `<div class="row total"><span class="k">Final score</span><span style="color:${s.band.color}">${s.score} / 100 \u2014 ${s.band.label}</span></div>`;
    html += `<div class="row" style="margin-top:6px; padding-top:6px; border-top:1px solid var(--border-soft);"><span class="k">Logging</span><span style="${s.logging.flagged ? 'color:' + (s.logging.severity === 'high' ? 'var(--c-critical)' : 'var(--c-high)') : ''}">${escapeHtml(s.logging.label)}</span></div>`;
    html += '</div></div>';

    html += '</div>';
    td.innerHTML = html;
    tr.appendChild(td);
    return tr;
  }

  function renderMemberTree(resolved, depth) {
    depth = depth || 0;
    if (depth > 6) return '<ul><li class="tag">max depth</li></ul>';
    if (!resolved) return '<span class="tag">unknown</span>';
    if (resolved.kind === 'any') return '<span class="tag">scope</span> any (0.0.0.0/0)';
    if (resolved.kind === 'host') return `<span class="tag">host</span> ${escapeHtml(resolved.address)}${resolved.name ? ' <span class="tag">' + escapeHtml(resolved.name) + '</span>' : ''}`;
    if (resolved.kind === 'subnet') return `<span class="tag">subnet</span> ${escapeHtml(resolved.address)}/${resolved.prefixLen ?? '?'} (${escapeHtml(resolved.mask || '')})${resolved.name ? ' <span class="tag">' + escapeHtml(resolved.name) + '</span>' : ''}`;
    if (resolved.kind === 'range') return `<span class="tag">range</span> ${escapeHtml(resolved.start)} \u2013 ${escapeHtml(resolved.end)}`;
    if (resolved.kind === 'fqdn') return `<span class="tag">fqdn</span> ${escapeHtml(resolved.address)}`;
    if (resolved.kind === 'literal') return `<span class="tag">${resolved.unresolved ? 'unresolved' : 'literal'}</span> ${escapeHtml(resolved.address)}`;
    if (resolved.kind === 'group') {
      let out = `<span class="tag">group</span> ${escapeHtml(resolved.name)} <ul>`;
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
      if (flagged) out += `<span class="flag">\u26A0 risk ${lookup.score}${lookup.note ? ': ' + escapeHtml(lookup.note) : ''}</span>`;
      out += '</li>';
    }
    out += '</ul>';
    return out;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ---- CSV export ----
  exportBtn.addEventListener('click', () => {
    const ruleRows = sortRows(ROWS.filter(rowMatchesFilters));
    const header = ['Rule #', 'Score', 'Band', 'Action', 'Inactive', 'Protocol', 'Source', 'Destination', 'Service', 'Interface', 'Direction', 'ACL', 'Implicit', 'Logging', 'Logging Flagged', 'Exposure Label', 'Exposure Score', 'Service Risk Name', 'Service Risk Score'];
    const lines = [header.join(',')];
    for (const row of ruleRows) {
      const s = row.scored;
      const fields = [
        row.ruleNumber ?? '',
        s.score, s.band.label, s.action,
        row.inactive ? 'yes' : 'no',
        (s.services[0] && s.services[0].protocol) || 'ip',
        endpointText(s.srcResolved), endpointText(s.dstResolved), serviceText(s.services),
        row.interface || '', row.direction || '', row.aclName || '',
        row.implicit ? 'yes' : 'no',
        s.logging.label, s.logging.flagged ? 'yes' : 'no',
        s.exposure.label, s.exposure.score, s.service.name, s.service.score
      ].map(csvEscape);
      lines.push(fields.join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'asa-rule-risk-export.csv';
    a.click();
    URL.revokeObjectURL(url);
  });

  function csvEscape(v) {
    const s = String(v ?? '');
    if (s.includes(',') || s.includes('"') || s.includes('\n')) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
})();
