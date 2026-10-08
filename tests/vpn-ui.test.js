const assert = require('assert');
const { fixture, loadPage } = require('./helpers');

const FORTI = `#config-version=FGT60F-7.0.1-FW-build0157:opmode=0:vdom=0
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
`;

const visible = (w, sel) => [...w.document.querySelectorAll(sel)]
  .filter(e => w.getComputedStyle(e).display !== 'none').length;

const heads = (d) => [...d.querySelectorAll('#invBody .grp-head')];
const headFor = (d, title) => heads(d).find(h => h.querySelector('.grp-title').textContent === title);
const openCount = (d) => d.querySelectorAll('#invBody .grp.open').length;

module.exports = async () => {
  // ---- ASA: tab present and populated ----
  const { w, d } = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));

  // version shown in page title and header
  assert.ok(d.title.endsWith(' v1.0.6'), 'title carries version: ' + d.title);
  assert.strictEqual(d.querySelector('.header h1 .ver').textContent, 'v1.0.6');

  assert.notStrictEqual(d.getElementById('tabBar').style.display, 'none');
  assert.strictEqual(d.getElementById('inventoryTabBtn').textContent, 'Remote-access VPN');
  assert.strictEqual(d.getElementById('inventoryView').style.display, 'none', 'rules tab is the default');

  d.getElementById('inventoryTabBtn').click();
  assert.strictEqual(d.getElementById('inventoryView').style.display, '');
  assert.strictEqual(d.getElementById('rulesView').style.display, 'none');
  assert.deepStrictEqual([...d.querySelectorAll('#invBody h3')].map(h => h.textContent), ['VPN policies']);

  // one collapsed block per policy, with summaries
  assert.deepStrictEqual(heads(d).map(h => h.querySelector('.grp-title').textContent),
    ['DfltGrpPolicy', 'ENG_GP', 'CONTR_GP', 'OPEN_GP', 'INHERIT_GP', 'Global / unassigned']);
  assert.strictEqual(openCount(d), 0, 'all collapsed by default');
  assert.strictEqual(d.querySelectorAll('#invBody .grp-body').length, 0);
  assert.ok(headFor(d, 'ENG_GP').textContent.includes('split: Enabled (include)'));
  assert.ok(headFor(d, 'ENG_GP').textContent.includes('filter: ENG_FILTER'));
  assert.strictEqual(headFor(d, 'ENG_GP').querySelector('.grp-toggle').textContent, '+');

  // expand a single policy
  headFor(d, 'ENG_GP').click();
  assert.strictEqual(openCount(d), 1);
  assert.strictEqual(headFor(d, 'ENG_GP').querySelector('.grp-toggle').textContent, '−');
  assert.strictEqual(headFor(d, 'CONTR_GP').querySelector('.grp-toggle').textContent, '+');
  let body = d.getElementById('invBody').textContent;
  assert.ok(body.includes('Effective settings') && body.includes('Tunnel-groups using this policy'));
  assert.ok(body.includes('Enabled (include)') && body.includes('Engineering'));

  // settings row detail shows the split-tunnel networks
  const splitRow = [...d.querySelectorAll('#invBody tr.rule-row')].find(tr => tr.textContent.includes('Split tunneling') && tr.textContent.includes('Enabled (include)'));
  splitRow.click();
  assert.ok(d.getElementById('invBody').textContent.includes('Split-tunnel networks'));

  // filter rule rows inside the policy expand with the risk calculation (risk ON)
  const ruleHead = [...d.querySelectorAll('#invBody h4')].find(h => h.textContent === 'VPN filter rules');
  ruleHead.nextSibling.querySelector('tr.rule-row').click();
  assert.ok(d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(visible(w, '#invBody td.risk-cell') > 0);

  // Expand all / Collapse all
  d.querySelector('[data-grp-all="open"]').click();
  assert.strictEqual(openCount(d), 6);
  d.querySelector('[data-grp-all="close"]').click();
  assert.strictEqual(openCount(d), 0);
  // per-policy collapse
  headFor(d, 'OPEN_GP').click();
  assert.strictEqual(openCount(d), 1);
  headFor(d, 'OPEN_GP').click();
  assert.strictEqual(openCount(d), 0);

  // ---- risk toggle OFF hides scores in the VPN tab, keeps factual state ----
  d.querySelector('[data-grp-all="open"]').click();
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(openCount(d), 6, 'expansion state survives the toggle');
  assert.strictEqual(visible(w, '#invBody td.risk-cell'), 0);
  assert.strictEqual(visible(w, '#invBody th.risk-only'), 0);
  assert.ok(!d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(d.getElementById('invBody').textContent.includes('Enabled (include)'), 'split state is not scoring');

  // ---- search filters whole policies ----
  const s = d.getElementById('invSearch');
  s.value = 'CONTR'; s.dispatchEvent(new w.Event('input'));
  await new Promise(r => setTimeout(r, 250));
  const titles = heads(d).map(h => h.querySelector('.grp-title').textContent);
  assert.ok(titles.includes('CONTR_GP') && !titles.includes('ENG_GP'), titles.join(','));
  assert.ok(!d.getElementById('invBody').textContent.includes('Engineering'));

  // ---- non-ASA: no tab ----
  const f = await loadPage('fwrra-fortios.html', FORTI);
  assert.strictEqual(f.d.getElementById('tabBar').style.display, 'none');
  const c1 = await loadPage('fwrra.html', FORTI);
  assert.strictEqual(c1.d.getElementById('tabBar').style.display, 'none');
  const c2 = await loadPage('fwrra.html', fixture('asa-vpn.cfg'));
  assert.notStrictEqual(c2.d.getElementById('tabBar').style.display, 'none');

  // ---- Review focus: HTML in names is escaped ----
  const evil = fixture('asa-vpn.cfg') +
    'tunnel-group <img/src=x/onerror=alert(1)> type remote-access\n';
  const e = await loadPage('fwrra-asa.html', evil);
  e.d.getElementById('inventoryTabBtn').click();
  e.d.querySelector('[data-grp-all="open"]').click();
  assert.strictEqual(e.d.querySelectorAll('#invBody img').length, 0, 'no live <img> from config text');
  assert.ok(e.d.getElementById('invBody').textContent.includes('<img/src=x/onerror=alert(1)>'));

  // ---- VPN CSV export (per policy) ----
  const g = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));
  let csv = '';
  g.w.Blob = function (parts) { csv = parts.join(''); };
  g.w.URL.createObjectURL = () => 'blob:x';
  g.w.URL.revokeObjectURL = () => {};
  g.w.HTMLAnchorElement.prototype.click = function () {};
  g.d.getElementById('inventoryTabBtn').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('# ENG_GP / Tunnel-groups using this policy'), csv.slice(0, 300));
  assert.ok(csv.includes('# CONTR_GP / VPN filter rules') && csv.includes('# Global / unassigned / Findings'));
  assert.ok(csv.includes('Policy,ACL,Rule #,Score,Band,Action'), 'risk ON: score columns present');
  assert.ok(csv.includes('ENG_GP,ENG,'), 'rows are prefixed with the policy name');
  assert.ok(csv.includes('Enabled (include) (from ENG_GP)'), 'cell notes are exported');
  const rt = g.d.getElementById('riskToggle');
  rt.checked = false; rt.dispatchEvent(new g.w.Event('change'));
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('Policy,ACL,Rule #,Action'), 'risk OFF: header without score');
  assert.ok(!csv.includes(',Score,') && !csv.includes(',Band,'));
  g.d.querySelector('[data-tab="rules"]').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.startsWith('Rule #,'));
};
