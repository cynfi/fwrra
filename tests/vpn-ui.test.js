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

module.exports = async () => {
  // ---- ASA: tab present and populated ----
  const { w, d } = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));

  // version shown in page title and header
  assert.ok(d.title.endsWith(' v1.0.9'), 'title carries version: ' + d.title);
  assert.strictEqual(d.querySelector('.header h1 .ver').textContent, 'v1.0.9');

  assert.notStrictEqual(d.getElementById('tabBar').style.display, 'none');
  assert.strictEqual(d.getElementById('inventoryTabBtn').textContent, 'Remote-access VPN');
  assert.strictEqual(d.getElementById('inventoryView').style.display, 'none', 'rules tab is the default');

  d.getElementById('inventoryTabBtn').click();
  assert.strictEqual(d.getElementById('inventoryView').style.display, '');
  assert.strictEqual(d.getElementById('rulesView').style.display, 'none');
  const heads = [...d.querySelectorAll('#invBody h3')].map(h => h.textContent);
  assert.deepStrictEqual(heads,
    ['Tunnel-groups', 'Group-policies', 'User overrides', 'Address pools', 'VPN filter rules', 'Findings']);
  const body = d.getElementById('invBody').textContent;
  assert.ok(body.includes('Enabled (include)') && body.includes('Enabled (exclude)') && body.includes('Disabled'));
  assert.ok(body.includes('inherited: DfltGrpPolicy'));

  // expand a tunnel-group row -> detail shows split networks
  const engRow = [...d.querySelectorAll('#invBody tr.rule-row')].find(tr => tr.textContent.includes('Engineering'));
  engRow.click();
  assert.ok(d.getElementById('invBody').textContent.includes('Split-tunnel networks'));

  // VPN filter rules: one collapsed group per unique filter ACL, with +/-
  const gheads = () => [...d.querySelectorAll('#invBody .grp-head')];
  const gtitles = () => gheads().map(h => h.querySelector('.grp-title').textContent);
  const gopen = () => d.querySelectorAll('#invBody .grp.open').length;
  assert.deepStrictEqual(gtitles(), ['ENG_FILTER', 'CONTR_FILTER']);
  assert.strictEqual(gopen(), 0, 'filter groups collapsed by default');
  assert.strictEqual(gheads()[0].querySelector('.grp-toggle').textContent, '+');
  assert.ok(gheads()[0].textContent.includes('2 rules') && gheads()[0].textContent.includes('policies: ENG_GP, CONTR_GP'));
  assert.ok(visible(w, '#invBody .grp-head .risk-only') > 0, 'risk chip visible while risk is ON');
  gheads()[0].click();
  assert.strictEqual(gopen(), 1);
  assert.strictEqual(gheads()[0].querySelector('.grp-toggle').textContent, '\u2212');
  assert.ok(d.getElementById('invBody').textContent.includes('user alice'), 'used-by lists every identity');
  // a filter rule row expands with the risk calculation while risk is ON
  const grpBody = d.querySelector('#invBody .grp.open .grp-body');
  [...grpBody.querySelectorAll('h4')].find(h => h.textContent === 'Rules').nextSibling.querySelector('tr.rule-row').click();
  assert.ok(d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(visible(w, '#invBody td.risk-cell') > 0);
  // Expand all / Collapse all
  d.querySelector('[data-grp-all="open"]').click();
  assert.strictEqual(gopen(), 2);
  d.querySelector('[data-grp-all="close"]').click();
  assert.strictEqual(gopen(), 0);
  d.querySelector('[data-grp-all="open"]').click();

  // ---- risk toggle OFF hides scores in the VPN tab, keeps factual state ----
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(gopen(), 2, 'expansion state survives the toggle');
  assert.strictEqual(visible(w, '#invBody td.risk-cell'), 0);
  assert.strictEqual(visible(w, '#invBody .grp-head .risk-only'), 0, 'risk chip hidden when risk is OFF');
  assert.strictEqual(visible(w, '#invBody th.risk-only'), 0);
  assert.ok(!d.getElementById('invBody').textContent.includes('Risk calculation'));
  assert.ok(d.getElementById('invBody').textContent.includes('Enabled (include)'), 'split state is not scoring');

  // ---- search filters rows ----
  const s = d.getElementById('invSearch');
  s.value = 'CONTR'; s.dispatchEvent(new w.Event('input'));
  await new Promise(r => setTimeout(r, 250));
  const bodyText = d.getElementById('invBody').textContent;
  assert.ok(bodyText.includes('CONTR_GP') && !bodyText.includes('Engineering'));

  // ---- non-ASA: no tab ----
  const f = await loadPage('fwrra-fortios.html', FORTI);
  assert.strictEqual(f.d.getElementById('tabBar').style.display, 'none');
  // combined build with a non-ASA config: no tab; with ASA config: tab
  const c1 = await loadPage('fwrra.html', FORTI);
  assert.strictEqual(c1.d.getElementById('tabBar').style.display, 'none');
  const c2 = await loadPage('fwrra.html', fixture('asa-vpn.cfg'));
  assert.notStrictEqual(c2.d.getElementById('tabBar').style.display, 'none');

  // ---- Review focus: HTML in names is escaped ----
  const evil = fixture('asa-vpn.cfg') +
    'tunnel-group <img/src=x/onerror=alert(1)> type remote-access\n';
  const e = await loadPage('fwrra-asa.html', evil);
  e.d.getElementById('inventoryTabBtn').click();
  assert.strictEqual(e.d.querySelectorAll('#invBody img').length, 0, 'no live <img> from config text');
  assert.ok(e.d.getElementById('invBody').textContent.includes('<img/src=x/onerror=alert(1)>'));

  // ---- VPN CSV export ----
  const g = await loadPage('fwrra-asa.html', fixture('asa-vpn.cfg'));
  let csv = '';
  g.w.Blob = function (parts) { csv = parts.join(''); };
  g.w.URL.createObjectURL = () => 'blob:x';
  g.w.URL.revokeObjectURL = () => {};
  g.w.HTMLAnchorElement.prototype.click = function () {};
  g.d.getElementById('inventoryTabBtn').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('# Tunnel-groups') && csv.includes('# Findings'));
  assert.ok(csv.includes('# ENG_FILTER / Rules') && csv.includes('# CONTR_FILTER / Used by'));
  assert.ok(csv.includes('Filter ACL,ACL,Rule #,Score,Band,Action'), 'risk ON: score columns present');
  assert.ok(csv.includes('Enabled (include) (from ENG_GP)'), 'cell notes are exported');
  const rt = g.d.getElementById('riskToggle');
  rt.checked = false; rt.dispatchEvent(new g.w.Event('change'));
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.includes('Filter ACL,ACL,Rule #,Action'), 'risk OFF: header without score');
  assert.ok(!csv.includes(',Score,') && !csv.includes(',Band,'));
  // rules tab export is unchanged: starts with the rule header
  g.d.querySelector('[data-tab="rules"]').click();
  g.d.getElementById('exportBtn').click();
  assert.ok(csv.startsWith('Rule #,'));
};
