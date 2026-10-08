const assert = require('assert');
const { loadPage } = require('./helpers');

const ASA = `ASA Version 9.16(1)
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
interface GigabitEthernet0/2
 nameif dmz
 security-level 50
 ip address 172.16.0.1 255.255.255.0
access-list OUT_IN extended permit tcp any host 10.0.0.5 eq 443 log
access-list OUT_IN extended deny ip any any log
access-list IN_OUT extended permit tcp 10.0.0.0 255.255.255.0 any eq 443 log
access-list IN_OUT extended permit udp 10.0.0.0 255.255.255.0 any eq 53 log
access-list IN_OUT extended deny ip any any log
access-list UNUSED extended permit ip any any
access-group OUT_IN in interface outside
access-group IN_OUT in interface inside
`;

const FORTI = `#config-version=FGT60F-7.0.1-FW-build0157:opmode=0:vdom=0
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
    edit "dmz"
        set ip 172.16.0.1 255.255.255.0
        set role dmz
    next
end
config router static
    edit 1
        set device "wan1"
        set gateway 203.0.113.1
    next
end
config firewall policy
    edit 1
        set name "LAN-OUT"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 2
        set name "DMZ-OUT"
        set srcintf "dmz"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 3
        set name "LAN-OUT-2"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
`;

const PAN = `set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set rulebase security rules in-ssh from untrust
set rulebase security rules in-ssh to trust
set rulebase security rules in-ssh source any
set rulebase security rules in-ssh destination any
set rulebase security rules in-ssh application ssh
set rulebase security rules in-ssh service application-default
set rulebase security rules in-ssh action allow
set rulebase security rules out-web from trust
set rulebase security rules out-web to untrust
set rulebase security rules out-web source any
set rulebase security rules out-web destination any
set rulebase security rules out-web application web-browsing
set rulebase security rules out-web service application-default
set rulebase security rules out-web action allow
`;

const ruleRows = (d) => [...d.querySelectorAll('#ruleTableBody tr.rule-row')];
const totalCell = (d) => d.querySelector('#summary .cell .n').textContent;
const groupOpts = (d, label) => {
  const g = [...d.querySelectorAll('#filterScope optgroup')].find(o => o.label === label);
  return g ? [...g.querySelectorAll('option')].map(o => o.textContent) : null;
};
function pick(w, d, id, value) {
  const el = d.getElementById(id);
  el.value = value;
  el.dispatchEvent(new w.Event('change'));
}
const optValue = (d, startsWith) => [...d.querySelectorAll('#filterScope option')].find(o => o.textContent.startsWith(startsWith)).value;

module.exports = async () => {
  // ---- ASA: interface + ACL groups ----
  const { w, d } = await loadPage('fwrra-asa.html', ASA);
  const controls = d.querySelector('#rulesView .controls');
  assert.strictEqual(controls.firstElementChild.id, 'filterScope', 'Scope is the left-most filter');
  assert.strictEqual(d.getElementById('filterScope').options[0].value, 'all');

  const ifaces = groupOpts(d, 'Interface / path');
  assert.ok(ifaces && ifaces.some(t => t.startsWith('outside')) && ifaces.some(t => t.startsWith('inside')), ifaces && ifaces.join('|'));
  assert.ok(ifaces.some(t => /dmz/.test(t)), 'implicit dmz path is listed');
  const acls = groupOpts(d, 'ACL');
  assert.ok(acls && acls.some(t => t.startsWith('OUT_IN') && t.includes('outside') && t.includes('in')), acls && acls.join('|'));
  assert.ok(acls.some(t => t.startsWith('IN_OUT')));
  assert.ok(!acls.some(t => t.startsWith('UNUSED')), 'unapplied ACL never shows (not enforced)');

  const allCount = ruleRows(d).length;
  pick(w, d, 'filterScope', optValue(d, 'OUT_IN'));
  assert.strictEqual(ruleRows(d).length, 2);
  assert.ok(ruleRows(d).every(tr => tr.textContent.includes('OUT_IN')));
  assert.strictEqual(totalCell(d), '2', 'summary strip follows the scope');

  pick(w, d, 'filterScope', optValue(d, 'IN_OUT'));
  assert.strictEqual(ruleRows(d).length, 3);
  // composes (AND) with the other filters
  pick(w, d, 'filterAction', 'permit');
  assert.strictEqual(ruleRows(d).length, 2);
  assert.strictEqual(totalCell(d), '3', 'summary counts the scope, not the table filters');
  pick(w, d, 'filterAction', 'all');

  // interface scope
  pick(w, d, 'filterScope', optValue(d, 'outside'));
  assert.ok(ruleRows(d).length >= 2 && ruleRows(d).every(tr => tr.textContent.includes('outside')));

  // CSV export follows the scope
  let csv = '';
  w.Blob = function (p) { csv = p.join(''); };
  w.URL.createObjectURL = () => 'x'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  pick(w, d, 'filterScope', optValue(d, 'OUT_IN'));
  d.getElementById('exportBtn').click();
  assert.strictEqual(csv.trim().split('\n').length, 1 + 2, 'CSV = header + 2 scoped rules');

  // back to all
  pick(w, d, 'filterScope', 'all');
  assert.strictEqual(ruleRows(d).length, allCount);

  // scope persists while risk analysis is toggled
  pick(w, d, 'filterScope', optValue(d, 'OUT_IN'));
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(ruleRows(d).length, 2);
  assert.strictEqual(d.getElementById('filterScope').value.startsWith('acl:'), true);

  // ---- FortiOS: path group only (policy names are per-rule, so no ACL group) ----
  const f = await loadPage('fwrra-fortios.html', FORTI);
  assert.strictEqual(f.d.querySelector('#rulesView .controls').firstElementChild.id, 'filterScope');
  const fPaths = groupOpts(f.d, 'Interface / path');
  assert.ok(fPaths.some(t => t.startsWith('lan → wan1')) && fPaths.some(t => t.startsWith('dmz → wan1')), fPaths.join('|'));
  assert.strictEqual(groupOpts(f.d, 'ACL'), null, 'no ACL group when names are unique per rule');
  pick(f.w, f.d, 'filterScope', optValue(f.d, 'lan → wan1'));
  assert.strictEqual(ruleRows(f.d).length, 2);
  assert.strictEqual(totalCell(f.d), '2');

  // ---- PAN-OS ----
  const p = await loadPage('fwrra-panos.html', PAN);
  const pPaths = groupOpts(p.d, 'Interface / path');
  assert.ok(pPaths.some(t => t.startsWith('untrust → trust')) && pPaths.some(t => t.startsWith('trust → untrust')), pPaths.join('|'));
  pick(p.w, p.d, 'filterScope', optValue(p.d, 'untrust → trust'));
  assert.strictEqual(ruleRows(p.d).length, 1);
  assert.ok(ruleRows(p.d)[0].textContent.includes('in-ssh'));

  // ---- Review focus: HTML in an ACL / interface name is not interpreted ----
  const evil = await loadPage('fwrra-asa.html', ASA.replace(/IN_OUT/g, 'IN<img/src=x/onerror=1>'));
  assert.strictEqual(evil.d.querySelectorAll('#filterScope img').length, 0);
  assert.ok([...evil.d.querySelectorAll('#filterScope option')].some(o => o.textContent.includes('<img/src=x/onerror=1>')));

  // ---- loading another config resets the scope ----
  const c = await loadPage('fwrra.html', ASA);
  pick(c.w, c.d, 'filterScope', optValue(c.d, 'OUT_IN'));
  assert.strictEqual(ruleRows(c.d).length, 2);
};
