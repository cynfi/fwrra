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

const ASA_OUTBOUND = ASA + `access-list EGRESS extended permit ip any any log
access-list EGRESS extended deny ip any any log
access-group EGRESS out interface outside
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
    edit 4
        set name "ANY-OUT"
        set srcintf "any"
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
const zoneOpts = (d) => [...d.querySelectorAll('#filterZone option')].map(o => o.textContent);
function pick(w, d, id, value) {
  const el = d.getElementById(id);
  el.value = value;
  el.dispatchEvent(new w.Event('change'));
}
const zone = (w, d, z) => pick(w, d, 'filterZone', z);
const dir = (d, which) => d.querySelector(`#filterDir [data-dir="${which}"]`).click();
const aclOpts = (d) => [...d.querySelectorAll('#filterAcl option')].map(o => o.textContent);
const aclVal = (d, startsWith) => [...d.querySelectorAll('#filterAcl option')].find(o => o.textContent.startsWith(startsWith)).value;
const has = (d, text) => ruleRows(d).some(tr => tr.textContent.includes(text));

module.exports = async () => {
  // ---- ASA ----
  const { w, d } = await loadPage('fwrra-asa.html', ASA);
  const controls = d.querySelector('#rulesView .controls');
  assert.strictEqual(controls.children[0].id, 'filterZone', 'zone is the left-most filter');
  assert.strictEqual(controls.children[1].id, 'filterDir');
  assert.strictEqual(controls.children[2].id, 'filterAcl');

  const zo = zoneOpts(d);
  assert.deepStrictEqual(zo.map(t => t.replace(/ \(\d+\)$/, '')), ['All zones / interfaces', 'outside', 'inside', 'dmz'].filter(x => zo.some(z => z.startsWith(x))));
  assert.ok(['outside', 'inside', 'dmz'].every(n => zo.some(z => z.startsWith(n))), zo.join('|'));
  assert.ok(!zo.some(z => /any/i.test(z.replace('All zones', ''))), 'no pseudo zones in the list');
  assert.ok(d.querySelector('#filterDir [data-dir="from"]').disabled, 'direction disabled until a zone is chosen');

  const total = ruleRows(d).length;

  // outside: 2 inbound-ACL rules (From) + implicit dmz->outside (To)
  zone(w, d, 'outside');
  assert.ok(!d.querySelector('#filterDir [data-dir="from"]').disabled);
  assert.strictEqual(ruleRows(d).length, 3, 'Any = source or destination side');
  assert.strictEqual(totalCell(d), '3', 'summary follows the scope');
  dir(d, 'from');
  assert.strictEqual(ruleRows(d).length, 2);
  assert.ok(ruleRows(d).every(tr => tr.textContent.includes('OUT_IN')));
  assert.ok(!has(d, 'IMPLICIT'));
  dir(d, 'to');
  assert.strictEqual(ruleRows(d).length, 1);
  assert.ok(has(d, 'IMPLICIT'), 'implicit dmz->outside is "To outside"');

  // dmz has no ACL: only its implicit permit, From dmz
  zone(w, d, 'dmz'); dir(d, 'any');
  assert.strictEqual(ruleRows(d).length, 1);
  assert.ok(has(d, 'IMPLICIT'));
  dir(d, 'from'); assert.strictEqual(ruleRows(d).length, 1);
  dir(d, 'to'); assert.strictEqual(ruleRows(d).length, 0);

  // inside (strict): inbound ACL is From inside; nothing is claimed To anything
  zone(w, d, 'inside'); dir(d, 'any');
  assert.strictEqual(ruleRows(d).length, 3);
  dir(d, 'from'); assert.strictEqual(ruleRows(d).length, 3);
  dir(d, 'to'); assert.strictEqual(ruleRows(d).length, 0, 'strict: unknown destination side is not guessed');

  // ACL dropdown (ASA only), composes with zone
  assert.notStrictEqual(d.getElementById('filterAcl').style.display, 'none');
  const acls = aclOpts(d);
  assert.ok(acls.some(t => t.startsWith('OUT_IN') && t.includes('outside') && t.includes('in')), acls.join('|'));
  assert.ok(acls.some(t => t.startsWith('IN_OUT')));
  assert.ok(!acls.some(t => t.startsWith('UNUSED')), 'unapplied ACL never shows');
  zone(w, d, 'all');
  assert.ok(d.querySelector('#filterDir [data-dir="from"]').disabled);
  pick(w, d, 'filterAcl', aclVal(d, 'IN_OUT'));
  assert.strictEqual(ruleRows(d).length, 3);
  zone(w, d, 'outside'); dir(d, 'any');
  assert.strictEqual(ruleRows(d).length, 0, 'zone AND acl: IN_OUT never touches outside');
  pick(w, d, 'filterAcl', aclVal(d, 'OUT_IN'));
  assert.strictEqual(ruleRows(d).length, 2);
  assert.strictEqual(totalCell(d), '2');

  // composes (AND) with the other filters; summary counts the scope only
  pick(w, d, 'filterAction', 'permit');
  assert.strictEqual(ruleRows(d).length, 1);
  assert.strictEqual(totalCell(d), '2');
  pick(w, d, 'filterAction', 'all');

  // CSV follows the scope
  let csv = '';
  w.Blob = function (p) { csv = p.join(''); };
  w.URL.createObjectURL = () => 'x'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  d.getElementById('exportBtn').click();
  assert.strictEqual(csv.trim().split('\n').length, 1 + 2, 'CSV = header + 2 scoped rules');

  // scope persists across the risk toggle; reset restores everything
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(ruleRows(d).length, 2);
  pick(w, d, 'filterAcl', 'all'); zone(w, d, 'all');
  assert.strictEqual(ruleRows(d).length, total);

  // outbound ACL: "To outside" (strict - known destination side)
  const ob = await loadPage('fwrra-asa.html', ASA_OUTBOUND);
  zone(ob.w, ob.d, 'outside'); dir(ob.d, 'to');
  assert.ok(has(ob.d, 'EGRESS'), 'outbound ACL on outside is To outside');
  assert.ok(!has(ob.d, 'OUT_IN'));
  dir(ob.d, 'from');
  assert.ok(!has(ob.d, 'EGRESS') && has(ob.d, 'OUT_IN'));

  // ---- FortiOS: zones from srcintf/dstintf; "any" is a wildcard, never a zone ----
  const f = await loadPage('fwrra-fortios.html', FORTI);
  assert.strictEqual(f.d.querySelector('#rulesView .controls').children[0].id, 'filterZone');
  const fz = zoneOpts(f.d);
  assert.ok(['wan1', 'lan', 'dmz'].every(n => fz.some(z => z.startsWith(n))), fz.join('|'));
  assert.ok(!fz.some(z => z.startsWith('any')), 'any is not a zone option');
  assert.strictEqual(f.d.getElementById('filterAcl').style.display, 'none', 'no ACL control when names are per-rule');
  zone(f.w, f.d, 'wan1'); dir(f.d, 'to');
  assert.strictEqual(ruleRows(f.d).length, 4);
  dir(f.d, 'from');
  assert.strictEqual(ruleRows(f.d).length, 1, 'only the srcintf-any policy (a wildcard) can come From wan1');
  zone(f.w, f.d, 'lan'); dir(f.d, 'from');
  assert.strictEqual(ruleRows(f.d).length, 3, 'lan: two lan policies + the srcintf any policy');
  assert.strictEqual(totalCell(f.d), '3');
  dir(f.d, 'to');
  assert.strictEqual(ruleRows(f.d).length, 0);

  // ---- PAN-OS ----
  const p = await loadPage('fwrra-panos.html', PAN);
  zone(p.w, p.d, 'untrust'); dir(p.d, 'from');
  assert.strictEqual(ruleRows(p.d).length, 1);
  assert.ok(has(p.d, 'in-ssh'));
  dir(p.d, 'to');
  assert.strictEqual(ruleRows(p.d).length, 1);
  assert.ok(has(p.d, 'out-web'));
  dir(p.d, 'any');
  assert.strictEqual(ruleRows(p.d).length, 2);

  // ---- Review focus: HTML in an ACL name is not interpreted ----
  const evil = await loadPage('fwrra-asa.html', ASA.replace(/IN_OUT/g, 'IN<img/src=x/onerror=1>'));
  assert.strictEqual(evil.d.querySelectorAll('#filterAcl img, #filterZone img').length, 0);
  assert.ok([...evil.d.querySelectorAll('#filterAcl option')].some(o => o.textContent.includes('<img/src=x/onerror=1>')));

  // ---- a combined build resets cleanly per config ----
  const c = await loadPage('fwrra.html', ASA);
  zone(c.w, c.d, 'dmz');
  assert.strictEqual(ruleRows(c.d).length, 1);
};
