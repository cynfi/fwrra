const assert = require('assert');
const { fixture, loadPage } = require('./helpers');

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
end
config router static
    edit 1
        set device "wan1"
        set gateway 203.0.113.1
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
`;

const PAN = `set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set rulebase security rules r1 from untrust
set rulebase security rules r1 to trust
set rulebase security rules r1 source any
set rulebase security rules r1 destination any
set rulebase security rules r1 application ssh
set rulebase security rules r1 service application-default
set rulebase security rules r1 action allow
`;

const visible = (w, sel) => [...w.document.querySelectorAll(sel)]
  .filter(e => w.getComputedStyle(e).display !== 'none').length;

async function check(file, cfg) {
  const { w, d } = await loadPage(file, cfg);
  assert.ok(d.querySelectorAll('td.risk-cell').length > 0, file + ': rows rendered');
  d.querySelector('tr.rule-row').click();
  assert.ok(d.querySelector('.detail-row').textContent.includes('Risk calculation'));

  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(d.body.className.includes('no-risk'), true);
  assert.strictEqual(visible(w, 'td.risk-cell'), 0, file + ': risk cells hidden');
  assert.strictEqual(visible(w, 'th.risk-only'), 0);
  assert.strictEqual(visible(w, '#filterBand'), 0);
  assert.strictEqual(visible(w, '#filterPolicy'), 0);
  assert.strictEqual(d.querySelectorAll('.policy-pill').length, 0);
  assert.ok(!d.querySelector('.detail-row').textContent.includes('Risk calculation'));
  assert.ok(!/heuristic/.test(d.getElementById('footerNote').textContent));
  assert.strictEqual(visible(w, '.summary .cell'), 3);

  let csv = '';
  w.Blob = function (p) { csv = p.join(''); };
  w.URL.createObjectURL = () => 'x'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  d.getElementById('exportBtn').click();
  assert.ok(!csv.split('\n')[0].includes('Score'), file + ': CSV header has no score columns');

  t.checked = true; t.dispatchEvent(new w.Event('change'));
  assert.strictEqual(visible(w, 'td.risk-cell') > 0, true, file + ': restored');
  assert.strictEqual(visible(w, '.summary .cell'), 9);
}

module.exports = async () => {
  await check('fwrra-asa.html', fixture('asa-vpn.cfg'));
  await check('fwrra-fortios.html', FORTI);
  await check('fwrra-panos.html', PAN);
  await check('fwrra.html', FORTI);
};
