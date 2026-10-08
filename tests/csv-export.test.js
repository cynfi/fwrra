const assert = require('assert');
const { fixture, loadPage } = require('./helpers');

const ASA = `ASA Version 9.16(1)
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
object network WEB
 host 10.0.0.9
object-group network INNER
 network-object host 10.0.0.62
 network-object 10.5.0.0 255.255.255.0
object-group network ENG_SERVERS
 network-object host 10.0.0.60
 network-object host 10.0.0.61
 group-object INNER
 network-object host 10.0.0.60
object-group network EMPTY_GRP
access-list OUT_IN extended permit tcp any object-group ENG_SERVERS eq 22 log
access-list OUT_IN extended permit tcp host 10.1.1.1 object WEB eq 443 log
access-list OUT_IN extended permit tcp object-group ENG_SERVERS any eq 25 log
access-list OUT_IN extended deny ip any object-group EMPTY_GRP log
access-group OUT_IN in interface outside
`;

// Minimal RFC-4180 parser: returns rows of fields (handles quotes and "" escapes).
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}

async function exportCsv(file, cfg, prepare) {
  const { w, d } = await loadPage(file, cfg);
  let csv = '';
  w.Blob = function (p) { csv = p.join(''); };
  w.URL.createObjectURL = () => 'x'; w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () {};
  if (prepare) prepare(w, d);
  d.getElementById('exportBtn').click();
  return { csv, w, d };
}

module.exports = async () => {
  // ---- rules CSV: groups enumerated to individual addresses ----
  const { csv, w, d } = await exportCsv('fwrra-asa.html', ASA);
  const rows = parseCsv(csv.trim());
  const H = rows[0];
  const col = (name) => H.indexOf(name);
  assert.ok(col('Source') >= 0 && col('Destination') >= 0);
  assert.deepStrictEqual(H.slice(-2), ['Source Group', 'Destination Group'], 'group-name columns are appended');
  assert.ok(rows.slice(1).every(r => r.length === H.length), 'every row has the same column count');

  const byAction = rows.slice(1);
  const r1 = byAction.find(r => r[col('Service')].includes('22'));
  assert.strictEqual(r1[col('Source')], 'any');
  assert.strictEqual(r1[col('Destination')], '10.0.0.60,10.0.0.61,10.0.0.62,10.5.0.0/24',
    'nested groups flattened, duplicates removed, subnets as addr/prefix');
  assert.strictEqual(r1[col('Destination Group')], 'ENG_SERVERS');
  assert.strictEqual(r1[col('Source Group')], '');
  assert.ok(csv.includes('"10.0.0.60,10.0.0.61,10.0.0.62,10.5.0.0/24"'), 'comma-separated list is quoted as one field');

  // group on the source side
  const r3 = byAction.find(r => r[col('Service')].includes('25'));
  assert.strictEqual(r3[col('Source')], '10.0.0.60,10.0.0.61,10.0.0.62,10.5.0.0/24');
  assert.strictEqual(r3[col('Source Group')], 'ENG_SERVERS');
  assert.strictEqual(r3[col('Destination')], 'any');

  // non-group endpoints keep their existing text
  const r2 = byAction.find(r => r[col('Service')].includes('443'));
  assert.strictEqual(r2[col('Source')], '10.1.1.1');
  assert.strictEqual(r2[col('Destination')], '10.0.0.9 (WEB)');
  assert.strictEqual(r2[col('Destination Group')], '');

  // Review focus: an empty group exports as a marked empty list, not a blank
  const r4 = byAction.find(r => r[col('Action')] === 'deny');
  assert.strictEqual(r4[col('Destination')], '(empty)');
  assert.strictEqual(r4[col('Destination Group')], 'EMPTY_GRP');

  // risk toggle off: still appended at the end
  const t = d.getElementById('riskToggle');
  t.checked = false; t.dispatchEvent(new w.Event('change'));
  let csv2 = '';
  w.Blob = function (p) { csv2 = p.join(''); };
  d.getElementById('exportBtn').click();
  const H2 = parseCsv(csv2.trim())[0];
  assert.ok(!H2.includes('Score'));
  assert.deepStrictEqual(H2.slice(-2), ['Source Group', 'Destination Group']);

  // ---- VPN tab CSV: filter rules enumerate groups too ----
  const v = await exportCsv('fwrra-asa.html', fixture('asa-vpn.cfg'), (w2, d2) => d2.getElementById('inventoryTabBtn').click());
  const vrows = parseCsv(v.csv);
  const vh = vrows.find(r => r[0] === 'Filter ACL' && r.includes('Destination'));
  assert.ok(vh, 'filter-rules header present');
  assert.deepStrictEqual(vh.slice(-2), ['Source Group', 'Destination Group']);
  const ssh = vrows.find(r => r[0] === 'ENG_FILTER' && r[vh.indexOf('Service')] && r[vh.indexOf('Service')].includes('22'));
  assert.strictEqual(ssh[vh.indexOf('Destination')], '10.0.0.60,10.0.0.61');
  assert.strictEqual(ssh[vh.indexOf('Destination Group')], 'ENG_SERVERS');
};
