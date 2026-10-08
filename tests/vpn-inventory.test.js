const assert = require('assert');
const { loadVendor, fixture, plain } = require('./helpers');

const ct = (c) => (c && typeof c === 'object') ? c.text : c;
const note = (c) => (c && typeof c === 'object') ? c.note : undefined;
const tone = (c) => (c && typeof c === 'object') ? c.tone : undefined;

module.exports = async () => {
  const asa = loadVendor('fwrra-asa.html', 'asa');
  assert.strictEqual(typeof asa.buildInventory, 'function', 'ASA must register buildInventory');
  const inv = plain(asa.buildInventory(asa.parse(fixture('asa-vpn.cfg')), {}));
  const sec = (id) => inv.sections.find(s => s.id === id);
  const row = (id, name) => sec(id).rows.find(r => ct(r.cells.name) === name);

  assert.strictEqual(inv.title, 'Remote-access VPN');
  assert.deepStrictEqual(inv.sections.map(s => s.id),
    ['tunnel-groups', 'group-policies', 'users', 'pools', 'filter-rules', 'findings']);

  // tunnel-groups: site-to-site excluded, 4 remote-access rows
  assert.strictEqual(sec('tunnel-groups').rows.length, 4);
  assert.strictEqual(row('tunnel-groups', '198.51.100.7'), undefined);

  // ENG: split include, comes from its group-policy; filter from group-policy
  const eng = row('tunnel-groups', 'ENG');
  assert.strictEqual(ct(eng.cells.split), 'Enabled (include)');
  assert.strictEqual(note(eng.cells.split), 'from ENG_GP');
  assert.strictEqual(ct(eng.cells.filter), 'ENG_FILTER');
  assert.ok(ct(eng.cells.pools).includes('ENG_POOL') && ct(eng.cells.pools).includes('50'));
  assert.strictEqual(note(eng.cells.pools), 'from ENG_GP');
  assert.ok(ct(eng.cells.alias).includes('Engineering'));

  // CONTR: split exclude; pool comes from the tunnel-group itself (no note)
  const contr = row('tunnel-groups', 'CONTR');
  assert.strictEqual(ct(contr.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(contr.cells.pools), undefined);

  // INH: nothing set -> inherits DfltGrpPolicy tunnelall -> Disabled
  const inh = row('tunnel-groups', 'INH');
  assert.strictEqual(ct(inh.cells.split), 'Disabled');
  assert.strictEqual(note(inh.cells.split), 'inherited: DfltGrpPolicy');
  assert.strictEqual(ct(inh.cells.filter), 'none');
  assert.strictEqual(tone(inh.cells.filter), 'warn');

  // OPEN: explicit "vpn-filter none" and split enabled with no list -> flagged
  const open = row('tunnel-groups', 'OPEN');
  assert.strictEqual(ct(open.cells.filter), 'none (explicit)');
  assert.strictEqual(ct(open.cells.split), 'Enabled (include)');
  assert.strictEqual(tone(open.cells.split), 'warn');

  // group-policies: referenced ones + DfltGrpPolicy
  assert.deepStrictEqual(sec('group-policies').rows.map(r => ct(r.cells.name)),
    ['DfltGrpPolicy', 'ENG_GP', 'CONTR_GP', 'OPEN_GP', 'INHERIT_GP']);
  const dflt = row('group-policies', 'DfltGrpPolicy');
  assert.strictEqual(ct(dflt.cells.split), 'Disabled');
  assert.strictEqual(note(dflt.cells.split), undefined, 'own value => no note');
  assert.strictEqual(ct(row('group-policies', 'ENG_GP').cells.logins), '2');

  // user override: own filter, framed IP, split from its group-policy
  const alice = row('users', 'alice');
  assert.strictEqual(ct(alice.cells.groupPolicy), 'CONTR_GP');
  assert.strictEqual(ct(alice.cells.filter), 'ENG_FILTER');
  assert.strictEqual(note(alice.cells.filter), undefined);
  assert.strictEqual(ct(alice.cells.pools), '10.9.0.99 (framed)');
  assert.strictEqual(ct(alice.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(alice.cells.split), 'from CONTR_GP');

  // pools
  const ep = row('pools', 'ENG_POOL');
  assert.strictEqual(ct(ep.cells.count), '50');
  assert.ok(ct(ep.cells.usedBy).includes('tunnel-group ENG'));

  // detail blocks exist and the split networks resolve
  assert.ok(eng.detail.some(b => b.kind === 'networks' && b.entries.length === 1));

  // findings (factual, not scored)
  const f = sec('findings').rows.map(r => `${ct(r.cells.level)}|${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(f.some(x => x.startsWith('info|Global|sysopt connection permit-vpn')));
  assert.ok(f.some(x => /warn\|tunnel-group OPEN\|no vpn-filter \(explicit "none"\)/.test(x)));
  assert.ok(f.some(x => /warn\|tunnel-group INH\|no vpn-filter \(unset\)/.test(x)));
  assert.ok(f.some(x => /warn\|tunnel-group OPEN\|split tunneling enabled but no split-tunnel-network-list/.test(x)));

  // Review focus: no VPN content at all -> null (no tab)
  assert.strictEqual(asa.buildInventory(asa.parse('interface Gi0/0\n nameif outside\n security-level 0\n'), {}), null);

  // Review focus: dangling references -> warn findings, no exception
  const dangling = [
    'ip local pool P1 10.1.1.1-10.1.1.5 mask 255.255.255.0',
    'tunnel-group T1 type remote-access',
    'tunnel-group T1 general-attributes',
    ' address-pool NOPOOL',
    ' default-group-policy NOGP',
    'group-policy G2 internal',
    'group-policy G2 attributes',
    ' vpn-filter value NOACL',
    ' split-tunnel-policy tunnelspecified',
    ' split-tunnel-network-list value NOSPLIT',
    'tunnel-group T2 type remote-access',
    'tunnel-group T2 general-attributes',
    ' default-group-policy G2',
    '',
  ].join('\n');
  const dinv = plain(asa.buildInventory(asa.parse(dangling), {}));
  const df = dinv.sections.find(s => s.id === 'findings').rows.map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(df.some(x => /tunnel-group T1\|default-group-policy NOGP is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T1\|address pool NOPOOL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|vpn-filter ACL NOACL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|split tunneling enabled but split-tunnel ACL NOSPLIT is not defined/.test(x)));

  // ---- filter rule rows (scored) ----
  const fr = sec('filter-rules');
  assert.ok(fr && Array.isArray(fr.ruleRows), 'filter-rules section with ruleRows');
  // ENG_FILTER (2 ACEs) + CONTR_FILTER (3 ACEs), one row per distinct ACE
  assert.strictEqual(fr.ruleRows.length, 5);
  assert.ok(fr.ruleRows.every(r => r.id >= 100000 && r.type === 'rule' && r.interface === 'vpn-filter'));
  assert.strictEqual(new Set(fr.ruleRows.map(r => r.id)).size, 5, 'row ids unique');
  const e1 = fr.ruleRows[0], e2 = fr.ruleRows[1];
  assert.strictEqual(e1.aclName, 'ENG_FILTER');
  assert.strictEqual(e1.ruleNumber, 1);
  assert.deepStrictEqual(e1.usedBy, ['tunnel-group ENG', 'group-policy ENG_GP', 'user alice']);
  assert.strictEqual(e1.scored.action, 'permit');
  assert.strictEqual(typeof e1.scored.score, 'number');
  assert.notStrictEqual(e1.scored.score, e2.scored.score, 'different ACEs score differently');
  const contrRows = fr.ruleRows.filter(r => r.aclName === 'CONTR_FILTER');
  assert.deepStrictEqual(contrRows[0].usedBy, ['tunnel-group CONTR', 'group-policy CONTR_GP']);
  assert.strictEqual(contrRows[1].inactive, true);
  assert.strictEqual(contrRows[2].scored.action, 'deny');
  assert.strictEqual(contrRows[2].scored.score, 0);
  assert.strictEqual(contrRows[2].scored.srcResolved.kind, 'any', 'deny rows must carry resolved endpoints');
  assert.ok(contrRows[2].scored.services.length >= 1);
};
