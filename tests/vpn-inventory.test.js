const assert = require('assert');
const { loadVendor, fixture, plain } = require('./helpers');

const ct = (c) => (c && typeof c === 'object') ? c.text : c;
const note = (c) => (c && typeof c === 'object') ? c.note : undefined;
const tone = (c) => (c && typeof c === 'object') ? c.tone : undefined;

module.exports = async () => {
  const asa = loadVendor('fwrra-asa.html', 'asa');
  assert.strictEqual(typeof asa.buildInventory, 'function', 'ASA must register buildInventory');
  const inv = plain(asa.buildInventory(asa.parse(fixture('asa-vpn.cfg')), {}));

  assert.strictEqual(inv.title, 'Remote-access VPN');
  assert.strictEqual(inv.sections.length, 1);
  const psec = inv.sections[0];
  assert.strictEqual(psec.id, 'policies');
  assert.strictEqual(psec.heading, 'VPN policies');

  const groups = psec.groups;
  const grp = (t) => groups.find(g => g.title === t);
  const sec = (g, id) => g.sections.find(s => s.id === id);
  const row = (g, id, name) => sec(g, id).rows.find(r => ct(r.cells.name) === name);

  // one block per group-policy (Dflt first), plus the global/unassigned block
  assert.deepStrictEqual(groups.map(g => g.title),
    ['DfltGrpPolicy', 'ENG_GP', 'CONTR_GP', 'OPEN_GP', 'INHERIT_GP', 'Global / unassigned']);
  assert.ok(groups.every(g => typeof g.key === 'string' && Array.isArray(g.summary) && Array.isArray(g.sections)));
  assert.strictEqual(new Set(groups.map(g => g.key)).size, groups.length, 'group keys unique');

  // site-to-site tunnel-group excluded everywhere
  for (const g of groups) {
    const t = sec(g, 'tunnel-groups');
    if (t) assert.ok(!t.rows.some(r => ct(r.cells.name) === '198.51.100.7'));
  }

  // ---- ENG_GP ----
  const engG = grp('ENG_GP');
  assert.deepStrictEqual(engG.sections.map(s => s.id), ['settings', 'tunnel-groups', 'filter-rules', 'findings'].filter(id => sec(engG, id)));
  const engSummary = engG.summary.map(ct).join(' | ');
  assert.ok(engSummary.includes('split: Enabled (include)'), engSummary);
  assert.ok(engSummary.includes('filter: ENG_FILTER'), engSummary);
  assert.ok(engSummary.includes('ENG_POOL'), engSummary);
  assert.ok(engSummary.includes('1 tunnel-group'), engSummary);
  const eng = row(engG, 'tunnel-groups', 'ENG');
  assert.strictEqual(ct(eng.cells.split), 'Enabled (include)');
  assert.strictEqual(note(eng.cells.split), 'from ENG_GP');
  assert.strictEqual(ct(eng.cells.filter), 'ENG_FILTER');
  assert.ok(ct(eng.cells.pools).includes('ENG_POOL') && ct(eng.cells.pools).includes('50'));
  assert.strictEqual(note(eng.cells.pools), 'from ENG_GP');
  assert.ok(ct(eng.cells.alias).includes('Engineering'));
  assert.ok(eng.detail.some(b => b.kind === 'networks' && b.entries.length === 1));
  const engSettings = (n) => sec(engG, 'settings').rows.find(r => ct(r.cells.name) === n);
  assert.strictEqual(ct(engSettings('Simultaneous logins').cells.value), '2');
  assert.strictEqual(ct(engSettings('Split tunneling').cells.value).startsWith('Enabled (include)'), true);
  assert.ok(engSettings('Split tunneling').detail.some(b => b.kind === 'networks' && b.entries.length === 1));
  const engRules = sec(engG, 'filter-rules').ruleRows;
  assert.strictEqual(engRules.length, 2);
  assert.deepStrictEqual(engRules[0].usedBy, ['tunnel-group ENG', 'group-policy ENG_GP']);
  assert.strictEqual(engRules[0].aclName, 'ENG_FILTER');
  assert.strictEqual(engRules[0].ruleNumber, 1);
  assert.ok(engRules.every(r => r.interface === 'vpn-filter' && r.type === 'rule' && r.id >= 100000));
  assert.strictEqual(typeof engRules[0].scored.score, 'number');
  assert.notStrictEqual(engRules[0].scored.score, engRules[1].scored.score);

  // ---- CONTR_GP: tunnel-group + user override with its own filter ----
  const conG = grp('CONTR_GP');
  const contr = row(conG, 'tunnel-groups', 'CONTR');
  assert.strictEqual(ct(contr.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(contr.cells.pools), undefined);
  const alice = row(conG, 'users', 'alice');
  assert.strictEqual(ct(alice.cells.filter), 'ENG_FILTER');
  assert.strictEqual(note(alice.cells.filter), undefined);
  assert.strictEqual(ct(alice.cells.pools), '10.9.0.99 (framed)');
  assert.strictEqual(ct(alice.cells.split), 'Enabled (exclude)');
  assert.strictEqual(note(alice.cells.split), 'from CONTR_GP');
  assert.ok(conG.summary.map(ct).join(' | ').includes('1 user'));
  const conRules = sec(conG, 'filter-rules').ruleRows;
  assert.strictEqual(conRules.length, 5, 'CONTR_FILTER (3) + alice ENG_FILTER (2)');
  const cf = conRules.filter(r => r.aclName === 'CONTR_FILTER');
  assert.deepStrictEqual(cf[0].usedBy, ['tunnel-group CONTR', 'group-policy CONTR_GP']);
  assert.strictEqual(cf[1].inactive, true);
  assert.strictEqual(cf[2].scored.action, 'deny');
  assert.strictEqual(cf[2].scored.score, 0);
  assert.strictEqual(cf[2].scored.srcResolved.kind, 'any', 'deny rows must carry resolved endpoints');
  assert.ok(cf[2].scored.services.length >= 1);
  assert.deepStrictEqual(conRules.filter(r => r.aclName === 'ENG_FILTER')[0].usedBy, ['user alice']);

  // ---- INHERIT_GP: nothing set -> inherits DfltGrpPolicy tunnelall -> Disabled ----
  const inhG = grp('INHERIT_GP');
  const inh = row(inhG, 'tunnel-groups', 'INH');
  assert.strictEqual(ct(inh.cells.split), 'Disabled');
  assert.strictEqual(note(inh.cells.split), 'inherited: DfltGrpPolicy');
  assert.strictEqual(ct(inh.cells.filter), 'none');
  assert.strictEqual(tone(inh.cells.filter), 'warn');
  assert.ok(inhG.summary.some(c => tone(c) === 'warn' && /warning/.test(ct(c))), 'warning chip in summary');
  assert.ok(sec(inhG, 'findings').rows.some(r => /tunnel-group INH/.test(ct(r.cells.subject)) && /no vpn-filter \(unset\)/.test(ct(r.cells.finding))));
  assert.strictEqual(sec(inhG, 'filter-rules'), undefined, 'no filter ACL -> no rules section');

  // ---- OPEN_GP: explicit none + split enabled with no list ----
  const openG = grp('OPEN_GP');
  const open = row(openG, 'tunnel-groups', 'OPEN');
  assert.strictEqual(ct(open.cells.filter), 'none (explicit)');
  assert.strictEqual(ct(open.cells.split), 'Enabled (include)');
  assert.strictEqual(tone(open.cells.split), 'warn');
  const of = sec(openG, 'findings').rows.map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(of.some(x => /tunnel-group OPEN\|no vpn-filter \(explicit "none"\)/.test(x)));
  assert.ok(of.some(x => /tunnel-group OPEN\|split tunneling enabled but no split-tunnel-network-list/.test(x)));

  // ---- DfltGrpPolicy: own values, no note; nothing attached ----
  const dG = grp('DfltGrpPolicy');
  const dSplit = sec(dG, 'settings').rows.find(r => ct(r.cells.name) === 'Split tunneling');
  assert.strictEqual(ct(dSplit.cells.value), 'Disabled');
  assert.strictEqual(note(dSplit.cells.value), undefined, 'own value => no note');
  assert.deepStrictEqual(dG.sections.map(s => s.id), ['settings']);

  // ---- Global / unassigned ----
  const gl = grp('Global / unassigned');
  const gf = sec(gl, 'findings').rows.map(r => `${ct(r.cells.level)}|${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(gf.some(x => x.startsWith('info|Global|sysopt connection permit-vpn')));
  assert.ok(gf.some(x => /^info\|Global\|Attributes supplied by RADIUS/.test(x)));

  // rule-row ids unique across the whole inventory
  const ids = groups.flatMap(g => g.sections.filter(s => s.ruleRows).flatMap(s => s.ruleRows.map(r => r.id)));
  assert.strictEqual(new Set(ids).size, ids.length, 'rule row ids unique across groups');

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
  const dg = dinv.sections[0].groups;
  assert.ok(dg.some(g => g.title === 'NOGP (not defined)'), dg.map(g => g.title).join(','));
  const df = dg.flatMap(g => (g.sections.find(s => s.id === 'findings') || { rows: [] }).rows)
    .map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(df.some(x => /tunnel-group T1\|default-group-policy NOGP is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T1\|address pool NOPOOL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|vpn-filter ACL NOACL is not defined/.test(x)));
  assert.ok(df.some(x => /tunnel-group T2\|split tunneling enabled but split-tunnel ACL NOSPLIT is not defined/.test(x)));
  // unused pool lands in Global / unassigned
  const dgl = dg.find(g => g.title === 'Global / unassigned');
  assert.ok(dgl.sections.some(s => s.id === 'pools' && s.rows.some(r => ct(r.cells.name) === 'P1')));

  // group-lock without vpn-group-policy: user lands in, and inherits from, the locked tunnel-group's policy
  const lock = [
    'ip local pool P 10.2.0.1-10.2.0.9 mask 255.255.255.0',
    'access-list ENGF extended permit tcp 10.2.0.0 255.255.255.0 host 10.0.0.5 eq 22',
    'group-policy GP_ENG internal',
    'group-policy GP_ENG attributes',
    ' vpn-filter value ENGF',
    ' split-tunnel-policy excludespecified',
    ' split-tunnel-network-list value NONE',
    'tunnel-group ENG type remote-access',
    'tunnel-group ENG general-attributes',
    ' address-pool P',
    ' default-group-policy GP_ENG',
    'username bob attributes',
    ' group-lock value ENG',
    '',
  ].join('\n');
  const linv = plain(asa.buildInventory(asa.parse(lock), {}));
  const lg = linv.sections[0].groups.find(g => g.title === 'GP_ENG');
  const bob = lg.sections.find(s => s.id === 'users').rows.find(r => ct(r.cells.name) === 'bob');
  assert.strictEqual(ct(bob.cells.filter), 'ENGF', 'user inherits locked tunnel-group policy filter');
  assert.strictEqual(note(bob.cells.filter), 'from GP_ENG');
  assert.strictEqual(ct(bob.cells.split), 'Enabled (exclude)');
  const lf = lg.sections.find(s => s.id === 'findings').rows.map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(!lf.some(x => /user bob\|no vpn-filter/.test(x)), 'no false "no vpn-filter" for bob');

  // user with no policy and no lock -> Global / unassigned
  const noPol = linv; // bob is locked; build another config
  const np = plain(asa.buildInventory(asa.parse(lock + 'username carl attributes\n vpn-framed-ip-address 10.2.0.7 255.255.255.0\n'), {}));
  const npl = np.sections[0].groups.find(g => g.title === 'Global / unassigned');
  assert.ok(npl.sections.find(s => s.id === 'users').rows.some(r => ct(r.cells.name) === 'carl'));

  // built-in default tunnel-groups have no "type" line in show run
  const builtin = [
    'group-policy GPW internal',
    'group-policy GPW attributes',
    ' vpn-filter value WF',
    'access-list WF extended permit ip 10.3.0.0 255.255.255.0 any',
    'tunnel-group DefaultWEBVPNGroup general-attributes',
    ' default-group-policy GPW',
    '',
  ].join('\n');
  const binv = plain(asa.buildInventory(asa.parse(builtin), {}));
  assert.ok(binv, 'built-in default group alone must produce an inventory');
  const bg = binv.sections[0].groups.find(g => g.title === 'GPW');
  assert.deepStrictEqual(bg.sections.find(s => s.id === 'tunnel-groups').rows.map(r => ct(r.cells.name)), ['DefaultWEBVPNGroup']);
};
