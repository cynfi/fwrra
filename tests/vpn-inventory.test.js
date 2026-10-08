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

  // ---- VPN filter rules: one expandable group per unique filter ACL ----
  const fr = sec('filter-rules');
  assert.ok(fr && Array.isArray(fr.groups) && !fr.ruleRows, 'filter-rules is a groups section');
  assert.strictEqual(fr.groupLabel, 'Filter ACL');
  assert.deepStrictEqual(fr.groups.map(g => g.title), ['ENG_FILTER', 'CONTR_FILTER']);
  assert.strictEqual(new Set(fr.groups.map(g => g.key)).size, 2, 'group keys unique');
  const fg = (t) => fr.groups.find(g => g.title === t);
  const used = (g) => g.sections.find(s => s.id === 'used-by').rows
    .map(r => `${ct(r.cells.kind)} ${ct(r.cells.name)} -> ${ct(r.cells.policy)}`);

  const eg = fg('ENG_FILTER');
  assert.deepStrictEqual(eg.sections.map(s => s.id), ['used-by', 'rules']);
  assert.deepStrictEqual(used(eg),
    ['tunnel-group ENG -> ENG_GP', 'group-policy ENG_GP -> ENG_GP', 'user alice -> CONTR_GP']);
  const egSummary = eg.summary.map(ct).join(' | ');
  assert.ok(egSummary.includes('2 rules'), egSummary);
  assert.ok(egSummary.includes('policies: ENG_GP, CONTR_GP'), egSummary);
  assert.ok(eg.summary.some(c => c.risk === true && /highest risk: \d+/.test(ct(c))), 'risk chip is flagged risk');
  const er = eg.sections.find(s => s.id === 'rules').ruleRows;
  assert.strictEqual(er.length, 2);
  assert.ok(er.every(r => r.id >= 100000 && r.type === 'rule' && r.interface === 'vpn-filter' && r.aclName === 'ENG_FILTER'));
  assert.deepStrictEqual(er[0].usedBy, ['tunnel-group ENG', 'group-policy ENG_GP', 'user alice']);
  assert.strictEqual(er[0].ruleNumber, 1);
  assert.strictEqual(er[0].scored.action, 'permit');
  assert.strictEqual(typeof er[0].scored.score, 'number');
  assert.notStrictEqual(er[0].scored.score, er[1].scored.score, 'different ACEs score differently');

  const cg = fg('CONTR_FILTER');
  assert.deepStrictEqual(used(cg), ['tunnel-group CONTR -> CONTR_GP', 'group-policy CONTR_GP -> CONTR_GP']);
  const cr = cg.sections.find(s => s.id === 'rules').ruleRows;
  assert.strictEqual(cr.length, 3);
  assert.strictEqual(cr[1].inactive, true);
  assert.strictEqual(cr[2].scored.action, 'deny');
  assert.strictEqual(cr[2].scored.score, 0);
  assert.strictEqual(cr[2].scored.srcResolved.kind, 'any', 'deny rows must carry resolved endpoints');
  assert.ok(cr[2].scored.services.length >= 1);
  const allIds = fr.groups.flatMap(g => g.sections.filter(s => s.ruleRows).flatMap(s => s.ruleRows.map(r => r.id)));
  assert.strictEqual(new Set(allIds).size, allIds.length, 'rule row ids unique across groups');

  // the SAME filter used by several policies -> ONE group listing every policy
  const shared = [
    'access-list SHARED extended permit ip 10.5.0.0 255.255.255.0 host 10.0.0.9',
    'group-policy A internal',
    'group-policy A attributes',
    ' vpn-filter value SHARED',
    'group-policy B internal',
    'group-policy B attributes',
    ' vpn-filter value SHARED',
    'tunnel-group TA type remote-access',
    'tunnel-group TA general-attributes',
    ' default-group-policy A',
    'tunnel-group TB type remote-access',
    'tunnel-group TB general-attributes',
    ' default-group-policy B',
    '',
  ].join('\n');
  const sinv = plain(asa.buildInventory(asa.parse(shared), {}));
  const sfr = sinv.sections.find(s => s.id === 'filter-rules');
  assert.strictEqual(sfr.groups.length, 1, 'one group for one unique filter ACL');
  const sg = sfr.groups[0];
  assert.strictEqual(sg.title, 'SHARED');
  const sSummary = sg.summary.map(ct).join(' | ');
  assert.ok(sSummary.includes('policies: A, B'), sSummary);
  const sUsed = sg.sections.find(s => s.id === 'used-by').rows.map(r => `${ct(r.cells.kind)} ${ct(r.cells.name)} -> ${ct(r.cells.policy)}`).sort();
  assert.deepStrictEqual(sUsed, ['group-policy A -> A', 'group-policy B -> B', 'tunnel-group TA -> A', 'tunnel-group TB -> B']);
  assert.strictEqual(sg.sections.find(s => s.id === 'rules').ruleRows.length, 1, 'rules listed once, not per policy');

  // ---- Final-review fixes ----
  // group-lock without vpn-group-policy: inherit the locked tunnel-group's default group-policy
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
  const bob = linv.sections.find(s => s.id === 'users').rows.find(r => ct(r.cells.name) === 'bob');
  assert.strictEqual(ct(bob.cells.filter), 'ENGF', 'user inherits locked tunnel-group policy filter');
  assert.strictEqual(note(bob.cells.filter), 'from GP_ENG');
  assert.strictEqual(ct(bob.cells.split), 'Enabled (exclude)');
  const lf = linv.sections.find(s => s.id === 'findings').rows.map(r => `${ct(r.cells.subject)}|${ct(r.cells.finding)}`);
  assert.ok(!lf.some(x => /user bob\|no vpn-filter/.test(x)), 'no false "no vpn-filter" for bob');

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
  const btg = binv.sections.find(s => s.id === 'tunnel-groups').rows.map(r => ct(r.cells.name));
  assert.deepStrictEqual(btg, ['DefaultWEBVPNGroup']);
};
