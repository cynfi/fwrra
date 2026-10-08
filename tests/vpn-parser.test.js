const assert = require('assert');
const { loadVendor, fixture, plain } = require('./helpers');

module.exports = async () => {
  const asa = loadVendor('fwrra-asa.html', 'asa');
  const c = plain(asa.parse(fixture('asa-vpn.cfg')));

  // pools
  assert.deepStrictEqual(c.pools.ENG_POOL,
    { name: 'ENG_POOL', start: '10.9.0.10', end: '10.9.0.59', mask: '255.255.255.0', count: 50 });
  assert.strictEqual(c.pools.CONTRACTOR_POOL.count, 20);

  // group-policies
  const eng = c.groupPolicies.ENG_GP;
  assert.deepStrictEqual(eng.vpnFilter, { mode: 'value', acl: 'ENG_FILTER' });
  assert.strictEqual(eng.splitPolicy, 'tunnelspecified');
  assert.deepStrictEqual(eng.splitAcl, { mode: 'value', acl: 'ENG_SPLIT' });
  assert.deepStrictEqual(eng.addressPools, ['ENG_POOL']);
  assert.deepStrictEqual(eng.tunnelProtocols, ['ssl-client', 'ikev2']);
  assert.deepStrictEqual(eng.dnsServers, ['10.0.0.53']);
  assert.strictEqual(eng.simultaneousLogins, 2);
  assert.deepStrictEqual(eng.rawAttrs, [], 'nested webvpn block must be skipped, not raw');
  assert.deepStrictEqual(c.groupPolicies.OPEN_GP.vpnFilter, { mode: 'none' });
  assert.strictEqual(c.groupPolicies.INHERIT_GP.vpnFilter, undefined);
  assert.strictEqual(c.groupPolicies.DfltGrpPolicy.splitPolicy, 'tunnelall');

  // tunnel-groups
  const t = c.tunnelGroups.ENG;
  assert.strictEqual(t.type, 'remote-access');
  assert.deepStrictEqual(t.addressPools, ['ENG_POOL']);
  assert.strictEqual(t.defaultGroupPolicy, 'ENG_GP');
  assert.strictEqual(t.authServerGroup, 'RADIUS1');
  assert.deepStrictEqual(t.aliases, ['Engineering']);
  assert.strictEqual(c.tunnelGroups['198.51.100.7'].type, 'ipsec-l2l');

  // users (password never stored)
  assert.strictEqual(c.users.alice.vpnGroupPolicy, 'CONTR_GP');
  assert.deepStrictEqual(c.users.alice.vpnFilter, { mode: 'value', acl: 'ENG_FILTER' });
  assert.strictEqual(c.users.alice.groupLock, 'ENG');
  assert.deepStrictEqual(c.users.alice.framedIp, { ip: '10.9.0.99', mask: '255.255.255.0' });
  assert.ok(!JSON.stringify(c).includes('xxxx'), 'password must not be stored');

  // standard ACLs kept separate from extended ACLs (main rule table unaffected)
  assert.deepStrictEqual(c.standardAcls.ENG_SPLIT, [{
    action: 'permit',
    src: { kind: 'subnet', address: '10.0.0.0', mask: '255.255.255.0' },
    raw: 'access-list ENG_SPLIT standard permit 10.0.0.0 255.255.255.0',
  }]);
  assert.strictEqual(c.acls.ENG_SPLIT, undefined);
  assert.strictEqual(c.acls.ENG_FILTER.length, 2);
  assert.strictEqual(c.accessGroups.length, 1);

  // globals
  assert.deepStrictEqual(c.vpnGlobal, {
    permitVpn: true, permitVpnExplicit: true,
    webvpnEnabledOn: ['outside'], anyconnectEnabled: true, tunnelGroupList: true,
  });

  // Review focus: CRLF line endings parse identically
  const crlf = plain(asa.parse(fixture('asa-vpn.cfg').replace(/\n/g, '\r\n')));
  assert.deepStrictEqual(crlf.pools, c.pools);
  assert.deepStrictEqual(crlf.groupPolicies, c.groupPolicies);
  assert.deepStrictEqual(crlf.tunnelGroups, c.tunnelGroups);

  // Review focus: inverted pool range clamps to 0, never negative
  const inv = plain(asa.parse('ip local pool BAD 10.1.1.50-10.1.1.10 mask 255.255.255.0\n'));
  assert.strictEqual(inv.pools.BAD.count, 0);

  // Explicit "no sysopt connection permit-vpn"
  const no = plain(asa.parse('no sysopt connection permit-vpn\n'));
  assert.strictEqual(no.vpnGlobal.permitVpn, false);
  assert.strictEqual(no.vpnGlobal.permitVpnExplicit, true);

  // No VPN content at all -> empty collections, defaults
  const empty = plain(asa.parse('interface Gi0/0\n nameif outside\n security-level 0\n'));
  assert.deepStrictEqual(empty.pools, {});
  assert.strictEqual(empty.vpnGlobal.permitVpn, true);
  assert.strictEqual(empty.vpnGlobal.permitVpnExplicit, false);
};
