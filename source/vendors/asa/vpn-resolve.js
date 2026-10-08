// ============================================================
// ASA remote-access VPN (AnyConnect) inventory
// ============================================================
// buildVpnInventory(config) -> Inventory | null. See shared/registry.js for
// the vendor-neutral Inventory shape ui.js renders.
//
// Inheritance (ASA): user -> group-policy -> DfltGrpPolicy. A value of
// `undefined` on an object means "unset, keep looking"; an explicit `none`
// is a real value that stops the search.

const VPN_DFLT = 'DfltGrpPolicy';
const VPN_ROW_ID_BASE = 100000;

// show run omits the `type` line for the built-in default groups, so a
// type-less DefaultRAGroup / DefaultWEBVPNGroup is still a remote-access group.
function vpnIsRemoteAccess(tg) {
  return tg.type === 'remote-access' || tg.type === 'ipsec-ra' ||
    (tg.type === null && /^Default(RA|WEBVPN)Group$/.test(tg.name));
}

function vpnCell(text, tone, note) {
  const c = { text };
  if (tone) c.tone = tone;
  if (note) c.note = note;
  return c;
}

function vpnChain(config, ownerKind, owner) {
  const chain = [];
  let gpName = null;
  if (ownerKind === 'user') {
    chain.push({ source: 'user', label: owner.name, obj: owner });
    // No explicit vpn-group-policy: the user lands in its group-lock'ed
    // tunnel-group and inherits that group's default group-policy.
    const locked = owner.groupLock && config.tunnelGroups[owner.groupLock];
    gpName = owner.vpnGroupPolicy || (locked && locked.defaultGroupPolicy) || null;
  } else if (ownerKind === 'tunnel-group') {
    gpName = owner.defaultGroupPolicy || null;
  } else {
    chain.push({ source: 'group-policy', label: owner.name, obj: owner });
  }
  if (ownerKind !== 'group-policy' && gpName && config.groupPolicies[gpName]) {
    chain.push({ source: 'group-policy', label: gpName, obj: config.groupPolicies[gpName] });
  }
  const dflt = config.groupPolicies[VPN_DFLT];
  if (dflt && !chain.some(l => l.obj === dflt)) {
    chain.push({ source: 'DfltGrpPolicy', label: VPN_DFLT, obj: dflt });
  }
  return chain;
}

function vpnEffective(chain, getter) {
  for (const link of chain) {
    const v = getter(link.obj);
    if (v !== undefined) return { value: v, source: link.source, label: link.label };
  }
  return { value: undefined, source: 'default', label: null };
}

// Where did an effective value come from, relative to the row that shows it?
function vpnNote(eff, ownKind) {
  if (eff.source === 'default') return 'default';
  if (eff.source === ownKind) return undefined;
  if (eff.source === 'DfltGrpPolicy') return 'inherited: DfltGrpPolicy';
  return 'from ' + eff.label;
}

function vpnAclNetworks(config, name) {
  if (config.standardAcls[name]) {
    return config.standardAcls[name].map(e => ({ action: e.action, resolved: resolveEndpoint(config, e.src) }));
  }
  if (config.acls[name]) { // extended ACL used as a split-tunnel list: show destinations
    return config.acls[name].filter(e => !e.remark).map(e => ({ action: e.action, resolved: resolveEndpoint(config, e.dst) }));
  }
  return null;
}

function vpnFilterInfo(config, chain) {
  const f = vpnEffective(chain, o => o.vpnFilter);
  if (f.value === undefined || f.value.mode === 'none') {
    return { aclName: null, source: f.source, label: f.label, explicitNone: f.value !== undefined, entries: null };
  }
  const acl = config.acls[f.value.acl];
  return {
    aclName: f.value.acl, source: f.source, label: f.label, explicitNone: false,
    missing: !acl, entries: acl ? acl.filter(e => !e.remark) : [],
  };
}

// Split tunneling: tunnelall = Disabled; tunnelspecified/excludespecified =
// Enabled (include/exclude). Unset everywhere = DfltGrpPolicy default tunnelall.
function vpnSplitState(config, chain) {
  const pol = vpnEffective(chain, o => o.splitPolicy);
  const policy = pol.value || 'tunnelall';
  const enabled = policy === 'tunnelspecified' || policy === 'excludespecified';
  const mode = policy === 'tunnelspecified' ? 'include' : policy === 'excludespecified' ? 'exclude' : 'off';
  const acl = vpnEffective(chain, o => o.splitAcl);
  const out = {
    policy, enabled, mode,
    text: enabled ? `Enabled (${mode})` : 'Disabled', // display text; `label` stays the provenance name used by vpnNote()
    source: pol.value ? pol.source : 'default', label: pol.label,
    aclName: acl.value && acl.value.acl ? acl.value.acl : null,
    networks: [], problem: null,
  };
  if (enabled) {
    if (!acl.value || acl.value.mode === 'none') {
      out.problem = 'no split-tunnel-network-list is configured';
    } else {
      const nets = vpnAclNetworks(config, acl.value.acl);
      if (!nets) out.problem = `split-tunnel ACL ${acl.value.acl} is not defined`;
      else if (!nets.length) out.problem = `split-tunnel ACL ${acl.value.acl} is empty`;
      else out.networks = nets;
    }
  }
  return out;
}

function vpnPools(ownerKind, owner, chain) {
  if (ownerKind === 'user' && owner.framedIp) {
    return { names: [], single: owner.framedIp.ip, source: 'user', label: owner.name };
  }
  const eff = vpnEffective(chain, o => o.addressPools);
  if (eff.value !== undefined && eff.value.length) {
    return { names: eff.value, single: null, source: eff.source, label: eff.label };
  }
  if (ownerKind === 'tunnel-group' && owner.addressPools.length) {
    return { names: owner.addressPools, single: null, source: 'tunnel-group', label: owner.name };
  }
  return { names: [], single: null, source: 'default', label: null };
}

function vpnIdentityInfo(config, kind, owner) {
  const chain = vpnChain(config, kind, owner);
  const poolSel = vpnPools(kind, owner, chain);
  const pools = poolSel.names.map(n => ({ name: n, pool: config.pools[n] || null }));
  const poolTotal = pools.reduce((s, p) => s + (p.pool ? p.pool.count : 0), 0) + (poolSel.single ? 1 : 0);
  return {
    kind, name: owner.name, owner, chain,
    filter: vpnFilterInfo(config, chain),
    split: vpnSplitState(config, chain),
    poolSel, pools, poolTotal,
    protocols: vpnEffective(chain, o => o.tunnelProtocols),
    logins: vpnEffective(chain, o => o.simultaneousLogins),
    dns: vpnEffective(chain, o => o.dnsServers),
  };
}

function vpnPoolsText(info) {
  if (info.poolSel.single) return `${info.poolSel.single} (framed)`;
  if (!info.pools.length) return info.kind === 'user' ? '— (per tunnel-group at login)' : '—';
  return info.pools.map(p => p.pool
    ? `${p.name} (${p.pool.start}–${p.pool.end}, ${p.pool.count})`
    : `${p.name} (not defined)`).join(', ');
}

function vpnFilterText(info) {
  if (info.filter.aclName) return info.filter.aclName;
  return info.filter.explicitNone ? 'none (explicit)' : 'none';
}

function vpnJoin(eff) {
  if (eff.value === undefined) return '—';
  return Array.isArray(eff.value) ? (eff.value.join(', ') || 'none') : String(eff.value);
}

// Cells shared by tunnel-group / group-policy / user rows
function vpnCommonCells(info) {
  const k = info.kind;
  return {
    pools: vpnCell(vpnPoolsText(info), null, vpnNote(info.poolSel, k)),
    filter: vpnCell(vpnFilterText(info), info.filter.aclName ? null : 'warn', vpnNote(info.filter, k)),
    split: vpnCell(info.split.text, info.split.problem ? 'warn' : null, vpnNote(info.split, k)),
  };
}

function vpnCommonDetail(info) {
  const k = info.kind;
  return [
    ['Address pool(s)', vpnCell(vpnPoolsText(info), null, vpnNote(info.poolSel, k))],
    ['VPN filter', vpnCell(vpnFilterText(info), info.filter.aclName ? null : 'warn', vpnNote(info.filter, k))],
    ['Split tunneling', vpnCell(info.split.text + (info.split.aclName ? `, list ${info.split.aclName}` : ''), info.split.problem ? 'warn' : null, vpnNote(info.split, k))],
    ['Tunnel protocols', vpnCell(vpnJoin(info.protocols), null, vpnNote(info.protocols, k))],
    ['Simultaneous logins', vpnCell(vpnJoin(info.logins), null, vpnNote(info.logins, k))],
    ['DNS servers', vpnCell(vpnJoin(info.dns), null, vpnNote(info.dns, k))],
  ];
}

function vpnDetailBlocks(info, extraPairs) {
  const blocks = [{ kind: 'kv', title: 'Effective attributes', pairs: extraPairs.concat(vpnCommonDetail(info)) }];
  if (info.split.networks.length) {
    blocks.push({
      kind: 'networks',
      title: `Split-tunnel networks (${info.split.aclName}, ${info.split.mode === 'include' ? 'tunneled' : 'excluded from tunnel'})`,
      entries: info.split.networks,
    });
  }
  if (info.owner.rawAttrs && info.owner.rawAttrs.length) {
    blocks.push({ kind: 'list', title: 'Unmodelled attributes', items: info.owner.rawAttrs });
  }
  return blocks;
}

function vpnTunnelGroupRow(info) {
  const tg = info.owner;
  const gpName = tg.defaultGroupPolicy || VPN_DFLT;
  return {
    cells: Object.assign({
      name: tg.name,
      alias: [].concat(tg.aliases, tg.urls).join(', ') || '—',
      groupPolicy: gpName,
      auth: tg.authServerGroup || '—',
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [
      ['Group-policy', gpName],
      ['Group aliases', tg.aliases.join(', ') || '—'],
      ['Group URLs', tg.urls.join(', ') || '—'],
      ['Authentication server group', tg.authServerGroup || '—'],
    ]),
  };
}

function vpnGroupPolicyRow(info) {
  const gp = info.owner;
  return {
    cells: Object.assign({
      name: gp.name,
      protocols: vpnCell(vpnJoin(info.protocols), null, vpnNote(info.protocols, 'group-policy')),
      logins: vpnCell(vpnJoin(info.logins), null, vpnNote(info.logins, 'group-policy')),
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [['Type', gp.kind || '—']]),
  };
}

function vpnUserRow(info) {
  const u = info.owner;
  return {
    cells: Object.assign({
      name: u.name,
      groupPolicy: u.vpnGroupPolicy || '—',
      groupLock: u.groupLock || '—',
    }, vpnCommonCells(info)),
    detail: vpnDetailBlocks(info, [
      ['vpn-group-policy', u.vpnGroupPolicy || '—'],
      ['group-lock', u.groupLock || '—'],
      ['vpn-framed-ip-address', u.framedIp ? `${u.framedIp.ip}${u.framedIp.mask ? ' ' + u.framedIp.mask : ''}` : '—'],
    ]),
  };
}

function vpnFindings(config, tgInfos, userInfos) {
  const out = [];
  const add = (level, subject, finding) => out.push({
    cells: { level: vpnCell(level, level === 'warn' ? 'warn' : 'dim'), subject, finding },
  });
  const g = config.vpnGlobal;
  add('info', 'Global', g.permitVpn
    ? `sysopt connection permit-vpn${g.permitVpnExplicit ? '' : ' (ASA default)'}: decrypted VPN traffic bypasses interface ACLs; only each identity's vpn-filter restricts it.`
    : 'sysopt connection permit-vpn is disabled: VPN traffic is also checked against interface ACLs.');
  add('info', 'Global', 'Attributes supplied by RADIUS/LDAP (pools, filters, group-policy) are not visible in the config and are not reflected here.');
  for (const info of tgInfos.concat(userInfos)) {
    const subj = `${info.kind} ${info.name}`;
    const o = info.owner;
    if (info.kind === 'tunnel-group' && o.defaultGroupPolicy && !config.groupPolicies[o.defaultGroupPolicy]) {
      add('warn', subj, `default-group-policy ${o.defaultGroupPolicy} is not defined`);
    }
    if (info.kind === 'user' && o.vpnGroupPolicy && !config.groupPolicies[o.vpnGroupPolicy]) {
      add('warn', subj, `vpn-group-policy ${o.vpnGroupPolicy} is not defined`);
    }
    if (!info.filter.aclName) {
      add('warn', subj, `no vpn-filter (${info.filter.explicitNone ? 'explicit "none"' : 'unset'}): authenticated users are not restricted by an ACL`);
    } else if (info.filter.missing) {
      add('warn', subj, `vpn-filter ACL ${info.filter.aclName} is not defined`);
    } else if (!info.filter.entries.length) {
      add('warn', subj, `vpn-filter ACL ${info.filter.aclName} has no entries`);
    }
    for (const p of info.pools) if (!p.pool) add('warn', subj, `address pool ${p.name} is not defined`);
    if (info.kind === 'tunnel-group' && !info.pools.length && !info.poolSel.single) {
      add('info', subj, 'no local address pool resolved (DHCP/AAA-assigned pools are not visible in the config)');
    }
    if (info.split.problem) add('warn', subj, `split tunneling enabled but ${info.split.problem}`);
  }
  return out;
}

// One scored rule row per distinct (vpn-filter ACL, ACE), with the identities
// that use it. Direction is 'internal' (client -> internal, symmetric blend).
function vpnFilterRuleRows(config, infos) {
  const usedBy = new Map(); // aclName -> ["tunnel-group ENG", ...]
  for (const info of infos) {
    if (!info.filter.aclName) continue;
    if (!usedBy.has(info.filter.aclName)) usedBy.set(info.filter.aclName, []);
    usedBy.get(info.filter.aclName).push(`${info.kind} ${info.name}`);
  }
  const rows = [];
  let id = VPN_ROW_ID_BASE;
  for (const [aclName, users] of usedBy) {
    const acl = config.acls[aclName];
    if (!acl) continue;
    let seq = 0;
    for (const entry of acl) {
      if (entry.remark) continue;
      seq += 1;
      const scored = scoreEntry(config, entry, 'internal');
      if (!scored.srcResolved) { // scoreEntry's deny shortcut omits these
        scored.srcResolved = resolveEndpoint(config, entry.src);
        scored.dstResolved = resolveEndpoint(config, entry.dst);
        scored.services = resolveRuleServices(config, entry);
      }
      rows.push({
        id: id++, type: 'rule', aclName, ruleNumber: seq, entry, scored,
        interface: 'vpn-filter', direction: 'vpn-filter', implicit: false,
        inactive: !!entry.inactive, usedBy: users,
      });
    }
  }
  return rows;
}

function buildVpnInventory(config, options) {
  const tgs = Object.keys(config.tunnelGroups).map(k => config.tunnelGroups[k]).filter(vpnIsRemoteAccess);
  if (!tgs.length && !Object.keys(config.pools).length) return null;

  const userList = Object.keys(config.users).map(k => config.users[k])
    .filter(u => u.vpnGroupPolicy || u.vpnFilter || u.groupLock || u.framedIp);

  const gpNames = new Set();
  for (const tg of tgs) if (tg.defaultGroupPolicy && config.groupPolicies[tg.defaultGroupPolicy]) gpNames.add(tg.defaultGroupPolicy);
  for (const u of userList) if (u.vpnGroupPolicy && config.groupPolicies[u.vpnGroupPolicy]) gpNames.add(u.vpnGroupPolicy);
  if (config.groupPolicies[VPN_DFLT]) gpNames.add(VPN_DFLT);

  const tgInfos = tgs.map(tg => vpnIdentityInfo(config, 'tunnel-group', tg));
  const gpInfos = Object.keys(config.groupPolicies).filter(n => gpNames.has(n))
    .sort((a, b) => (a === VPN_DFLT ? -1 : b === VPN_DFLT ? 1 : 0))
    .map(n => vpnIdentityInfo(config, 'group-policy', config.groupPolicies[n]));
  const userInfos = userList.map(u => vpnIdentityInfo(config, 'user', u));
  const all = tgInfos.concat(gpInfos, userInfos);

  const sections = [];
  if (tgInfos.length) sections.push({
    id: 'tunnel-groups', heading: 'Tunnel-groups',
    columns: [
      { key: 'name', label: 'Tunnel-group' }, { key: 'alias', label: 'Alias / URL' },
      { key: 'pools', label: 'Address pool(s)' }, { key: 'groupPolicy', label: 'Group-policy' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
      { key: 'auth', label: 'Auth server' },
    ],
    rows: tgInfos.map(vpnTunnelGroupRow),
  });
  if (gpInfos.length) sections.push({
    id: 'group-policies', heading: 'Group-policies',
    columns: [
      { key: 'name', label: 'Group-policy' }, { key: 'pools', label: 'Address pool(s)' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
      { key: 'protocols', label: 'Tunnel protocols' }, { key: 'logins', label: 'Simult. logins' },
    ],
    rows: gpInfos.map(vpnGroupPolicyRow),
  });
  if (userInfos.length) sections.push({
    id: 'users', heading: 'User overrides',
    columns: [
      { key: 'name', label: 'User' }, { key: 'groupPolicy', label: 'Group-policy' },
      { key: 'groupLock', label: 'Group-lock' }, { key: 'pools', label: 'Address' },
      { key: 'filter', label: 'VPN filter' }, { key: 'split', label: 'Split tunneling' },
    ],
    rows: userInfos.map(vpnUserRow),
  });

  const poolNames = Object.keys(config.pools);
  if (poolNames.length) sections.push({
    id: 'pools', heading: 'Address pools',
    columns: [
      { key: 'name', label: 'Pool' }, { key: 'range', label: 'Range' }, { key: 'mask', label: 'Mask' },
      { key: 'count', label: 'Addresses' }, { key: 'usedBy', label: 'Used by' },
    ],
    rows: poolNames.map(n => {
      const p = config.pools[n];
      const users = all.filter(i => i.poolSel.names.includes(n)).map(i => `${i.kind} ${i.name}`);
      return { cells: { name: n, range: `${p.start}–${p.end}`, mask: p.mask || '—', count: String(p.count), usedBy: users.join(', ') || '—' } };
    }),
  });

  const filterRows = vpnFilterRuleRows(config, all);
  if (filterRows.length) sections.push({ id: 'filter-rules', heading: 'VPN filter rules', ruleRows: filterRows });

  sections.push({
    id: 'findings', heading: 'Findings',
    columns: [{ key: 'level', label: 'Level' }, { key: 'subject', label: 'Subject' }, { key: 'finding', label: 'Finding' }],
    rows: vpnFindings(config, tgInfos, userInfos),
  });

  return { title: 'Remote-access VPN', sections };
}
