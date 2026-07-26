// ============================================================
// FortiOS Resolver: parsed config -> fully-resolved, scored rules
// ============================================================
// Translates FortiGate's object model into the shared endpoint/service
// vocabulary and scores each policy with the vendor-neutral risk engine in
// shared/risk.js. Emits the same row/scored contract ui.js renders for ASA.
//
// Notable FortiOS-vs-ASA differences handled here:
//  - Default-deny: FortiGate drops inter-zone traffic with no matching policy,
//    so there is NO implicit-permit synthesis (unlike ASA's higher->lower
//    default-permit). Only explicit policies are scored.
//  - Every policy is inherently bound to srcintf/dstintf, so there is no
//    "unapplied ACL" concept — all policies are enforced unless disabled.
//  - `set status disable` is the inactive marker (tagged, not dropped).
//  - Trust for default ordering is derived from routing/role, not a native
//    numeric security-level (FortiGate has none): the interface that egresses
//    a default route is the internet edge (least trusted).

// ---- endpoint resolution ----

function fortiResolveAddress(config, name, seen) {
  seen = seen || new Set();
  if (name === 'all') return { kind: 'any' };
  if (name === 'none') return { kind: 'literal', address: 'none', name };
  if (seen.has(name)) return { kind: 'literal', address: name, cyclic: true, name };
  seen.add(name);

  const addr = config.addresses[name];
  if (addr) {
    switch (addr.kind) {
      case 'host': return { kind: 'host', address: addr.address, name };
      case 'subnet': return { kind: 'subnet', address: addr.address, mask: addr.mask, prefixLen: addr.prefixLen, name };
      case 'range': return { kind: 'range', start: addr.start, end: addr.end, name };
      case 'fqdn': return { kind: 'fqdn', address: addr.address, name };
      // Geography and wildcard objects don't map to a concrete CIDR. Render
      // them as labeled literals (breadth 0). In practice they appear on deny
      // rules (block-country lists), where exposure isn't scored anyway.
      case 'geo': return { kind: 'literal', address: 'geo:' + addr.country, name };
      case 'wildcard': return { kind: 'literal', address: addr.address, name };
      default: return { kind: 'literal', address: name, unresolved: true, name };
    }
  }

  const grp = config.addrgrps[name];
  if (grp) {
    return { kind: 'group', name, members: grp.members.map(m => fortiResolveAddress(config, m, seen)) };
  }

  return { kind: 'literal', address: name, unresolved: true, name };
}

// A policy's srcaddr/dstaddr is a LIST of address names. Any "all" member makes
// the whole side `any`; a single member resolves directly; multiple members are
// an inline group (intentional, curated — no indiscriminate-subnet penalty).
function fortiResolveEndpointList(config, names) {
  if (!names || names.length === 0) return { kind: 'any' }; // empty == all in FortiOS
  if (names.includes('all')) return { kind: 'any' };
  if (names.length === 1) return fortiResolveAddress(config, names[0]);
  return { kind: 'group', name: null, members: names.map(n => fortiResolveAddress(config, n)) };
}

// ---- service resolution ----

function fortiResolveServiceName(config, name, seen) {
  seen = seen || new Set();
  if (seen.has(name)) return [];
  seen.add(name);

  const upper = (name || '').toUpperCase();
  if (upper === 'ALL') return [{ protocol: 'ip', destPort: null }];
  if (upper === 'ALL_TCP') return [{ protocol: 'tcp', destPort: null }];
  if (upper === 'ALL_UDP') return [{ protocol: 'udp', destPort: null }];
  if (upper === 'ALL_ICMP' || upper === 'ALL_ICMP6') return [{ protocol: 'icmp', destPort: null }];
  if (upper === 'PING') return [{ protocol: 'icmp', destPort: null }];

  const svc = config.services[name];
  if (svc) return svc.combos.slice();

  const grp = config.serviceGroups[name];
  if (grp) {
    let out = [];
    for (const mem of grp.members) out = out.concat(fortiResolveServiceName(config, mem, seen));
    return out;
  }

  // Unknown/redacted service name — score conservatively as a single unlisted
  // service rather than assuming any-port.
  return [{ protocol: 'tcp', destPort: null, unknown: true, name }];
}

function fortiResolveServices(config, names) {
  let combos = [];
  for (const n of names) combos = combos.concat(fortiResolveServiceName(config, n));
  if (combos.length === 0) combos = [{ protocol: 'ip', destPort: null }];
  return combos;
}

// Worst-case service risk across all combos. Extends the shared per-port
// lookup with range handling: a port range scans the risk table for any
// flagged port it covers and takes the worst.
function fortiWorstService(combos) {
  let worst = { score: 0, name: 'n/a', note: '' };
  for (const c of combos) {
    const r = fortiServiceRiskForCombo(c);
    if (r.score > worst.score) worst = r;
  }
  return worst;
}

function fortiServiceRiskForCombo(combo) {
  if (combo.isRange && combo.destPort != null && combo.destPortEnd != null) {
    const lo = parseInt(combo.destPort, 10), hi = parseInt(combo.destPortEnd, 10);
    let worst = null;
    for (const key of Object.keys(SERVICE_RISK_TABLE)) {
      const slash = key.indexOf('/');
      const proto = key.slice(0, slash);
      const port = parseInt(key.slice(slash + 1), 10);
      if (proto === combo.protocol && port >= lo && port <= hi) {
        const entry = SERVICE_RISK_TABLE[key];
        if (!worst || entry.score > worst.score) worst = entry;
      }
    }
    if (worst) return worst;
    return { score: DEFAULT_SERVICE_RISK, name: `${combo.protocol}/${lo}-${hi}`, note: 'Port range, no flagged port inside' };
  }
  return lookupServiceRisk(combo.protocol, combo.destPort);
}

// ---- interface trust (for default ordering only, not the risk model) ----

// Higher = more trusted. The default-route egress interface is the internet
// edge and always least-trusted; otherwise fall back to `set role`, then to a
// neutral internal default for untagged interfaces. Zones inherit the minimum
// trust of their member interfaces.
function fortiInterfaceTrust(config, ifName, seen) {
  seen = seen || new Set();
  if (!ifName || ifName === 'any') return 0; // "any" includes the internet edge
  if (seen.has(ifName)) return 60;
  seen.add(ifName);

  const zone = config.zones[ifName];
  if (zone) {
    let min = 100;
    for (const mem of zone.members) min = Math.min(min, fortiInterfaceTrust(config, mem, seen));
    return zone.members.length ? min : 60;
  }

  const iface = config.interfaces[ifName];
  if (!iface) return 30; // referenced but undefined (e.g. redacted) — unknown
  if (iface.isDefaultRouteEgress) return 0;
  switch (iface.role) {
    case 'wan': return 0;
    case 'dmz': return 50;
    case 'lan': return 100;
    default: return 60; // untagged interface: internal-by-default, below explicit lan
  }
}

// Trust of a policy's source side = the least-trusted srcintf member (a policy
// sourced from several interfaces is as exposed as its weakest one).
function fortiPolicySourceTrust(config, srcintf) {
  if (!srcintf || srcintf.length === 0) return 60;
  let min = 100;
  for (const nm of srcintf) min = Math.min(min, fortiInterfaceTrust(config, nm));
  return min;
}

// Zone-trust class for a policy side = class of the least-trusted interface in
// the list (so a side that includes the internet edge is classed `internet`).
function fortiZoneClass(config, intfList) {
  if (!intfList || intfList.length === 0) return trustClassFromLevel(60);
  let min = 100;
  for (const nm of intfList) min = Math.min(min, fortiInterfaceTrust(config, nm));
  return trustClassFromLevel(min);
}

// Auto-detect firewall role: internet-facing if any interface is a default-route
// egress (internet edge) or explicitly role wan; otherwise internal segmentation.
function detectFortiRole(config) {
  for (const name of Object.keys(config.interfaces)) {
    const iface = config.interfaces[name];
    if (iface.isDefaultRouteEgress || iface.role === 'wan') return 'internet-facing';
  }
  return 'internal';
}

// ---- logging classification ----
// FortiOS grammar: `set logtraffic all | utm | disable` (or absent). `all`
// logs every session; `utm` logs only sessions that trip a security profile
// (most allowed traffic goes unlogged); `disable`/absent means no per-session
// logging. Same {flagged, severity, label, detail} contract as ASA, with the
// same deny>permit severity asymmetry for un-logged rules.
function fortiClassifyLogging(policy) {
  const isDeny = (policy.action !== 'accept');
  const lt = policy.logtraffic;

  if (lt === 'all') {
    return { flagged: false, severity: 'none', label: 'All sessions', detail: "'set logtraffic all' — every session matching this policy is logged." };
  }
  if (lt === 'utm') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'UTM only',
      detail: "'set logtraffic utm' — only sessions that trigger a security profile are logged; ordinary allowed traffic is not.",
    };
  }
  if (lt === 'disable') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'Logging disabled',
      detail: isDeny
        ? "'set logtraffic disable' — denied traffic (possible recon/attack) generates no log."
        : "'set logtraffic disable' — this policy generates no session log.",
    };
  }
  // absent
  return {
    flagged: true,
    severity: isDeny ? 'high' : 'medium',
    label: 'No logging',
    detail: isDeny
      ? 'No logtraffic set — denied traffic (possible recon/attack) is not logged.'
      : 'No logtraffic set — this policy has no explicit session logging.',
  };
}

// ---- scoring ----

function fortiScorePolicy(config, policy, role) {
  const logging = fortiClassifyLogging(policy);
  const action = policy.action === 'accept' ? 'permit' : 'deny';

  const srcClass = fortiZoneClass(config, policy.srcintf);
  const dstClass = fortiZoneClass(config, policy.dstintf);
  const direction = ruleDirection(srcClass, dstClass, role);

  if (action !== 'permit') {
    return {
      action,
      score: 0,
      band: riskBand(0),
      exposure: { score: 0, label: 'deny', direction },
      service: { score: 0, name: 'n/a' },
      subnetPenaltyApplied: false,
      subnetPenalty: 0,
      // Resolve the deny's services/dest even though it isn't scored — the
      // buyback matcher needs to know what ports/destinations this deny blocks.
      services: fortiResolveServices(config, policy.service),
      srcResolved: fortiResolveEndpointList(config, policy.srcaddr),
      dstResolved: fortiResolveEndpointList(config, policy.dstaddr),
      srcScope: { kind: 'unknown' },
      dstScope: { kind: 'unknown' },
      srcClass,
      dstClass,
      direction,
      logging,
    };
  }

  const srcResolved = fortiResolveEndpointList(config, policy.srcaddr);
  const dstResolved = fortiResolveEndpointList(config, policy.dstaddr);
  const srcScope = classifyEndpointScope(srcResolved);
  const dstScope = classifyEndpointScope(dstResolved);

  const serviceCombos = fortiResolveServices(config, policy.service);
  const isAnyPort = serviceCombos.some(c => !c.destPort);
  const worstService = fortiWorstService(serviceCombos);

  const exposure = computeExposureScore(srcScope, dstScope, isAnyPort, !!worstService.subnetPenaltyEligible, direction);
  const { combined, subnetPenaltyApplied, subnetPenalty } = combineRisk(
    exposure.score, worstService.score, srcScope, dstScope, !!worstService.subnetPenaltyEligible
  );

  return {
    action,
    score: combined,
    band: riskBand(combined),
    exposure,
    service: worstService,
    subnetPenaltyApplied,
    subnetPenalty,
    services: serviceCombos,
    srcResolved,
    dstResolved,
    srcScope,
    dstScope,
    srcClass,
    dstClass,
    direction,
    logging,
  };
}

// ---- ruleset assembly ----

function fortiBuildRuleset(config, options) {
  options = options || {};
  const role = options.firewallRole || detectFortiRole(config);

  // Pass 1: score every policy in evaluation order.
  const scoredList = config.policies.map(policy => ({
    policy,
    scored: fortiScorePolicy(config, policy, role),
  }));

  // Pass 2: buyback matching over the whole rulebase (needs every rule, incl.
  // denies). Build normalized records, then credit each permit for high-risk
  // ports / threat-geo destinations carved out by preceding enabled denies.
  const records = scoredList.map((e, i) => ({
    index: i,
    action: e.scored.action,
    enabled: e.policy.status !== 'disable',
    srcintf: e.policy.srcintf,
    dstintf: e.policy.dstintf,
    srcResolved: e.scored.srcResolved,
    dstResolved: e.scored.dstResolved,
    services: e.scored.services,
    // "unrestricted" = permits all TCP/UDP ports or all IP protocols (portless
    // protocols like ICMP alone do NOT count). Drives buyback port eligibility
    // and the policy any-service standards.
    isAnyPort: servicesAreUnrestricted(e.scored.services),
    isAnyDest: !!(e.scored.dstResolved && e.scored.dstResolved.kind === 'any'),
  }));
  scoredList.forEach((e, i) => {
    if (e.scored.action === 'permit') {
      Object.assign(e.scored, applyBuyback(e.scored, computeRuleBuyback(records[i], records)));
    }
    // Policy verdict (gate, independent of the score).
    e.scored.policyVerdict = evaluatePolicy({
      action: e.scored.action,
      direction: e.scored.direction,
      services: e.scored.services,
      isAnyPort: records[i].isAnyPort,
    });
  });

  // Pass 3: assemble display rows.
  const rows = [];
  let ruleId = 0;
  let seq = 0;
  for (const e of scoredList) {
    const policy = e.policy;
    seq += 1; // evaluation order (position in the policy table)
    const srcLabel = (policy.srcintf && policy.srcintf.length) ? policy.srcintf.join('/') : 'any';
    const dstLabel = (policy.dstintf && policy.dstintf.length) ? policy.dstintf.join('/') : 'any';
    const trust = fortiPolicySourceTrust(config, policy.srcintf);

    rows.push({
      id: ruleId++,
      type: 'rule',
      aclName: policy.name || null,
      ruleNumber: policy.id,        // FortiGate policy ID — the canonical reference
      entry: policy,
      scored: e.scored,
      interface: `${srcLabel} → ${dstLabel}`,
      direction: 'policy',
      implicit: false,
      inactive: policy.status === 'disable',
      // Sort most-trusted source first, then srcintf name, then evaluation order.
      defaultOrder: { level: trust, ifName: (policy.srcintf && policy.srcintf[0]) || '', ruleNumber: seq },
    });
  }

  return rows;
}

// ============================================================
// Vendor detection + registration
// ============================================================
// Confidence that a config blob is FortiOS. The `#config-version=FGT...`
// header and `config firewall policy` block are unambiguous FortiGate tells;
// ASA grammar never appears in a FortiGate backup.
function detectFortiOSConfig(text) {
  let score = 0;
  if (/^#config-version=/m.test(text)) score += 3;
  if (/^\s*config\s+firewall\s+policy\b/m.test(text)) score += 3;
  if (/^\s*config\s+system\s+interface\b/m.test(text)) score += 2;
  if (/^\s*set\s+(srcintf|dstintf)\s+/m.test(text)) score += 2;
  if (/^\s*config\s+firewall\s+(address|addrgrp|service custom)\b/m.test(text)) score += 1;
  // ASA grammar would mean this isn't FortiOS.
  if (/^\s*access-list\s+\S+\s+extended\s/m.test(text)) score = 0;
  return score;
}

registerVendor({
  id: 'fortios',
  label: 'Fortinet FortiOS',
  detect: detectFortiOSConfig,
  parse: parseFortiOSConfig,
  buildRuleset: fortiBuildRuleset,
  detectRole: detectFortiRole,
});
