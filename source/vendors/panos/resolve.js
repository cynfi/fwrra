// ============================================================
// PAN-OS Resolver: parsed config -> fully-resolved, scored rules
// ============================================================
// Translates Palo Alto's security rulebase into the shared endpoint/service
// vocabulary and scores it with the vendor-neutral engine, emitting the same
// row/scored contract as ASA/FortiOS.
//
// PAN-OS specifics handled here:
//  - Default-deny interzone / allow intrazone: no implicit-permit synthesis;
//    only explicit security rules are scored.
//  - Zone trust for default ordering: the zone whose interface egresses a
//    default route is the internet edge (trust 0); otherwise a zone-name
//    heuristic (untrust/outside->0, dmz->50, trust/inside->100).
//  - App-ID: a rule may allow `application ssh` with `service application-
//    default`, so the effective ports come from the App-ID -> port map below.
//    This keeps the buyback/policy matching keyed on {protocol, port} exactly
//    like the other vendors.
//  - `disabled yes` is the inactive marker.

// Common App-ID -> {protocol, port} combos (security-relevant subset). Used when
// a rule's service is `application-default` (or empty) so App-ID rules score,
// buy back, and match policy on their real ports.
const PANOS_APPID_PORTS = {
  ssh: [['tcp', '22']], telnet: [['tcp', '23']], 'ms-rdp': [['tcp', '3389']], rdp: [['tcp', '3389']],
  'ms-ds-smb': [['tcp', '445']], 'ms-ds-smbv3': [['tcp', '445']], smb: [['tcp', '445']],
  ftp: [['tcp', '21']], tftp: [['udp', '69']], 'ms-sql-db': [['tcp', '1433']], mssql: [['tcp', '1433']],
  mysql: [['tcp', '3306']], postgres: [['tcp', '5432']], redis: [['tcp', '6379']], mongodb: [['tcp', '27017']],
  'web-browsing': [['tcp', '80']], ssl: [['tcp', '443']], dns: [['udp', '53'], ['tcp', '53']],
  ping: [['icmp', null]], snmp: [['udp', '161']], vnc: [['tcp', '5900']], ldap: [['tcp', '389']],
  smtp: [['tcp', '25']], 'ms-rpc': [['tcp', '135']], 'netbios-ss': [['tcp', '139']], rexec: [['tcp', '512']],
};

// ---- endpoint resolution ----

function panResolveAddress(config, name, seen) {
  seen = seen || new Set();
  if (name === 'any') return { kind: 'any' };
  if (seen.has(name)) return { kind: 'literal', address: name, cyclic: true, name };
  seen.add(name);

  const a = config.addresses[name];
  if (a) {
    if (a.kind === 'host') return { kind: 'host', address: a.address, name };
    if (a.kind === 'subnet') return { kind: 'subnet', address: a.address, prefixLen: a.prefixLen, name };
    if (a.kind === 'range') return { kind: 'range', start: a.start, end: a.end, name };
    if (a.kind === 'fqdn') return { kind: 'fqdn', address: a.address, name };
  }
  const g = config.addressGroups[name];
  if (g) {
    if (g.dynamic) return { kind: 'literal', address: 'dynamic-group', name };
    return { kind: 'group', name, members: g.members.map(m => panResolveAddress(config, m, seen)) };
  }
  // inline CIDR / host literal
  if (/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(name)) {
    const [addr, pfx] = name.split('/');
    if (pfx == null || pfx === '32') return { kind: 'host', address: addr, name };
    return { kind: 'subnet', address: addr, prefixLen: parseInt(pfx, 10), name };
  }
  return { kind: 'literal', address: name, unresolved: true, name };
}

function panResolveEndpointList(config, names) {
  if (!names || names.length === 0) return { kind: 'any' };
  if (names.includes('any')) return { kind: 'any' };
  if (names.length === 1) return panResolveAddress(config, names[0]);
  return { kind: 'group', name: null, members: names.map(n => panResolveAddress(config, n)) };
}

// ---- service resolution ----

function panAppServiceCombos(config, apps) {
  if (!apps || !apps.length || apps.includes('any')) {
    return [{ protocol: 'tcp', destPort: null }, { protocol: 'udp', destPort: null }];
  }
  let out = [];
  for (const a of apps) {
    const m = PANOS_APPID_PORTS[(a || '').toLowerCase()];
    if (m) out = out.concat(m.map(([p, port]) => ({ protocol: p, destPort: port })));
    else out.push({ protocol: 'tcp', destPort: a }); // unknown App-ID -> unlisted specific service
  }
  return out;
}

function panResolveServiceName(config, name, seen) {
  seen = seen || new Set();
  if (seen.has(name)) return [];
  seen.add(name);
  const low = (name || '').toLowerCase();
  if (low === 'service-http') return [{ protocol: 'tcp', destPort: '80' }];
  if (low === 'service-https') return [{ protocol: 'tcp', destPort: '443' }];
  if (config.services[name]) return config.services[name].combos.slice();
  if (config.serviceGroups[name]) {
    let out = [];
    for (const m of config.serviceGroups[name].members) out = out.concat(panResolveServiceName(config, m, seen));
    return out;
  }
  return [{ protocol: 'tcp', destPort: name }]; // unknown named service -> unlisted specific
}

function panResolveServices(config, rule) {
  const svcList = (rule.service && rule.service.length) ? rule.service : ['application-default'];
  if (svcList.includes('any')) return [{ protocol: 'tcp', destPort: null }, { protocol: 'udp', destPort: null }];
  let combos = [];
  let appDefault = false;
  for (const s of svcList) {
    if (s === 'application-default') { appDefault = true; continue; }
    combos = combos.concat(panResolveServiceName(config, s));
  }
  if (appDefault || combos.length === 0) combos = combos.concat(panAppServiceCombos(config, rule.application));
  if (!combos.length) combos = [{ protocol: 'tcp', destPort: null }];
  return combos;
}

function panServiceRiskForCombo(combo) {
  if (combo.isRange && combo.destPort != null && combo.destPortEnd != null) {
    const lo = parseInt(combo.destPort, 10), hi = parseInt(combo.destPortEnd, 10);
    let worst = null;
    for (const key of Object.keys(SERVICE_RISK_TABLE)) {
      const slash = key.indexOf('/');
      const proto = key.slice(0, slash);
      const port = parseInt(key.slice(slash + 1), 10);
      if (proto === combo.protocol && port >= lo && port <= hi) {
        const e = SERVICE_RISK_TABLE[key];
        if (!worst || e.score > worst.score) worst = e;
      }
    }
    if (worst) return worst;
    return { score: DEFAULT_SERVICE_RISK, name: `${combo.protocol}/${lo}-${hi}`, note: 'Port range, no flagged port inside' };
  }
  return lookupServiceRisk(combo.protocol, combo.destPort);
}

function panWorstService(combos) {
  let worst = { score: 0, name: 'n/a', note: '' };
  for (const c of combos) {
    const r = panServiceRiskForCombo(c);
    if (r.score > worst.score) worst = r;
  }
  return worst;
}

// ---- zone trust (default ordering + direction) ----

function panZoneTrust(config, zoneName) {
  if (!zoneName || zoneName === 'any') return 0; // 'any' includes the internet edge
  const z = config.zones[zoneName];
  if (z) {
    for (const intf of z.interfaces) {
      if (config.interfaces[intf] && config.interfaces[intf].isDefaultRouteEgress) return 0;
    }
  }
  if (/untrust|outside|internet|wan/i.test(zoneName)) return 0;
  if (/dmz/i.test(zoneName)) return 50;
  if (/trust|inside|lan|internal|corp/i.test(zoneName)) return 100;
  return 60;
}

function panZoneClass(config, zones) {
  if (!zones || !zones.length || zones.includes('any')) return trustClassFromLevel(0);
  let min = 100;
  for (const z of zones) min = Math.min(min, panZoneTrust(config, z));
  return trustClassFromLevel(min);
}

function panRuleSourceTrust(config, fromZones) {
  if (!fromZones || !fromZones.length) return 60;
  let min = 100;
  for (const z of fromZones) min = Math.min(min, panZoneTrust(config, z));
  return min;
}

function detectPanRole(config) {
  for (const z of Object.keys(config.zones)) {
    if (panZoneTrust(config, z) <= 15) return 'internet-facing';
  }
  for (const nm of Object.keys(config.interfaces)) {
    if (config.interfaces[nm].isDefaultRouteEgress) return 'internet-facing';
  }
  return 'internal';
}

// ---- logging ----
// PAN-OS logs per rule via log-start / log-end + a log-forwarding profile.
// log-end is the meaningful "sessions are logged" signal; start-only or none is
// flagged, with the same deny>allow severity asymmetry as the other vendors.
function panClassifyLogging(rule) {
  const isDeny = rule.action !== 'allow';
  if (rule.logEnd) {
    return { flagged: false, severity: 'none', label: 'Log at session end', detail: 'log-end enabled — sessions matching this rule are logged.' };
  }
  if (rule.logStart) {
    return { flagged: true, severity: isDeny ? 'high' : 'medium', label: 'Log at start only',
      detail: 'log-start only — session end is not logged, so most session detail is lost.' };
  }
  return { flagged: true, severity: isDeny ? 'high' : 'medium', label: 'No logging',
    detail: isDeny ? 'No logging on a deny rule — dropped traffic (recon/attack) is not recorded.' : 'No logging configured for this rule.' };
}

// ---- scoring ----

function scorePanRule(config, rule, role) {
  const logging = panClassifyLogging(rule);
  const action = rule.action === 'allow' ? 'permit' : 'deny';
  const srcClass = panZoneClass(config, rule.from);
  const dstClass = panZoneClass(config, rule.to);
  const direction = ruleDirection(srcClass, dstClass, role);
  const srcResolved = panResolveEndpointList(config, rule.source);
  const dstResolved = panResolveEndpointList(config, rule.destination);
  // negate-source/negate-destination invert the endpoint set: the rule matches
  // everything EXCEPT what's listed. Flagging the resolved node lets the shared
  // engine score the complement breadth (a geofence allow-list is near-`any`)
  // and drives the geofence buyback + "not(...)" display.
  if (rule.negateSource) srcResolved.negated = true;
  if (rule.negateDest) dstResolved.negated = true;
  const services = panResolveServices(config, rule);

  if (action !== 'permit') {
    return {
      action, score: 0, band: riskBand(0),
      exposure: { score: 0, label: 'deny', direction },
      service: { score: 0, name: 'n/a' },
      subnetPenaltyApplied: false, subnetPenalty: 0,
      services, srcResolved, dstResolved,
      srcScope: { kind: 'unknown' }, dstScope: { kind: 'unknown' },
      srcClass, dstClass, direction, logging,
    };
  }

  const srcScope = classifyEndpointScope(srcResolved);
  const dstScope = classifyEndpointScope(dstResolved);
  const isAnyPort = services.some(c => !c.destPort);
  const worst = panWorstService(services);
  const exposure = computeExposureScore(srcScope, dstScope, isAnyPort, !!worst.subnetPenaltyEligible, direction);
  const { combined, subnetPenaltyApplied, subnetPenalty } = combineRisk(
    exposure.score, worst.score, srcScope, dstScope, !!worst.subnetPenaltyEligible
  );

  return {
    action, score: combined, band: riskBand(combined),
    exposure, service: worst, subnetPenaltyApplied, subnetPenalty,
    services, srcResolved, dstResolved, srcScope, dstScope,
    srcClass, dstClass, direction, logging,
  };
}

// ---- ruleset assembly ----

function panBuildRuleset(config, options) {
  options = options || {};
  const role = options.firewallRole || detectPanRole(config);

  const scoredList = config.rules.map(rule => ({ rule, scored: scorePanRule(config, rule, role) }));

  const records = scoredList.map((e, i) => ({
    index: i,
    action: e.scored.action,
    enabled: !e.rule.disabled,
    srcintf: e.rule.from,
    dstintf: e.rule.to,
    srcResolved: e.scored.srcResolved,
    dstResolved: e.scored.dstResolved,
    services: e.scored.services,
    isAnyPort: servicesAreUnrestricted(e.scored.services),
    isAnyDest: !!(e.scored.dstResolved && e.scored.dstResolved.kind === 'any' && !e.scored.dstResolved.negated),
    isAnySource: !!(e.scored.srcResolved && e.scored.srcResolved.kind === 'any' && !e.scored.srcResolved.negated),
    srcNegated: !!(e.scored.srcResolved && e.scored.srcResolved.negated),
    dstNegated: !!(e.scored.dstResolved && e.scored.dstResolved.negated),
  }));
  scoredList.forEach((e, i) => {
    if (e.scored.action === 'permit') {
      Object.assign(e.scored, applyBuyback(e.scored, computeRuleBuyback(records[i], records)));
    }
    e.scored.policyVerdict = evaluatePolicy({
      action: e.scored.action,
      direction: e.scored.direction,
      services: e.scored.services,
      isAnyPort: records[i].isAnyPort,
    });
  });

  const rows = [];
  let ruleId = 0;
  let seq = 0;
  for (const e of scoredList) {
    const rule = e.rule;
    seq += 1;
    const fromLabel = (rule.from && rule.from.length) ? rule.from.join('/') : 'any';
    const toLabel = (rule.to && rule.to.length) ? rule.to.join('/') : 'any';
    const trust = panRuleSourceTrust(config, rule.from);
    rows.push({
      id: ruleId++,
      type: 'rule',
      aclName: rule.name || null,     // PAN security rule name is its identity
      ruleNumber: seq,                // position in the rulebase (evaluation order)
      entry: rule,
      scored: e.scored,
      interface: `${fromLabel} → ${toLabel}`,
      direction: 'rule',
      implicit: false,
      inactive: !!rule.disabled,
      defaultOrder: { level: trust, ifName: (rule.from && rule.from[0]) || '', ruleNumber: seq },
    });
  }
  return rows;
}

// ============================================================
// Vendor detection + registration
// ============================================================
function detectPanOSConfig(text) {
  let score = 0;
  // XML running-config export.
  if (/^﻿?\s*<\?xml/i.test(text) || /^﻿?\s*<config\b/i.test(text)) {
    if (/<rulebase\b[\s\S]*?<security\b/i.test(text)) score += 4;
    if (/<devices\b[\s\S]*?<vsys\b/i.test(text)) score += 2;
    if (/urldb="paloaltonetworks"/i.test(text) || /paloaltonetworks/i.test(text)) score += 2;
    if (score) return score; // an XML config is unambiguously PAN-OS here
  }
  if (/^set\s+.*\brulebase\s+security\s+rules\s/m.test(text)) score += 3;
  if (/^set\s+zone\s+\S+\s+network/m.test(text)) score += 2;
  if (/^set\s+address\s+\S+\s+ip-netmask/m.test(text)) score += 1;
  if (/^set\s+network\s+virtual-router/m.test(text)) score += 1;
  if (/^set\s+service\s+\S+\s+protocol/m.test(text)) score += 1;
  // ASA / FortiOS grammar means this isn't PAN-OS.
  if (/^\s*access-list\s+\S+\s+extended\s/m.test(text)) score = 0;
  if (/^\s*config\s+firewall\s+policy\b/m.test(text)) score = 0;
  return score;
}

registerVendor({
  id: 'panos',
  label: 'Palo Alto PAN-OS',
  detect: detectPanOSConfig,
  parse: parsePanOSConfig,
  buildRuleset: panBuildRuleset,
  detectRole: detectPanRole,
});
