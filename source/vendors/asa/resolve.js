// ============================================================
// Resolver: turns parsed config into fully-resolved, scored rules
// ============================================================

function resolveNetworkRef(config, kind, name, seen) {
  seen = seen || new Set();
  if (seen.has(name)) return { kind: 'host', address: name, cyclic: true };
  seen.add(name);

  if (kind === 'object') {
    const obj = config.objects[name];
    if (!obj) return { kind: 'literal', address: name, unresolved: true };
    if (obj.kind === 'subnet') return { kind: 'subnet', address: obj.address, mask: obj.mask, prefixLen: maskToPrefixLen(obj.mask), name };
    if (obj.kind === 'host') return { kind: 'host', address: obj.address, name };
    if (obj.kind === 'range') return { kind: 'range', start: obj.start, end: obj.end, name };
    if (obj.kind === 'fqdn') return { kind: 'fqdn', address: obj.address, name };
    return { kind: 'literal', address: name };
  }
  if (kind === 'group') {
    const grp = config.groups[name];
    if (!grp) return { kind: 'literal', address: name, unresolved: true };
    const members = grp.members.map(mem => {
      if (mem.ref === 'object') return resolveNetworkRef(config, 'object', mem.name, seen);
      if (mem.ref === 'group') return resolveNetworkRef(config, 'group', mem.name, seen);
      if (mem.ref === 'inline') {
        if (mem.kind === 'host') return { kind: 'host', address: mem.address };
        if (mem.kind === 'subnet') return { kind: 'subnet', address: mem.address, mask: mem.mask, prefixLen: maskToPrefixLen(mem.mask) };
      }
      return { kind: 'literal', address: '?' };
    });
    return { kind: 'group', name, members };
  }
  return { kind: 'literal', address: name };
}

function resolveEndpoint(config, endpoint) {
  if (!endpoint) return { kind: 'unknown' };
  if (endpoint.kind === 'any') return { kind: 'any' };
  if (endpoint.kind === 'host') return { kind: 'host', address: endpoint.address };
  if (endpoint.kind === 'subnet') return { kind: 'subnet', address: endpoint.address, mask: endpoint.mask, prefixLen: maskToPrefixLen(endpoint.mask) };
  if (endpoint.kind === 'object') return resolveNetworkRef(config, 'object', endpoint.name);
  if (endpoint.kind === 'group') return resolveNetworkRef(config, 'group', endpoint.name);
  if (endpoint.kind === 'literal') return { kind: 'literal', address: endpoint.address };
  return { kind: 'unknown' };
}

// Resolve a service reference (object / object-group) down to a flat list of {protocol, destPort}
function resolveServiceRef(config, ref, seen) {
  seen = seen || new Set();
  if (!ref) return [];
  if (ref.ref === 'object') {
    if (seen.has('obj:' + ref.name)) return [];
    seen.add('obj:' + ref.name);
    const obj = config.objects[ref.name];
    if (!obj) return [{ protocol: 'tcp', destPort: null, unresolved: true, name: ref.name }];
    return [{ protocol: obj.protocol, destPort: obj.destPort, srcPort: obj.srcPort, name: ref.name }];
  }
  if (ref.ref === 'group') {
    if (seen.has('grp:' + ref.name)) return [];
    seen.add('grp:' + ref.name);
    const grp = config.groups[ref.name];
    if (!grp) return [{ protocol: 'tcp', destPort: null, unresolved: true, name: ref.name }];
    let results = [];
    for (const mem of grp.members) {
      if (mem.ref === 'object') results = results.concat(resolveServiceRef(config, { ref: 'object', name: mem.name }, seen));
      else if (mem.ref === 'group') results = results.concat(resolveServiceRef(config, { ref: 'group', name: mem.name }, seen));
      else if (mem.ref === 'inline') results.push({ protocol: mem.protocol, destPort: mem.destPort, srcPort: mem.srcPort });
    }
    return results;
  }
  return [];
}

// Resolve the protocol field of an ACL entry (literal / object / object-group protocol type)
function resolveProtocolRef(config, protoRef, seen) {
  seen = seen || new Set();
  if (!protoRef) return ['ip'];
  if (protoRef.ref === 'literal') return [protoRef.name];
  if (protoRef.ref === 'object') {
    const obj = config.objects[protoRef.name];
    return obj && obj.protocol ? [obj.protocol] : ['ip'];
  }
  if (protoRef.ref === 'group') {
    if (seen.has(protoRef.name)) return [];
    seen.add(protoRef.name);
    const grp = config.groups[protoRef.name];
    if (!grp) return ['ip'];
    let protos = [];
    for (const mem of grp.members) {
      if (mem.ref === 'inline') protos.push(mem.protocol);
      else if (mem.ref === 'group') protos = protos.concat(resolveProtocolRef(config, { ref: 'group', name: mem.name }, seen));
    }
    return protos.length ? protos : ['ip'];
  }
  return ['ip'];
}

// Build a flat list of {protocol, destPort} service combos for a rule, given
// the ACL entry's protocol field, srcPort/destPort (literal eq), and service ref.
function resolveRuleServices(config, entry) {
  // Case 1: destination service object/object-group specified (entry.service)
  if (entry.service) {
    const svcList = resolveServiceRef(config, entry.service);
    if (svcList.length) return svcList.map(s => ({ protocol: s.protocol || 'tcp', destPort: s.destPort }));
  }
  // Case 2: protocol field itself is object/object-group (protocol object-group, e.g. TCPUDP)
  const protocols = resolveProtocolRef(config, entry.protocol);
  const destPortSpec = entry.destPort; // {op, port} | {op:'range', start, end}
  const combos = [];
  for (const proto of protocols) {
    if (destPortSpec) {
      if (destPortSpec.op === 'eq') combos.push({ protocol: proto, destPort: destPortSpec.port });
      else if (destPortSpec.op === 'range') combos.push({ protocol: proto, destPort: destPortSpec.start, destPortEnd: destPortSpec.end, isRange: true });
      else combos.push({ protocol: proto, destPort: null });
    } else {
      combos.push({ protocol: proto, destPort: null });
    }
  }
  return combos.length ? combos : [{ protocol: 'ip', destPort: null }];
}

function scopeContainsMultipleHosts(resolvedEndpoint) {
  if (resolvedEndpoint.kind !== 'group') return false;
  return resolvedEndpoint.members.length > 1;
}

// Auto-detect firewall role: internet-facing if any interface's security-level
// classifies as the internet edge (e.g. an outside interface at level 0);
// otherwise internal segmentation.
function detectASARole(config) {
  for (const name of Object.keys(config.interfaces)) {
    if (trustClassFromLevel(config.interfaces[name].securityLevel) === 'internet') return 'internet-facing';
  }
  return 'internal';
}

// Direction of an ACE from the interface/direction it is applied on. ASA ACLs
// are bound to an interface + direction rather than a src/dst zone pair, so the
// applied interface *is* the source zone for an inbound ACL and the destination
// zone for an outbound one. This mirrors the ASA higher->lower mental model:
// an inbound ACL on the inside (high-trust) interface is egress-to-internet; an
// inbound ACL on the outside (internet) interface is ingress.
function asaDirection(config, ifName, aclDir, role) {
  if (role === 'internal') return 'internal';
  const cls = trustClassFromLevel(config.interfaces[ifName] ? config.interfaces[ifName].securityLevel : null);
  if (aclDir === 'in') { // applied interface is the source zone
    if (cls === 'internet') return 'ingress';
    if (cls === 'internal') return 'egress';
    return 'internal';
  }
  // 'out': applied interface is the destination zone
  if (cls === 'internet') return 'egress';
  if (cls === 'internal') return 'ingress';
  return 'internal';
}

// Compute risk for a single ACL entry, given the traffic `direction`
// (ingress/egress/internal) inferred from where the ACL is applied.
function scoreEntry(config, entry, direction) {
  if (entry.remark) return null; // remarks aren't scored
  const logging = classifyLogging(entry);
  if (entry.action !== 'permit') {
    return {
      action: entry.action,
      score: 0,
      band: riskBand(0),
      exposure: { score: 0, label: 'deny', direction },
      service: { score: 0, name: 'n/a' },
      services: [],
      direction,
      logging,
    };
  }

  const srcResolved = resolveEndpoint(config, entry.src);
  const dstResolved = resolveEndpoint(config, entry.dst);
  const srcScope = classifyEndpointScope(srcResolved);
  const dstScope = classifyEndpointScope(dstResolved);

  const serviceCombos = resolveRuleServices(config, entry);
  // "any port" if any resolved combo has no destPort restriction, or protocol is bare ip/gre/esp etc with no port concept
  const isAnyPort = serviceCombos.some(c => !c.destPort);

  // worst-case service risk across all resolved protocol/port combos. Looked up
  // before exposure because exposure's subnet-penalty treatment depends on
  // this service's subnetPenaltyEligible flag.
  let worstService = { score: 0, name: 'n/a', note: '' };
  for (const combo of serviceCombos) {
    const r = lookupServiceRisk(combo.protocol, combo.destPort);
    if (r.score > worstService.score) worstService = r;
  }

  const exposure = computeExposureScore(srcScope, dstScope, isAnyPort, !!worstService.subnetPenaltyEligible, direction);
  const { combined, subnetPenaltyApplied, subnetPenalty } = combineRisk(
    exposure.score, worstService.score, srcScope, dstScope, !!worstService.subnetPenaltyEligible
  );

  return {
    action: entry.action,
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
    direction,
    logging,
  };
}

// Build the full list of rules-to-display: real ACL entries (on applied ACLs only)
// plus synthesized implicit-permit entries for unprotected higher->lower security interface pairs.
// Default-order sort key for an applied ACL's interface: most-secure interface first,
// then least-secure. Interfaces with equal security level are tie-broken by name (lowest first).
function interfaceOrderKey(config, ifName) {
  const iface = config.interfaces[ifName];
  const level = iface && iface.securityLevel !== null ? iface.securityLevel : -1;
  return { level, name: ifName };
}

// Normalized rule record for buyback matching. srcintf/dstintf are left empty
// (wildcard) because matching is already scoped to a single ACL by the caller,
// whose ACEs share one applied interface. Services are resolved for denies too,
// so the matcher can see which ports a deny ACE blocks.
function asaBuybackRecord(config, entry, index) {
  const srcResolved = resolveEndpoint(config, entry.src);
  const dstResolved = resolveEndpoint(config, entry.dst);
  const services = resolveRuleServices(config, entry);
  return {
    index,
    action: entry.action,
    enabled: !entry.inactive,
    srcintf: [],
    dstintf: [],
    srcResolved,
    dstResolved,
    services,
    isAnyPort: servicesAreUnrestricted(services),
    isAnyDest: dstResolved.kind === 'any',
  };
}

function buildRuleset(config, options) {
  options = options || {};
  const role = options.firewallRole || detectASARole(config);
  const rows = [];

  // Determine which ACLs are actually applied, and to which interface/direction
  const appliedAcls = new Set(config.accessGroups.map(ag => ag.aclName));
  const aclApplication = {}; // aclName -> [{interface, direction}]
  for (const ag of config.accessGroups) {
    if (!aclApplication[ag.aclName]) aclApplication[ag.aclName] = [];
    aclApplication[ag.aclName].push({ interface: ag.interface, direction: ag.direction });
  }

  let ruleId = 0;
  for (const aclName of Object.keys(config.acls)) {
    if (!appliedAcls.has(aclName)) continue; // exclude ACLs not bound to any interface

    const applications = aclApplication[aclName];

    // Buyback matching is scoped to this ACL (its ACEs are evaluated in order,
    // first-match, on a shared applied interface — so a deny ACE before a broad
    // permit ACE within the same ACL carves ports/geo out of it). Build records
    // over the ACL's scored ACEs and compute each permit ACE's buyback credit
    // (direction-independent), keyed by the entry object.
    const aceEntries = config.acls[aclName].filter(e => !e.remark);
    const aclRecords = aceEntries.map((e, i) => asaBuybackRecord(config, e, i));
    const creditByEntry = new Map();
    aclRecords.forEach((rec, i) => {
      if (rec.action === 'permit') creditByEntry.set(aceEntries[i], computeRuleBuyback(rec, aclRecords));
    });

    // Per-ACL sequence number, restarting at 1 for each ACL, in original config order.
    // Inactive ACEs still consume a number (matching "show access-list" / ASDM), so the
    // numbering doesn't shift depending on whether inactive rules are currently shown.
    let seq = 0;

    for (const entry of config.acls[aclName]) {
      if (entry.remark) {
        rows.push({ id: ruleId++, type: 'remark', aclName, text: entry.remark });
        continue;
      }

      seq += 1;
      const ruleNumber = seq;
      const buyback = creditByEntry.get(entry);
      // Direction (and therefore the score) can differ per application when the
      // same ACL is bound to multiple interfaces, so score inside the loop.
      for (const app of applications) {
        const orderKey = interfaceOrderKey(config, app.interface);
        const direction = asaDirection(config, app.interface, app.direction, role);
        const scored = scoreEntry(config, entry, direction);
        // Buyback credit is direction-independent; the in-context floor uses this
        // application's own exposure/score.
        if (buyback) Object.assign(scored, applyBuyback(scored, buyback));
        // Policy verdict (gate, independent of the score).
        scored.policyVerdict = evaluatePolicy({
          action: scored.action,
          direction: scored.direction,
          services: scored.services,
          isAnyPort: servicesAreUnrestricted(scored.services),
        });
        rows.push({
          id: ruleId++,
          type: 'rule',
          aclName,
          ruleNumber,
          entry,
          scored,
          interface: app.interface,
          direction: app.direction,
          // Strict: an ACL only knows the interface it is bound to. Inbound = that
          // interface is the source side; outbound = the destination side.
          fromZones: app.direction === 'in' ? [app.interface] : [],
          toZones: app.direction === 'out' ? [app.interface] : [],
          implicit: false,
          inactive: !!entry.inactive,
          defaultOrder: { level: orderKey.level, ifName: orderKey.name, ruleNumber },
        });
      }
    }
  }

  // Synthesize implicit permit any/any for unprotected higher->lower security-level pairs
  const ifNames = Object.keys(config.interfaces).filter(nm => config.interfaces[nm].securityLevel !== null);
  const protectedInbound = new Set(); // interfaces that have an inbound ACL applied
  for (const ag of config.accessGroups) {
    if (ag.direction === 'in') protectedInbound.add(ag.interface);
  }

  for (const highIf of ifNames) {
    const highLevel = config.interfaces[highIf].securityLevel;
    for (const lowIf of ifNames) {
      if (highIf === lowIf) continue;
      const lowLevel = config.interfaces[lowIf].securityLevel;
      if (highLevel <= lowLevel) continue; // only higher -> lower is implicitly permitted
      // Traffic flows from highIf (ingress on high side) to lowIf. It is blocked only if
      // highIf has an inbound ACL applied (which would replace the implicit permit with explicit rules).
      if (protectedInbound.has(highIf)) continue;
      const scored = {
        action: 'permit',
        score: 100,
        band: riskBand(100),
        exposure: { score: 100, label: 'any \u2194 any (implicit)' },
        service: { score: 0, name: 'any' },
        services: [{ protocol: 'ip', destPort: null }],
        srcResolved: { kind: 'any' },
        dstResolved: { kind: 'any' },
        srcScope: { kind: 'any' },
        dstScope: { kind: 'any' },
        logging: {
          flagged: true,
          severity: 'high',
          label: 'No logging',
          detail: 'Implicit permit \u2014 there is no ACE to attach a log directive to, so this traffic is never logged.',
        },
      };
      const highOrder = interfaceOrderKey(config, highIf);
      rows.push({
        id: ruleId++,
        type: 'rule',
        aclName: null,
        ruleNumber: null,
        entry: { action: 'permit', protocol: { ref: 'literal', name: 'ip' }, src: { kind: 'any' }, dst: { kind: 'any' } },
        scored,
        interface: `${highIf} \u2192 ${lowIf}`,
        direction: 'implicit',
        fromZones: [highIf],
        toZones: [lowIf],
        implicit: true,
        implicitNote: `No inbound ACL on '${highIf}' (level ${highLevel}) \u2014 default ASA behavior implicitly permits all traffic to '${lowIf}' (level ${lowLevel}).`,
        // Implicit rules sort after all explicit rules for their source interface, grouped by that interface's security order.
        defaultOrder: { level: highOrder.level, ifName: highOrder.name, ruleNumber: Infinity },
      });
    }
  }

  return rows;
}

// ============================================================
// ASA-specific logging classification
// ============================================================
// ASA log directive grammar: "log [level] [interval secs]" | "log disable" |
// "log default". This is ASA-specific syntax/semantics (parsed into
// entry.logSetting by parser.js); other vendors express logging differently
// and need their own classifyLogging() in their own resolve.js. The
// resulting shape — { flagged, severity, label, detail } — is the
// vendor-neutral contract ui.js expects, and SYSLOG_LEVEL_NAMES (shared/logging.js)
// supplies the universal level-name lookup.

// Classifies an ACE's logging configuration for display + flagging.
// Returns { flagged, label, detail } where `flagged` means "no effective per-hit logging".
function classifyLogging(entry) {
  const setting = entry.logSetting;
  const isDeny = entry.action === 'deny';

  if (!setting) {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'No logging',
      detail: isDeny
        ? 'No log keyword \u2014 denied traffic (possible recon/attack attempts) will not generate a per-hit syslog message.'
        : 'No log keyword \u2014 this permit generates no per-hit syslog message.',
    };
  }
  if (setting.mode === 'disabled') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'Logging disabled',
      detail: `'log disable' explicitly suppresses syslog messages for this ACE${isDeny ? ' \u2014 denied traffic will be silent' : ''}.`,
    };
  }
  if (setting.mode === 'default-behavior') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'Logging disabled',
      detail: `'log default' reverts to the ASA's built-in logging behavior for this ACE, which does not include a per-hit message${isDeny ? ' \u2014 denied traffic will be silent' : ''}.`,
    };
  }
  // mode === 'level'
  const name = SYSLOG_LEVEL_NAMES[setting.level] ?? 'Unknown';
  const isBareDefaultLog = setting.level === 6;
  return {
    flagged: false,
    severity: 'none',
    label: isBareDefaultLog ? `Default (6 \u2013 ${name})` : `${setting.level} \u2013 ${name}`,
    detail: isBareDefaultLog
      ? "Bare 'log' keyword \u2014 ASA defaults to level 6 (Informational)."
      : `Explicit log level ${setting.level} (${name}).`,
  };
}

// ============================================================
// Vendor detection + registration
// ============================================================
// Confidence score that a given config blob is Cisco ASA. Markers are ASA-
// exclusive grammar; the boot/asdm image lines are especially unambiguous.
// ui.js compares this against every other registered vendor's detect() and
// uses the highest scorer, so exact magnitude matters less than being clearly
// above every non-ASA config's score (which should be ~0 for these markers).
function detectASAConfig(text) {
  let score = 0;
  if (/^\s*access-list\s+\S+\s+(extended|remark)\s/m.test(text)) score += 3;
  if (/^\s*access-group\s+\S+\s+(in|out)\s+interface\s/m.test(text)) score += 3;
  if (/^\s*nameif\s+\S+/m.test(text)) score += 2;
  if (/^\s*security-level\s+\d+/m.test(text)) score += 2;
  if (/^\s*boot\s+system\s+disk\d+:/m.test(text)) score += 2; // ASA image boot line
  if (/^\s*asdm\s+image\s+disk\d+:/m.test(text)) score += 2;   // ASDM GUI image line
  if (/^\s*object\s+network\s+\S+/m.test(text)) score += 1;
  // FortiOS/other block grammar should never appear in an ASA config; if it
  // does, this isn't ASA.
  if (/^\s*config\s+firewall\s+policy\b/m.test(text)) score = 0;
  return score;
}

registerVendor({
  id: 'asa',
  label: 'Cisco ASA',
  detect: detectASAConfig,
  parse: parseASAConfig,
  buildRuleset: buildRuleset,
  detectRole: detectASARole,
  buildInventory: buildVpnInventory,
});
