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

// Compute risk for a single ACL entry
function scoreEntry(config, entry) {
  if (entry.remark) return null; // remarks aren't scored
  const logging = classifyLogging(entry);
  if (entry.action !== 'permit') {
    return {
      action: entry.action,
      score: 0,
      band: riskBand(0),
      exposure: { score: 0, label: 'deny' },
      service: { score: 0, name: 'n/a' },
      bonusApplied: false,
      services: [],
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

  const exposure = computeExposureScore(srcScope, dstScope, isAnyPort);

  // worst-case service risk across all resolved protocol/port combos
  let worstService = { score: 0, name: 'n/a', note: '' };
  for (const combo of serviceCombos) {
    const r = lookupServiceRisk(combo.protocol, combo.destPort);
    if (r.score > worstService.score) worstService = r;
  }

  const { combined, bonusApplied } = combineRisk(exposure.score, worstService.score);

  return {
    action: entry.action,
    score: combined,
    band: riskBand(combined),
    exposure,
    service: worstService,
    bonusApplied,
    services: serviceCombos,
    srcResolved,
    dstResolved,
    srcScope,
    dstScope,
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

function buildRuleset(config) {
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
      const scored = scoreEntry(config, entry);
      for (const app of applications) {
        const orderKey = interfaceOrderKey(config, app.interface);
        rows.push({
          id: ruleId++,
          type: 'rule',
          aclName,
          ruleNumber,
          entry,
          scored,
          interface: app.interface,
          direction: app.direction,
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
        bonusApplied: false,
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
        implicit: true,
        implicitNote: `No inbound ACL on '${highIf}' (level ${highLevel}) \u2014 default ASA behavior implicitly permits all traffic to '${lowIf}' (level ${lowLevel}).`,
        // Implicit rules sort after all explicit rules for their source interface, grouped by that interface's security order.
        defaultOrder: { level: highOrder.level, ifName: highOrder.name, ruleNumber: Infinity },
      });
    }
  }

  return rows;
}
