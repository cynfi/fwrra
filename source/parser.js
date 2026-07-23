// ============================================================
// ASA Config Parser
// Parses: object network/service, object-group network/service/protocol,
//         access-list extended, nameif/security-level, access-group
// ============================================================

function parseASAConfig(text) {
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));

  const objects = {};       // name -> {type:'network'|'service', kind, ...}
  const groups = {};        // name -> {type:'network'|'service'|'protocol', members:[...]}
  const interfaces = {};    // nameif -> {securityLevel, physical}
  const acls = {};          // acl name -> [entries]
  const accessGroups = [];  // {aclName, direction, interface}

  let i = 0;
  const n = lines.length;

  function peekIndentedBlock(startIdx) {
    // collect subsequent lines that start with whitespace (sub-config)
    const block = [];
    let j = startIdx + 1;
    while (j < n) {
      const l = lines[j];
      if (/^\s+\S/.test(l)) {
        block.push(l.trim());
        j++;
      } else {
        break;
      }
    }
    return { block, nextIdx: j };
  }

  while (i < n) {
    const raw = lines[i];
    const line = raw.trim();

    if (!line || line.startsWith('!') || line.startsWith('#')) { i++; continue; }

    // ---- interface / nameif / security-level ----
    if (/^interface\s+/.test(line)) {
      const { block, nextIdx } = peekIndentedBlock(i);
      let nameif = null, secLevel = null, physical = line.replace(/^interface\s+/, '');
      for (const bl of block) {
        let m;
        if ((m = bl.match(/^nameif\s+(\S+)/))) nameif = m[1];
        if ((m = bl.match(/^security-level\s+(\d+)/))) secLevel = parseInt(m[1], 10);
      }
      if (nameif) {
        interfaces[nameif] = { securityLevel: secLevel !== null ? secLevel : null, physical };
      }
      i = nextIdx;
      continue;
    }

    // ---- object network / object service ----
    let m;
    if ((m = line.match(/^object\s+network\s+(\S+)/))) {
      const name = m[1];
      const { block, nextIdx } = peekIndentedBlock(i);
      const obj = { type: 'network', name, kind: null };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^host\s+(\S+)/))) { obj.kind = 'host'; obj.address = mm[1]; }
        else if ((mm = bl.match(/^subnet\s+(\S+)\s+(\S+)/))) { obj.kind = 'subnet'; obj.address = mm[1]; obj.mask = mm[2]; }
        else if ((mm = bl.match(/^range\s+(\S+)\s+(\S+)/))) { obj.kind = 'range'; obj.start = mm[1]; obj.end = mm[2]; }
        else if ((mm = bl.match(/^fqdn\s+(?:v4\s+|v6\s+)?(\S+)/))) { obj.kind = 'fqdn'; obj.address = mm[1]; }
      }
      objects[name] = obj;
      i = nextIdx;
      continue;
    }

    if ((m = line.match(/^object\s+service\s+(\S+)/))) {
      const name = m[1];
      const { block, nextIdx } = peekIndentedBlock(i);
      const obj = { type: 'service', name, protocol: null, srcPort: null, destPort: null };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^service\s+(\S+)(?:\s+source\s+eq\s+(\S+))?(?:\s+destination\s+eq\s+(\S+))?/))) {
          obj.protocol = mm[1];
          if (mm[2]) obj.srcPort = mm[2];
          if (mm[3]) obj.destPort = mm[3];
        }
      }
      objects[name] = obj;
      i = nextIdx;
      continue;
    }

    // ---- object-group network/service/protocol ----
    if ((m = line.match(/^object-group\s+network\s+(\S+)/))) {
      const name = m[1];
      const { block, nextIdx } = peekIndentedBlock(i);
      const grp = { type: 'network', name, members: [] };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^network-object\s+object\s+(\S+)/))) grp.members.push({ ref: 'object', name: mm[1] });
        else if ((mm = bl.match(/^network-object\s+host\s+(\S+)/))) grp.members.push({ ref: 'inline', kind: 'host', address: mm[1] });
        else if ((mm = bl.match(/^network-object\s+(\S+)\s+(\S+)/))) grp.members.push({ ref: 'inline', kind: 'subnet', address: mm[1], mask: mm[2] });
        else if ((mm = bl.match(/^group-object\s+(\S+)/))) grp.members.push({ ref: 'group', name: mm[1] });
      }
      groups[name] = grp;
      i = nextIdx;
      continue;
    }

    if ((m = line.match(/^object-group\s+service\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?/))) {
      const name = m[1];
      const proto = m[2] || null;
      const { block, nextIdx } = peekIndentedBlock(i);
      const grp = { type: 'service', name, protoHint: proto, members: [] };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^service-object\s+object\s+(\S+)/))) grp.members.push({ ref: 'object', name: mm[1] });
        else if ((mm = bl.match(/^service-object\s+(tcp|udp|tcp-udp)\s+(?:source\s+eq\s+(\S+)\s+)?destination\s+eq\s+(\S+)/))) {
          grp.members.push({ ref: 'inline', protocol: mm[1], srcPort: mm[2] || null, destPort: mm[3] });
        }
        else if ((mm = bl.match(/^service-object\s+(tcp|udp|tcp-udp)\s+eq\s+(\S+)/))) {
          grp.members.push({ ref: 'inline', protocol: mm[1], srcPort: null, destPort: mm[2] });
        }
        else if ((mm = bl.match(/^service-object\s+(\S+)$/))) {
          grp.members.push({ ref: 'inline', protocol: mm[1], srcPort: null, destPort: null });
        }
        else if ((mm = bl.match(/^port-object\s+eq\s+(\S+)/))) {
          grp.members.push({ ref: 'inline', protocol: proto || 'tcp', srcPort: null, destPort: mm[1] });
        }
        else if ((mm = bl.match(/^group-object\s+(\S+)/))) grp.members.push({ ref: 'group', name: mm[1] });
      }
      groups[name] = grp;
      i = nextIdx;
      continue;
    }

    if ((m = line.match(/^object-group\s+protocol\s+(\S+)/))) {
      const name = m[1];
      const { block, nextIdx } = peekIndentedBlock(i);
      const grp = { type: 'protocol', name, members: [] };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^protocol-object\s+(\S+)/))) grp.members.push({ ref: 'inline', protocol: mm[1] });
        else if ((mm = bl.match(/^group-object\s+(\S+)/))) grp.members.push({ ref: 'group', name: mm[1] });
      }
      groups[name] = grp;
      i = nextIdx;
      continue;
    }

    if ((m = line.match(/^object-group\s+icmp-type\s+(\S+)/))) {
      const name = m[1];
      const { block, nextIdx } = peekIndentedBlock(i);
      const grp = { type: 'icmp-type', name, members: [] };
      for (const bl of block) {
        let mm;
        if ((mm = bl.match(/^icmp-object\s+(\S+)/))) grp.members.push({ ref: 'inline', icmpType: mm[1] });
      }
      groups[name] = grp;
      i = nextIdx;
      continue;
    }

    // ---- access-list extended (single line form) ----
    if ((m = line.match(/^access-list\s+(\S+)\s+extended\s+(.+)$/))) {
      const aclName = m[1];
      const rest = m[2];
      if (!acls[aclName]) acls[aclName] = [];
      const entry = parseACLLine(rest);
      entry.raw = line;
      entry.aclName = aclName;
      acls[aclName].push(entry);
      i++;
      continue;
    }

    // ---- access-list remark ----
    if ((m = line.match(/^access-list\s+(\S+)\s+remark\s+(.*)$/))) {
      const aclName = m[1];
      if (!acls[aclName]) acls[aclName] = [];
      acls[aclName].push({ remark: m[2], aclName });
      i++;
      continue;
    }

    // ---- access-group ----
    if ((m = line.match(/^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)/))) {
      accessGroups.push({ aclName: m[1], direction: m[2], interface: m[3] });
      i++;
      continue;
    }

    i++;
  }

  return { objects, groups, interfaces, acls, accessGroups };
}

// Parses the remainder of an "access-list ... extended ..." line
function parseACLLine(rest) {
  const tokens = tokenize(rest);
  let idx = 0;
  const entry = { action: null, protocol: null, src: null, dst: null, service: null, logSetting: null, logInterval: null, disabled: false, inactive: false };

  entry.action = tokens[idx++]; // permit / deny

  // protocol: could be a keyword (tcp/udp/icmp/ip/esp/gre...), "object <name>", or "object-group <name>"
  if (tokens[idx] === 'object') {
    entry.protocol = { ref: 'object', name: tokens[idx + 1] };
    idx += 2;
  } else if (tokens[idx] === 'object-group') {
    entry.protocol = { ref: 'group', name: tokens[idx + 1] };
    idx += 2;
  } else {
    entry.protocol = { ref: 'literal', name: tokens[idx] };
    idx += 1;
  }

  // source
  const srcResult = parseEndpoint(tokens, idx);
  entry.src = srcResult.endpoint;
  idx = srcResult.nextIdx;

  // source port (eq/range/lt/gt), only meaningful for tcp/udp literal protocols
  const srcPortResult = parsePortSpec(tokens, idx);
  if (srcPortResult) { entry.srcPort = srcPortResult.spec; idx = srcPortResult.nextIdx; }

  // destination
  const dstResult = parseEndpoint(tokens, idx);
  entry.dst = dstResult.endpoint;
  idx = dstResult.nextIdx;

  // destination port / service object-group / icmp type
  if (tokens[idx] === 'object-group' ) {
    entry.service = { ref: 'group', name: tokens[idx + 1] };
    idx += 2;
  } else if (tokens[idx] === 'object') {
    entry.service = { ref: 'object', name: tokens[idx + 1] };
    idx += 2;
  } else {
    const dstPortResult = parsePortSpec(tokens, idx);
    if (dstPortResult) { entry.destPort = dstPortResult.spec; idx = dstPortResult.nextIdx; }
    else if (tokens[idx] && /^(echo|echo-reply|unreachable|time-exceeded|traceroute)/.test(tokens[idx])) {
      entry.icmpType = tokens[idx];
      idx++;
    }
  }

  // trailing flags
  // ASA syntax: log [level] [interval secs]  |  log disable  |  log default
  //   bare "log"        -> level defaults to 6 (informational)
  //   "log disable"      -> logging explicitly turned off for this ACE
  //   "log default"      -> reverts to the ASA's default logging behavior (treated as no per-ACE log)
  //   "log <0-7>"        -> explicit numeric level
  while (idx < tokens.length) {
    if (tokens[idx] === 'log') {
      idx++;
      if (tokens[idx] === 'disable') {
        entry.logSetting = { mode: 'disabled' };
        idx++;
      } else if (tokens[idx] === 'default') {
        entry.logSetting = { mode: 'default-behavior' };
        idx++;
      } else if (tokens[idx] && /^[0-7]$/.test(tokens[idx])) {
        entry.logSetting = { mode: 'level', level: parseInt(tokens[idx], 10) };
        idx++;
      } else {
        entry.logSetting = { mode: 'level', level: 6 }; // bare "log" = informational
      }
      // optional trailing "interval <seconds>"
      if (tokens[idx] === 'interval' && tokens[idx + 1]) {
        entry.logInterval = parseInt(tokens[idx + 1], 10);
        idx += 2;
      }
    }
    else if (tokens[idx] === 'disable') { entry.disabled = true; idx++; }
    else if (tokens[idx] === 'inactive') { entry.inactive = true; idx++; }
    else idx++;
  }

  return entry;
}

function tokenize(s) {
  return s.trim().split(/\s+/);
}

function parseEndpoint(tokens, idx) {
  const t = tokens[idx];
  if (t === 'any' || t === 'any4' || t === 'any6') {
    return { endpoint: { kind: 'any' }, nextIdx: idx + 1 };
  }
  if (t === 'host') {
    return { endpoint: { kind: 'host', address: tokens[idx + 1] }, nextIdx: idx + 2 };
  }
  if (t === 'object-group') {
    return { endpoint: { kind: 'group', name: tokens[idx + 1] }, nextIdx: idx + 2 };
  }
  if (t === 'object') {
    return { endpoint: { kind: 'object', name: tokens[idx + 1] }, nextIdx: idx + 2 };
  }
  // otherwise assume "IP MASK" subnet form
  if (t && /^\d+\.\d+\.\d+\.\d+$/.test(t) && tokens[idx + 1] && /^\d+\.\d+\.\d+\.\d+$/.test(tokens[idx + 1])) {
    return { endpoint: { kind: 'subnet', address: t, mask: tokens[idx + 1] }, nextIdx: idx + 2 };
  }
  // fallback: treat single token as a bare host/fqdn
  return { endpoint: { kind: 'literal', address: t }, nextIdx: idx + 1 };
}

function parsePortSpec(tokens, idx) {
  const t = tokens[idx];
  if (t === 'eq') return { spec: { op: 'eq', port: tokens[idx + 1] }, nextIdx: idx + 2 };
  if (t === 'range') return { spec: { op: 'range', start: tokens[idx + 1], end: tokens[idx + 2] }, nextIdx: idx + 3 };
  if (t === 'lt') return { spec: { op: 'lt', port: tokens[idx + 1] }, nextIdx: idx + 2 };
  if (t === 'gt') return { spec: { op: 'gt', port: tokens[idx + 1] }, nextIdx: idx + 2 };
  if (t === 'neq') return { spec: { op: 'neq', port: tokens[idx + 1] }, nextIdx: idx + 2 };
  return null;
}

