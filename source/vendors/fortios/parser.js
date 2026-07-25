// ============================================================
// FortiOS (FortiGate) Config Parser
// ============================================================
// Parses the block grammar of a FortiGate config/backup:
//   config <path>
//       edit <name|id>
//           set <key> <value...>
//           config <subtable> ... end     (nested; ignored unless needed)
//       next
//   end
//
// Only the sections relevant to rule-risk analysis are materialized:
//   system interface, system zone, firewall address, firewall addrgrp,
//   firewall service custom, firewall service group, firewall policy,
//   router static. Everything else (replacemsg, certificates, UTM profiles,
//   NAT, VPN, etc.) is walked past. NAT is intentionally out of scope, per
//   the project's cross-vendor design decisions.
//
// Produces a config shape consumed only by this vendor's resolve.js, plus a
// top-level `interfaces` map that ui.js reads for its file-info interface
// count (the one soft field the UI touches directly on the parsed config).

function parseFortiOSConfig(text) {
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));

  const config = {
    vendor: 'fortios',
    interfaces: {},      // name -> { name, role, type, ip, mask, prefixLen, members, status, isDefaultRouteEgress }
    zones: {},           // name -> { members: [ifaceName...] }
    addresses: {},       // name -> { kind, ... }
    addrgrps: {},        // name -> { members: [name...] }
    services: {},        // name -> { combos:[...], protocol, raw }
    serviceGroups: {},   // name -> { members: [name...] }
    policies: [],        // [ { id, name, srcintf, dstintf, srcaddr, dstaddr, service, action, status, logtraffic, comments } ]
    staticRoutes: [],    // [ { device, isDefault } ]
  };

  // Stack of frames. A frame is either:
  //   { kind: 'config', path: 'firewall policy' }
  //   { kind: 'edit',   name: 'port1', fields: { key: [values...] } }
  // Only the fields of the innermost edit frame receive `set` values; the
  // enclosing config frame's path decides which collection an entry commits to.
  const stack = [];

  function innerEdit() {
    for (let k = stack.length - 1; k >= 0; k--) {
      if (stack[k].kind === 'edit') return stack[k];
      if (stack[k].kind === 'config') return null; // a config with no open edit above it
    }
    return null;
  }
  function enclosingConfigPath() {
    for (let k = stack.length - 1; k >= 0; k--) {
      if (stack[k].kind === 'config') return stack[k].path;
    }
    return null;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;

    let m;
    if ((m = line.match(/^config\s+(.+)$/))) {
      stack.push({ kind: 'config', path: m[1].replace(/"/g, '').trim() });
      continue;
    }
    if ((m = line.match(/^edit\s+(.+)$/))) {
      stack.push({ kind: 'edit', name: unquoteFirst(m[1]), fields: {} });
      continue;
    }
    if (line === 'next') {
      // pop the innermost edit and commit it to its enclosing config's collection
      let editFrame = null;
      while (stack.length && stack[stack.length - 1].kind !== 'edit') stack.pop();
      if (stack.length) editFrame = stack.pop();
      if (editFrame) commitEntry(config, enclosingConfigPath(), editFrame.name, editFrame.fields);
      continue;
    }
    if (line === 'end') {
      // pop back through to and including the innermost config frame
      while (stack.length && stack[stack.length - 1].kind !== 'config') stack.pop();
      if (stack.length) stack.pop();
      continue;
    }
    if ((m = line.match(/^set\s+(\S+)\s*(.*)$/))) {
      const edit = innerEdit();
      if (edit) edit.fields[m[1]] = splitValues(m[2]);
      continue;
    }
    // unset / append / other directives: ignored for risk analysis
  }

  // Post-process: mark the egress interface of every default route as the
  // internet edge (least-trusted). A default route is one with no `set dst`
  // (dst implicitly 0.0.0.0/0) or an explicit all-zeros/`/0` destination. The
  // gateway may be dynamic (DHCP/`set dynamic-gateway enable`) with no IP, so
  // the `device` is the authoritative signal, not any gateway address.
  for (const route of config.staticRoutes) {
    if (route.isDefault && route.device && config.interfaces[route.device]) {
      config.interfaces[route.device].isDefaultRouteEgress = true;
    }
  }

  return config;
}

function commitEntry(config, path, name, fields) {
  switch (path) {
    case 'system interface':
      config.interfaces[name] = buildInterface(name, fields);
      break;
    case 'system zone':
      config.zones[name] = { members: fields.interface || [] };
      break;
    case 'firewall address':
      config.addresses[name] = buildAddress(name, fields);
      break;
    case 'firewall addrgrp':
      config.addrgrps[name] = { members: fields.member || [] };
      break;
    case 'firewall service custom':
      config.services[name] = buildService(name, fields);
      break;
    case 'firewall service group':
      config.serviceGroups[name] = { members: fields.member || [] };
      break;
    case 'firewall policy':
      config.policies.push(buildPolicy(name, fields));
      break;
    case 'router static':
      config.staticRoutes.push(buildRoute(fields));
      break;
    default:
      // section we don't model (certificates, UTM profiles, NAT, etc.) — skip
      break;
  }
}

function buildInterface(name, f) {
  const iface = {
    name,
    role: f.role ? f.role[0] : null,
    type: f.type ? f.type[0] : null,
    members: f.member || [],
    status: f.status ? f.status[0] : 'up',
    ip: null,
    mask: null,
    prefixLen: null,
    isDefaultRouteEgress: false,
  };
  if (f.ip && f.ip.length >= 2) {
    iface.ip = f.ip[0];
    iface.mask = f.ip[1];
    iface.prefixLen = maskToPrefixLen(f.ip[1]);
  }
  return iface;
}

function buildAddress(name, f) {
  const type = f.type ? f.type[0] : null;
  if (type === 'iprange') {
    return { kind: 'range', start: f['start-ip'] ? f['start-ip'][0] : null, end: f['end-ip'] ? f['end-ip'][0] : null, name };
  }
  if (type === 'fqdn') {
    return { kind: 'fqdn', address: f.fqdn ? f.fqdn[0] : name, name };
  }
  if (type === 'geography') {
    return { kind: 'geo', country: f.country ? f.country[0] : '?', name };
  }
  if (type === 'wildcard' && f.wildcard) {
    // wildcard-fqdn / wildcard address: treat as a broad, unresolvable match
    return { kind: 'wildcard', address: f.wildcard.join(' '), name };
  }
  if (f.subnet && f.subnet.length >= 1) {
    const addr = f.subnet[0];
    let mask = f.subnet[1] || null;
    let prefixLen = null;
    // subnet can be "IP MASK" or "IP/PREFIX"
    if (addr.includes('/')) {
      const [a, p] = addr.split('/');
      return finishSubnet(a, null, /^\d+$/.test(p) ? parseInt(p, 10) : maskToPrefixLen(p), name);
    }
    if (mask) prefixLen = mask.includes('.') ? maskToPrefixLen(mask) : (/^\d+$/.test(mask) ? parseInt(mask, 10) : null);
    return finishSubnet(addr, mask, prefixLen, name);
  }
  // No address material at all (e.g. the built-in "all"/"none" stubs, or a
  // redaction-emptied object). "all" is resolved to `any` in resolve.js by
  // name; anything else here is an empty/unresolvable object.
  return { kind: 'empty', name };
}

function finishSubnet(addr, mask, prefixLen, name) {
  if (prefixLen === 32) return { kind: 'host', address: addr, name };
  return { kind: 'subnet', address: addr, mask: mask, prefixLen: prefixLen, name };
}

function buildService(name, f) {
  // A FortiOS custom service can carry TCP and/or UDP port ranges, or be an
  // ICMP / raw-IP-protocol service. Collapse all of that into a flat list of
  // {protocol, destPort, destPortEnd?, isRange?} combos scored downstream.
  const combos = [];
  const proto = f.protocol ? f.protocol[0] : null;

  addPortRanges(combos, 'tcp', f['tcp-portrange']);
  addPortRanges(combos, 'udp', f['udp-portrange']);
  addPortRanges(combos, 'sctp', f['sctp-portrange']);

  if (proto === 'ICMP' || proto === 'ICMP6') {
    combos.push({ protocol: 'icmp', destPort: null });
  } else if (proto === 'IP') {
    const num = f['protocol-number'] ? f['protocol-number'][0] : null;
    combos.push({ protocol: ipProtocolName(num), destPort: null });
  } else if (proto === 'ALL' && combos.length === 0) {
    combos.push({ protocol: 'ip', destPort: null }); // all protocols, all ports
  }

  if (combos.length === 0) {
    // no recognizable port/proto material — treat as any-port on its stated
    // protocol, or bare IP if none stated
    combos.push({ protocol: 'ip', destPort: null });
  }
  return { name, combos, protocol: proto };
}

// Expand a FortiOS portrange field ("53", "88 464", "161-162",
// "0-65535:0-65535") into {protocol, destPort[, destPortEnd, isRange]} combos.
// The part after ':' is the SOURCE port range, which we don't score — drop it.
function addPortRanges(combos, protocol, tokens) {
  if (!tokens) return;
  for (const tokRaw of tokens) {
    const tok = tokRaw.split(':')[0]; // strip src-port range
    if (!tok) continue;
    if (tok.includes('-')) {
      const [loS, hiS] = tok.split('-');
      const lo = parseInt(loS, 10), hi = parseInt(hiS, 10);
      if (!isNaN(lo) && !isNaN(hi)) {
        if (lo <= 1 && hi >= 65535) combos.push({ protocol, destPort: null }); // whole port space = any port
        else combos.push({ protocol, destPort: lo, destPortEnd: hi, isRange: true });
        continue;
      }
    }
    if (/^\d+$/.test(tok)) combos.push({ protocol, destPort: tok });
  }
}

function ipProtocolName(num) {
  const map = { '1': 'icmp', '4': 'ipinip', '41': '41', '47': 'gre', '50': 'esp', '51': 'ah', '58': 'icmp' };
  if (num && map[num]) return map[num];
  if (num) return 'ip-proto-' + num;
  return 'ip';
}

function buildPolicy(id, f) {
  return {
    id,
    name: f.name ? f.name[0] : null,
    srcintf: f.srcintf || [],
    dstintf: f.dstintf || [],
    srcaddr: f.srcaddr || [],
    dstaddr: f.dstaddr || [],
    service: f.service || [],
    // FortiOS policies default to `deny` when `set action` is absent.
    action: f.action ? f.action[0] : 'deny',
    // Policies default to enabled; `set status disable` is the inactive marker.
    status: f.status ? f.status[0] : 'enable',
    logtraffic: f.logtraffic ? f.logtraffic[0] : null,
    comments: f.comments ? f.comments[0] : (f.comment ? f.comment[0] : null),
  };
}

function buildRoute(f) {
  const device = f.device ? f.device[0] : null;
  let isDefault = false;
  if (!f.dst) {
    isDefault = true; // no explicit dst => 0.0.0.0/0 default route
  } else {
    const dst = f.dst[0];
    if (dst === '0.0.0.0' && (!f.dst[1] || f.dst[1] === '0.0.0.0')) isDefault = true;
    else if (dst === '0.0.0.0/0') isDefault = true;
  }
  return { device, isDefault };
}

// Split a FortiOS `set` value string into tokens, honoring double-quoted
// values that may contain spaces (e.g. `set member "Yaz Wired" "Yaz Wireless"`).
function splitValues(s) {
  const out = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    out.push(m[1] !== undefined ? m[1] : m[2]);
  }
  return out;
}

function unquoteFirst(s) {
  const m = s.match(/^\s*"([^"]*)"|^\s*(\S+)/);
  if (!m) return s.trim();
  return m[1] !== undefined ? m[1] : m[2];
}
