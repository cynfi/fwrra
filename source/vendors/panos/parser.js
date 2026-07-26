// ============================================================
// Palo Alto PAN-OS Config Parser ("set" format)
// ============================================================
// Parses the flat `set ...` CLI/export format (one directive per line):
//   set zone <z> network layer3 [ <intf> ... ]
//   set network interface ethernet <intf> layer3 ip <cidr>
//   set network virtual-router <vr> routing-table ip static-route <n> destination 0.0.0.0/0 interface <intf>
//   set address <n> ip-netmask <cidr> | ip-range <a-b> | fqdn <host>
//   set address-group <n> static [ <member> ... ]
//   set service <n> protocol tcp|udp port <p|a-b>
//   set service-group <n> members [ <member> ... ]
//   set rulebase security rules <n> from|to|source|destination|application|service|action|disabled|... <value>
//
// XML exports are not parsed (set format first, per DESIGN.md §7). Only the
// sections relevant to rule-risk analysis are materialized. Panorama
// device-group and multi-vsys prefixes are tolerated (we key off the
// `rules`/`address`/`zone`/... keywords wherever they appear in the path).
// NAT is intentionally out of scope.

function parsePanOSConfig(text) {
  const lines = text.split('\n').map(l => l.replace(/\r$/, ''));

  const config = {
    vendor: 'panos',
    interfaces: {},       // name -> { name, ip, prefixLen, dhcp, zone, isDefaultRouteEgress }
    zones: {},            // name -> { interfaces: [] }
    addresses: {},        // name -> { kind, ... }
    addressGroups: {},    // name -> { members: [] }
    services: {},         // name -> { combos: [{protocol, destPort, destPortEnd?, isRange?}] }
    serviceGroups: {},    // name -> { members: [] }
    rules: [],            // [ { name, from, to, source, destination, application, service, action, disabled, logEnd, logStart } ]
    routes: [],           // [ { dest, iface, isDefault } ]
  };
  const ruleByName = new Map();

  function getRule(name) {
    let r = ruleByName.get(name);
    if (!r) {
      r = { name, from: [], to: [], source: [], destination: [], application: [], service: [],
            action: 'allow', disabled: false, logEnd: false, logStart: false };
      ruleByName.set(name, r);
      config.rules.push(r); // preserve first-seen (evaluation) order
    }
    return r;
  }

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    let rest = line;
    if (/^set\s+/.test(rest)) rest = rest.replace(/^set\s+/, '');
    else continue; // only `set` directives (ignore `delete`, comments, XML, ...)

    const t = tokenizePan(rest);
    if (!t.length) continue;

    // ---- zone ----
    if (t[0] === 'zone' && t[2] === 'network' && t[3] === 'layer3') {
      const z = config.zones[t[1]] || (config.zones[t[1]] = { interfaces: [] });
      z.interfaces = z.interfaces.concat(flattenTok(t[4]));
      continue;
    }
    // ---- network interface / virtual-router ----
    if (t[0] === 'network') {
      if (t[1] === 'interface') {
        // set network interface <type> <name> layer3 ip <cidr> | dhcp-client
        const name = t[3];
        const li = t.indexOf('layer3');
        if (name && li !== -1) {
          const iface = config.interfaces[name] || (config.interfaces[name] = { name, ip: null, prefixLen: null, dhcp: false, zone: null, isDefaultRouteEgress: false });
          if (t[li + 1] === 'ip' && typeof t[li + 2] === 'string') {
            const [addr, pfx] = t[li + 2].split('/');
            iface.ip = addr;
            iface.prefixLen = pfx != null ? parseInt(pfx, 10) : null;
          } else if (t[li + 1] === 'dhcp-client') {
            iface.dhcp = true;
          }
        }
        continue;
      }
      if (t[1] === 'virtual-router') {
        const sr = t.indexOf('static-route');
        if (sr !== -1) {
          const rname = t[sr + 1];
          let route = config.routes.find(r => r._name === rname);
          if (!route) { route = { _name: rname, dest: null, iface: null, isDefault: false }; config.routes.push(route); }
          const di = t.indexOf('destination');
          if (di !== -1 && typeof t[di + 1] === 'string') {
            route.dest = t[di + 1];
            if (route.dest === '0.0.0.0/0') route.isDefault = true;
          }
          const ii = t.indexOf('interface');
          if (ii !== -1 && typeof t[ii + 1] === 'string') route.iface = t[ii + 1];
        }
        continue;
      }
      continue;
    }
    // ---- address ----
    if (t[0] === 'address' && t[1]) {
      const name = t[1];
      if (t[2] === 'ip-netmask') config.addresses[name] = panAddrFromNetmask(name, t[3]);
      else if (t[2] === 'ip-range') config.addresses[name] = { kind: 'range', start: (t[3] || '').split('-')[0], end: (t[3] || '').split('-')[1], name };
      else if (t[2] === 'fqdn') config.addresses[name] = { kind: 'fqdn', address: t[3], name };
      continue;
    }
    // ---- address-group ----
    if (t[0] === 'address-group' && t[1]) {
      const name = t[1];
      if (t[2] === 'static') config.addressGroups[name] = { members: flattenTok(t[3]) };
      else if (t[2] === 'dynamic') config.addressGroups[name] = { members: [], dynamic: true };
      continue;
    }
    // ---- service ----
    if (t[0] === 'service' && t[1] && t[2] === 'protocol') {
      const name = t[1];
      const proto = (t[3] || 'tcp').toLowerCase();
      const pi = t.indexOf('port');
      const svc = config.services[name] || (config.services[name] = { combos: [] });
      if (pi !== -1) {
        for (const tok of flattenTok(t[pi + 1])) {
          if (typeof tok !== 'string') continue;
          if (tok.includes('-')) {
            const [lo, hi] = tok.split('-');
            svc.combos.push({ protocol: proto, destPort: lo, destPortEnd: hi, isRange: true });
          } else {
            svc.combos.push({ protocol: proto, destPort: tok });
          }
        }
      }
      continue;
    }
    // ---- service-group ----
    if (t[0] === 'service-group' && t[1] && t[2] === 'members') {
      config.serviceGroups[t[1]] = { members: flattenTok(t[3]) };
      continue;
    }
    // ---- security rules ----
    const ri = t.indexOf('rules');
    if (ri !== -1 && t[ri - 1] === 'security') {
      const name = t[ri + 1];
      const field = t[ri + 2];
      const value = t[ri + 3];
      if (!name || !field) continue;
      const rule = getRule(name);
      switch (field) {
        case 'from': rule.from = flattenTok(value); break;
        case 'to': rule.to = flattenTok(value); break;
        case 'source': rule.source = flattenTok(value); break;
        case 'destination': rule.destination = flattenTok(value); break;
        case 'application': rule.application = flattenTok(value); break;
        case 'service': rule.service = flattenTok(value); break;
        case 'action': rule.action = value; break;
        case 'disabled': rule.disabled = (value === 'yes'); break;
        case 'log-end': rule.logEnd = (value === 'yes'); break;
        case 'log-start': rule.logStart = (value === 'yes'); break;
        case 'log-setting': rule.logSetting = value; break;
        default: break; // description, tag, profiles, negate-*, rule-type — ignored
      }
      continue;
    }
  }

  // Resolve each zone's interfaces, and mark the default-route egress interface.
  for (const zName of Object.keys(config.zones)) {
    for (const intf of config.zones[zName].interfaces) {
      if (config.interfaces[intf]) config.interfaces[intf].zone = zName;
    }
  }
  for (const route of config.routes) {
    if (route.isDefault && route.iface && config.interfaces[route.iface]) {
      config.interfaces[route.iface].isDefaultRouteEgress = true;
    }
  }

  return config;
}

function panAddrFromNetmask(name, cidr) {
  const [addr, pfxStr] = (cidr || '').split('/');
  const prefixLen = pfxStr != null ? parseInt(pfxStr, 10) : 32;
  if (prefixLen === 32) return { kind: 'host', address: addr, name };
  return { kind: 'subnet', address: addr, prefixLen, name };
}

// Tokenize a PAN-OS `set` directive body into a flat token list, where a
// `[ a b c ]` bracket group becomes a nested array and "quoted values" collapse
// to a single token.
function tokenizePan(s) {
  const out = [];
  let i = 0;
  const n = s.length;
  while (i < n) {
    const ch = s[i];
    if (ch === ' ' || ch === '\t') { i++; continue; }
    if (ch === '"') {
      let j = i + 1; let val = '';
      while (j < n && s[j] !== '"') { val += s[j]; j++; }
      out.push(val);
      i = j + 1;
      continue;
    }
    if (ch === '[') {
      // collect until matching ]
      let j = i + 1; let inner = '';
      while (j < n && s[j] !== ']') { inner += s[j]; j++; }
      out.push(tokenizePan(inner)); // nested array
      i = j + 1;
      continue;
    }
    let j = i; let tok = '';
    while (j < n && s[j] !== ' ' && s[j] !== '\t') { tok += s[j]; j++; }
    out.push(tok);
    i = j;
  }
  return out;
}

function flattenTok(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v.filter(x => typeof x === 'string');
  return [v];
}
