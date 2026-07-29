// ============================================================
// Palo Alto PAN-OS Config Parser ("set" format + XML export)
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
// It also parses the XML `running-config` export (`show config running` /
// exported config file) via the platform DOMParser, materializing the same
// `config` shape so resolve.js is format-agnostic. Only the sections relevant
// to rule-risk analysis are read; the pbf/nat rulebases are skipped (NAT is
// intentionally out of scope). Both shared and every vsys are collected.
// Panorama device-group and multi-vsys prefixes are tolerated in set format
// (we key off the `rules`/`address`/`zone`/... keywords wherever they appear).

function parsePanOSConfig(text) {
  if (looksLikePanOSXml(text)) return parsePanOSXmlConfig(text);
  return parsePanOSSetConfig(text);
}

// A PAN-OS XML export starts with an <?xml?> prolog and/or a <config> root and
// carries a security rulebase or a vsys/devices tree — enough to tell it apart
// from the flat `set` format without a full parse.
function looksLikePanOSXml(text) {
  if (!/^﻿?\s*<\?xml/i.test(text) && !/^﻿?\s*<config\b/i.test(text)) return false;
  return /<rulebase\b/i.test(text) || /<vsys\b/i.test(text) || /<devices\b/i.test(text);
}

function parsePanOSSetConfig(text) {
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
            action: 'allow', disabled: false, logEnd: false, logStart: false,
            negateSource: false, negateDest: false };
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
        case 'negate-source': rule.negateSource = (value === 'yes'); break;
        case 'negate-destination': rule.negateDest = (value === 'yes'); break;
        default: break; // description, tag, profiles, rule-type — ignored
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

// ---- XML export path ----
// Materializes the identical `config` shape from a PAN-OS XML running-config so
// resolve.js never sees the difference. Uses the platform DOMParser (present in
// the browser and in the jsdom test harness) — no dependency is added.
function parsePanOSXmlConfig(text) {
  const config = {
    vendor: 'panos',
    interfaces: {}, zones: {}, addresses: {}, addressGroups: {},
    services: {}, serviceGroups: {}, rules: [], routes: [],
  };

  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    throw new Error('PAN-OS XML: malformed config (parsererror)');
  }

  const childByTag = (el, tag) => {
    if (!el) return null;
    for (const c of el.children) if (c.tagName === tag) return c;
    return null;
  };
  // Direct <member> children (falling back to the element's own text for the
  // `<service>any</service>` short form), trimmed and de-blanked.
  const memberValues = (el) => {
    if (!el) return [];
    const out = [];
    for (const c of el.children) if (c.tagName === 'member') {
      const v = c.textContent.trim(); if (v) out.push(v);
    }
    if (!out.length && !el.children.length) {
      const v = el.textContent.trim(); if (v) out.push(v);
    }
    return out;
  };
  const addIface = (name) => config.interfaces[name] ||
    (config.interfaces[name] = { name, ip: null, prefixLen: null, dhcp: false, zone: null, isDefaultRouteEgress: false, _ipRef: null });

  // ---- addresses (shared + every vsys) ----
  for (const e of doc.querySelectorAll('address > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    const nm = childByTag(e, 'ip-netmask');
    const rg = childByTag(e, 'ip-range');
    const fq = childByTag(e, 'fqdn');
    if (nm) config.addresses[name] = panAddrFromNetmask(name, nm.textContent.trim());
    else if (rg) {
      const [start, end] = rg.textContent.trim().split('-');
      config.addresses[name] = { kind: 'range', start, end, name };
    } else if (fq) config.addresses[name] = { kind: 'fqdn', address: fq.textContent.trim(), name };
  }

  // ---- address groups ----
  for (const e of doc.querySelectorAll('address-group > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    const st = childByTag(e, 'static');
    const dyn = childByTag(e, 'dynamic');
    if (st) config.addressGroups[name] = { members: memberValues(st) };
    else if (dyn) config.addressGroups[name] = { members: [], dynamic: true };
  }

  // ---- services ----
  for (const e of doc.querySelectorAll('service > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    const proto = childByTag(e, 'protocol'); if (!proto) continue;
    const svc = config.services[name] || (config.services[name] = { combos: [] });
    for (const pkey of ['tcp', 'udp']) {
      const pn = childByTag(proto, pkey); if (!pn) continue;
      const portEl = childByTag(pn, 'port'); if (!portEl) continue;
      for (const raw of portEl.textContent.trim().split(',')) {
        const p = raw.trim(); if (!p) continue;
        if (p.includes('-')) {
          const [lo, hi] = p.split('-');
          svc.combos.push({ protocol: pkey, destPort: lo, destPortEnd: hi, isRange: true });
        } else svc.combos.push({ protocol: pkey, destPort: p });
      }
    }
  }

  // ---- service groups ----
  for (const e of doc.querySelectorAll('service-group > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    config.serviceGroups[name] = { members: memberValues(childByTag(e, 'members')) };
  }

  // ---- zones ----
  for (const e of doc.querySelectorAll('zone > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    const z = config.zones[name] || (config.zones[name] = { interfaces: [] });
    const net = childByTag(e, 'network');
    const l3 = net && childByTag(net, 'layer3');
    if (l3) z.interfaces = z.interfaces.concat(memberValues(l3));
  }

  // ---- interfaces (ethernet + subinterface units) ----
  const applyL3 = (iface, l3) => {
    const dhcp = childByTag(l3, 'dhcp-client');
    if (dhcp) {
      iface.dhcp = true;
      const cdr = childByTag(dhcp, 'create-default-route');
      if (cdr && cdr.textContent.trim() === 'yes') iface.isDefaultRouteEgress = true;
    }
    const ip = childByTag(l3, 'ip');
    if (ip) {
      const ent = childByTag(ip, 'entry');
      if (ent) iface._ipRef = ent.getAttribute('name');       // ip refers to an address object
      else if (ip.textContent.trim()) {                       // or an inline CIDR
        const a = panAddrFromNetmask(iface.name, ip.textContent.trim());
        iface.ip = a.address || null;
        iface.prefixLen = a.prefixLen != null ? a.prefixLen : null;
      }
    }
  };
  for (const eth of doc.querySelectorAll('interface > ethernet > entry')) {
    const base = eth.getAttribute('name'); if (!base) continue;
    const l3 = childByTag(eth, 'layer3');
    if (!l3) { addIface(base); continue; }
    const units = childByTag(l3, 'units');
    const unitEntries = units ? Array.from(units.children).filter(c => c.tagName === 'entry') : [];
    if (unitEntries.length) {
      for (const u of unitEntries) {
        const uname = u.getAttribute('name'); if (!uname) continue;
        applyL3(addIface(uname), u);
      }
    } else applyL3(addIface(base), l3);
  }
  // Resolve interface IPs that referenced an address object.
  for (const nm of Object.keys(config.interfaces)) {
    const ref = config.interfaces[nm]._ipRef;
    if (ref && config.addresses[ref]) {
      const a = config.addresses[ref];
      config.interfaces[nm].ip = a.address || null;
      config.interfaces[nm].prefixLen = a.prefixLen != null ? a.prefixLen : null;
    }
  }

  // ---- static routes (default-route egress signal) ----
  for (const sr of doc.querySelectorAll('virtual-router routing-table ip static-route > entry')) {
    const dest = childByTag(sr, 'destination');
    const ifc = childByTag(sr, 'interface');
    const d = dest ? dest.textContent.trim() : null;
    config.routes.push({
      _name: sr.getAttribute('name'),
      dest: d,
      iface: ifc ? ifc.textContent.trim() : null,
      isDefault: d === '0.0.0.0/0',
    });
  }

  // ---- security rules (pbf/nat rulebases intentionally skipped) ----
  for (const e of doc.querySelectorAll('rulebase > security > rules > entry')) {
    const name = e.getAttribute('name'); if (!name) continue;
    const rule = {
      name, from: [], to: [], source: [], destination: [], application: [], service: [],
      action: 'allow', disabled: false, logEnd: false, logStart: false,
      negateSource: false, negateDest: false,
    };
    rule.from = memberValues(childByTag(e, 'from'));
    rule.to = memberValues(childByTag(e, 'to'));
    rule.source = memberValues(childByTag(e, 'source'));
    rule.destination = memberValues(childByTag(e, 'destination'));
    rule.application = memberValues(childByTag(e, 'application'));
    rule.service = memberValues(childByTag(e, 'service'));
    const act = childByTag(e, 'action'); if (act) rule.action = act.textContent.trim();
    const le = childByTag(e, 'log-end'); if (le) rule.logEnd = le.textContent.trim() === 'yes';
    const ls = childByTag(e, 'log-start'); if (ls) rule.logStart = ls.textContent.trim() === 'yes';
    const dis = childByTag(e, 'disabled'); if (dis) rule.disabled = dis.textContent.trim() === 'yes';
    const lset = childByTag(e, 'log-setting'); if (lset) rule.logSetting = lset.textContent.trim();
    const nsrc = childByTag(e, 'negate-source'); if (nsrc) rule.negateSource = nsrc.textContent.trim() === 'yes';
    const ndst = childByTag(e, 'negate-destination'); if (ndst) rule.negateDest = ndst.textContent.trim() === 'yes';
    config.rules.push(rule); // document order = evaluation order
  }

  // Assign each interface its zone, and mark default-route egress interfaces.
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
