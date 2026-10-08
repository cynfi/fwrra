// ============================================================
// ASA remote-access VPN (AnyConnect) grammar
// ============================================================
// Parses: ip local pool, group-policy (+attributes), tunnel-group (+general-
// and webvpn-attributes), username <n> attributes, standard ACLs (used by
// split tunneling), sysopt connection permit-vpn, and global webvpn.
// Runs as its own pass over the same line array as parseASAConfig. Uses
// tokenize()/parseEndpoint() from parser.js (same vendor IIFE).

function vpnIpToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

// Indented sub-block following lines[i]; each item keeps its indent so nested
// sub-blocks (e.g. `webvpn` under a group-policy) can be skipped.
function vpnBlock(lines, i) {
  const block = [];
  let j = i + 1;
  while (j < lines.length && /^\s+\S/.test(lines[j])) {
    block.push({ text: lines[j].trim(), indent: lines[j].match(/^\s*/)[0].length });
    j++;
  }
  return { block, nextIdx: j };
}

// "value NAME" -> {mode:'value', acl:NAME}; "none" -> {mode:'none'}; else undefined
function vpnRef(tokens) {
  if (tokens[0] === 'none') return { mode: 'none' };
  if (tokens[0] === 'value' && tokens[1]) return { mode: 'value', acl: tokens[1] };
  return undefined;
}

function applyGroupPolicyAttrs(gp, block) {
  let skipIndent = -1;
  for (const { text, indent } of block) {
    if (skipIndent >= 0) { if (indent > skipIndent) continue; skipIndent = -1; }
    if (text === 'webvpn') { skipIndent = indent; continue; }
    const t = tokenize(text);
    const key = t[0];
    let r;
    if (key === 'vpn-filter' && (r = vpnRef(t.slice(1)))) gp.vpnFilter = r;
    else if (key === 'split-tunnel-policy' && t[1]) gp.splitPolicy = t[1];
    else if (key === 'split-tunnel-network-list' && (r = vpnRef(t.slice(1)))) gp.splitAcl = r;
    else if (key === 'address-pools' && t[1] === 'value') gp.addressPools = t.slice(2);
    else if (key === 'address-pools' && t[1] === 'none') gp.addressPools = [];
    else if (key === 'vpn-tunnel-protocol') gp.tunnelProtocols = t.slice(1);
    else if (key === 'dns-server' && t[1] === 'value') gp.dnsServers = t.slice(2);
    else if (key === 'dns-server' && t[1] === 'none') gp.dnsServers = [];
    else if (key === 'vpn-simultaneous-logins' && /^\d+$/.test(t[1] || '')) gp.simultaneousLogins = parseInt(t[1], 10);
    else gp.rawAttrs.push(text);
  }
}

function applyUserAttrs(u, block) {
  for (const { text } of block) {
    const t = tokenize(text);
    const key = t[0];
    let r;
    if (key === 'vpn-group-policy' && t[1]) u.vpnGroupPolicy = t[1];
    else if (key === 'vpn-filter' && (r = vpnRef(t.slice(1)))) u.vpnFilter = r;
    else if (key === 'group-lock' && t[1] === 'value' && t[2]) u.groupLock = t[2];
    else if (key === 'vpn-framed-ip-address' && t[1]) u.framedIp = { ip: t[1], mask: t[2] || null };
    else u.rawAttrs.push(text);
  }
}

function parseASAVpn(lines) {
  const pools = {}, groupPolicies = {}, tunnelGroups = {}, users = {}, standardAcls = {};
  const vpnGlobal = { permitVpn: true, permitVpnExplicit: false, webvpnEnabledOn: [], anyconnectEnabled: false, tunnelGroupList: false };
  const gpOf = (name) => (groupPolicies[name] = groupPolicies[name] || { name, rawAttrs: [] });
  const tgOf = (name) => (tunnelGroups[name] = tunnelGroups[name] ||
    { name, type: null, addressPools: [], defaultGroupPolicy: null, authServerGroup: null, aliases: [], urls: [] });

  let i = 0;
  while (i < lines.length) {
    const rawLine = lines[i];
    const line = rawLine.trim();
    // Only top-level (non-indented) lines open constructs; nested lines are
    // consumed by vpnBlock().
    if (!line || line[0] === '!' || /^\s/.test(rawLine)) { i++; continue; }
    let m;

    if ((m = line.match(/^ip\s+local\s+pool\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)(?:\s+mask\s+(\S+))?/))) {
      pools[m[1]] = { name: m[1], start: m[2], end: m[3], mask: m[4] || null,
        count: Math.max(0, vpnIpToInt(m[3]) - vpnIpToInt(m[2]) + 1) };
      i++; continue;
    }

    if ((m = line.match(/^access-list\s+(\S+)\s+standard\s+(permit|deny)\s+(.+)$/))) {
      const endpoint = parseEndpoint(tokenize(m[3]), 0).endpoint;
      (standardAcls[m[1]] = standardAcls[m[1]] || []).push({ action: m[2], src: endpoint, raw: line });
      i++; continue;
    }

    if ((m = line.match(/^group-policy\s+(\S+)\s+(internal|external)\b/))) {
      gpOf(m[1]).kind = m[2];
      i++; continue;
    }
    if ((m = line.match(/^group-policy\s+(\S+)\s+attributes\s*$/))) {
      const { block, nextIdx } = vpnBlock(lines, i);
      applyGroupPolicyAttrs(gpOf(m[1]), block);
      i = nextIdx; continue;
    }

    if ((m = line.match(/^tunnel-group\s+(\S+)\s+type\s+(\S+)/))) {
      tgOf(m[1]).type = m[2];
      i++; continue;
    }
    if ((m = line.match(/^tunnel-group\s+(\S+)\s+(general-attributes|webvpn-attributes)\s*$/))) {
      const tg = tgOf(m[1]);
      const { block, nextIdx } = vpnBlock(lines, i);
      for (const { text } of block) {
        const t = tokenize(text);
        const noIf = t.slice(1).filter(x => !x.startsWith('('));
        if (m[2] === 'general-attributes') {
          if (t[0] === 'address-pool') tg.addressPools = noIf;
          else if (t[0] === 'default-group-policy' && t[1]) tg.defaultGroupPolicy = t[1];
          else if (t[0] === 'authentication-server-group' && noIf.length) tg.authServerGroup = noIf.join(' ');
        } else {
          if (t[0] === 'group-alias' && t[1] && t[2] !== 'disable') tg.aliases.push(t[1]);
          else if (t[0] === 'group-url' && t[1] && t[2] !== 'disable') tg.urls.push(t[1]);
        }
      }
      i = nextIdx; continue;
    }

    if ((m = line.match(/^username\s+(\S+)\s+attributes\s*$/))) {
      const u = users[m[1]] = users[m[1]] || { name: m[1], rawAttrs: [] };
      const { block, nextIdx } = vpnBlock(lines, i);
      applyUserAttrs(u, block);
      i = nextIdx; continue;
    }

    if (/^no\s+sysopt\s+connection\s+permit-vpn\b/.test(line)) {
      vpnGlobal.permitVpn = false; vpnGlobal.permitVpnExplicit = true; i++; continue;
    }
    if (/^sysopt\s+connection\s+permit-vpn\b/.test(line)) {
      vpnGlobal.permitVpn = true; vpnGlobal.permitVpnExplicit = true; i++; continue;
    }
    if (/^webvpn\s*$/.test(line)) {
      const { block, nextIdx } = vpnBlock(lines, i);
      for (const { text } of block) {
        let w;
        if ((w = text.match(/^enable\s+(\S+)/))) vpnGlobal.webvpnEnabledOn.push(w[1]);
        else if (/^anyconnect\s+enable\b/.test(text)) vpnGlobal.anyconnectEnabled = true;
        else if (/^tunnel-group-list\s+enable\b/.test(text)) vpnGlobal.tunnelGroupList = true;
      }
      i = nextIdx; continue;
    }

    i++;
  }

  return { pools, groupPolicies, tunnelGroups, users, standardAcls, vpnGlobal };
}
