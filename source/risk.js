// ============================================================
// Risk Scoring Engine
// ============================================================

// Well-known risky ports/protocols -> risk value (0-100)
// Tunable table. Keyed by "protocol/port" or protocol name for whole-protocol risk.
const SERVICE_RISK_TABLE = {
  // File transfer / exfiltration
  'tcp/21': { name: 'FTP', score: 55, note: 'Clear-text file transfer / exfil path' },
  'tcp/20': { name: 'FTP-DATA', score: 55, note: 'Clear-text file transfer / exfil path' },
  'udp/69': { name: 'TFTP', score: 55, note: 'Unauthenticated file transfer' },
  'tcp/22': { name: 'SSH', score: 50, note: 'Remote shell / tunneling / SCP-SFTP exfil' },
  'tcp/23': { name: 'Telnet', score: 60, note: 'Clear-text remote shell' },
  'tcp/445': { name: 'SMB', score: 55, note: 'File share / lateral movement / worm vector' },
  'tcp/139': { name: 'NetBIOS-SSN', score: 50, note: 'Legacy file share / lateral movement' },
  'udp/137': { name: 'NetBIOS-NS', score: 35, note: 'NetBIOS name service' },
  'udp/138': { name: 'NetBIOS-DGM', score: 35, note: 'NetBIOS datagram service' },
  'tcp/3389': { name: 'RDP', score: 50, note: 'Remote desktop / common ransomware entry vector' },
  'tcp/5900': { name: 'VNC', score: 45, note: 'Remote desktop' },
  'tcp/135': { name: 'MS-RPC', score: 45, note: 'Windows RPC endpoint mapper' },
  'tcp/1433': { name: 'MS-SQL', score: 35, note: 'Database access' },
  'tcp/3306': { name: 'MySQL', score: 35, note: 'Database access' },
  'tcp/5432': { name: 'PostgreSQL', score: 35, note: 'Database access' },
  'tcp/25': { name: 'SMTP', score: 25, note: 'Mail relay - potential exfil/spam vector' },
  'tcp/53': { name: 'DNS-TCP', score: 25, note: 'DNS tunneling potential' },
  'udp/53': { name: 'DNS', score: 20, note: 'DNS tunneling potential' },
  'tcp/6667': { name: 'IRC', score: 40, note: 'Common C2 channel' },
  'tcp/4444': { name: 'Metasploit-default', score: 60, note: 'Common malware/C2 default port' },
  'tcp/443': { name: 'HTTPS', score: 10, note: 'Encrypted - low visibility but broadly expected' },
  'tcp/80': { name: 'HTTP', score: 10, note: 'Web traffic' },
};

const PROTOCOL_WHOLE_RISK = {
  'ip': { name: 'IP (any protocol)', score: 70, note: 'All protocols permitted' },
  'gre': { name: 'GRE', score: 30, note: 'Tunneling protocol' },
  'esp': { name: 'ESP', score: 15, note: 'IPsec ESP - encrypted' },
  'ah': { name: 'AH', score: 15, note: 'IPsec AH' },
};

const DEFAULT_SERVICE_RISK = 15; // baseline for an explicit, otherwise-unlisted single port
const ANY_PORT_SERVICE_RISK = 65; // protocol specified but no port restriction (e.g. "permit tcp host A host B")

function serviceKey(protocol, port) {
  return `${protocol}/${port}`;
}

// Look up risk for a single resolved (protocol, destPort) pair
function lookupServiceRisk(protocol, destPort) {
  if (!protocol) return { score: DEFAULT_SERVICE_RISK, name: 'unknown', note: '' };
  const p = protocol.toLowerCase();
  if (destPort) {
    const key = serviceKey(p, destPort);
    if (SERVICE_RISK_TABLE[key]) return SERVICE_RISK_TABLE[key];
    return { score: DEFAULT_SERVICE_RISK, name: `${p}/${destPort}`, note: 'Not in risky-service table' };
  }
  if (PROTOCOL_WHOLE_RISK[p]) return PROTOCOL_WHOLE_RISK[p];
  // protocol given, no port restriction at all (tcp/udp with no eq) => any port on that protocol
  if (p === 'tcp' || p === 'udp' || p === 'tcp-udp') {
    return { score: ANY_PORT_SERVICE_RISK, name: `${p} (any port)`, note: 'No port restriction on this protocol' };
  }
  return { score: DEFAULT_SERVICE_RISK, name: p, note: '' };
}

// --- Address scope classification ---
// scope: 'any' | 'host' | 'subnet' | 'group'(resolved to worst-case) 
function classifyEndpointScope(resolvedEndpoint) {
  // resolvedEndpoint: { kind: 'any' } | { kind:'host', address } | { kind:'subnet', address, mask, prefixLen } | {kind:'range',...} | {kind:'group', members:[resolved...]}
  if (!resolvedEndpoint) return { kind: 'unknown', prefixLen: null };
  if (resolvedEndpoint.kind === 'any') return { kind: 'any', prefixLen: 0 };
  if (resolvedEndpoint.kind === 'host') return { kind: 'host', prefixLen: 32 };
  if (resolvedEndpoint.kind === 'subnet') return { kind: 'subnet', prefixLen: resolvedEndpoint.prefixLen };
  if (resolvedEndpoint.kind === 'range') return { kind: 'range', prefixLen: null };
  if (resolvedEndpoint.kind === 'fqdn' || resolvedEndpoint.kind === 'literal') return { kind: 'host', prefixLen: 32 };
  if (resolvedEndpoint.kind === 'group') {
    // worst case = broadest member (lowest prefixLen / any present)
    let worst = { kind: 'host', prefixLen: 32 };
    for (const mem of resolvedEndpoint.members) {
      const c = classifyEndpointScope(mem);
      if (c.kind === 'any') return { kind: 'any', prefixLen: 0 };
      if (c.prefixLen !== null && (worst.prefixLen === null || c.prefixLen < worst.prefixLen)) worst = c;
    }
    return { kind: worst.kind === 'host' && resolvedEndpoint.members.length > 1 ? 'group-multi-host' : worst.kind, prefixLen: worst.prefixLen };
  }
  return { kind: 'unknown', prefixLen: null };
}

function maskToPrefixLen(mask) {
  const parts = mask.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return null;
  let bits = 0;
  for (const p of parts) {
    bits += (p >>> 0).toString(2).split('1').length - 1;
  }
  return bits;
}

// Exposure base score from src/dst scope classification + port breadth
// srcScope/dstScope: {kind, prefixLen}
// anyPortBothDirections: bool - true if the rule permits any port/proto (bidirectional concept doesn't
//   really apply to a single stateless ACL entry, so we treat "any port" as the bidirectional-equivalent case)
function computeExposureScore(srcScope, dstScope, isAnyPort) {
  const kinds = [srcScope.kind, dstScope.kind];

  // any <-> any
  if (kinds.includes('any') && kinds.filter(k => k === 'any').length === 2) {
    return { score: 100, label: 'any \u2194 any' };
  }
  // any <-> host
  if (kinds.includes('any') && kinds.includes('host')) {
    return { score: isAnyPort ? 85 : 75, label: 'any \u2194 host' };
  }
  // any <-> subnet (scale by prefix length of the subnet side)
  if (kinds.includes('any') && (kinds.includes('subnet') || kinds.includes('group-multi-host'))) {
    const subnetSide = srcScope.kind === 'subnet' || srcScope.kind === 'group-multi-host' ? srcScope : dstScope;
    const pfx = subnetSide.prefixLen;
    // smaller prefix (bigger network) = closer to "any"; larger prefix = closer to "host"
    let base;
    if (pfx === null) base = 70;
    else if (pfx <= 8) base = 95;
    else if (pfx <= 16) base = 88;
    else if (pfx <= 23) base = 80;
    else if (pfx <= 28) base = 65;
    else base = 55;
    return { score: isAnyPort ? Math.min(100, base + 8) : base, label: `any \u2194 subnet/${pfx ?? '?'}` };
  }
  // host <-> large subnet (prefix <= 23)
  if (kinds.includes('host') && (kinds.includes('subnet') || kinds.includes('group-multi-host'))) {
    const subnetSide = srcScope.kind === 'subnet' || srcScope.kind === 'group-multi-host' ? srcScope : dstScope;
    const pfx = subnetSide.prefixLen;
    let base;
    if (pfx === null) base = 45;
    else if (pfx <= 16) base = 60;
    else if (pfx <= 23) base = 50;
    else if (pfx <= 28) base = 32;
    else base = 25;
    return { score: isAnyPort ? Math.min(100, base + 15) : base, label: `host \u2194 subnet/${pfx ?? '?'}` };
  }
  // subnet <-> subnet
  if (kinds.includes('subnet') || kinds.includes('group-multi-host')) {
    const p1 = srcScope.prefixLen ?? 24, p2 = dstScope.prefixLen ?? 24;
    const minPfx = Math.min(p1, p2);
    let base;
    if (minPfx <= 8) base = 90;
    else if (minPfx <= 16) base = 78;
    else if (minPfx <= 23) base = 65;
    else base = 45;
    return { score: isAnyPort ? Math.min(100, base + 10) : base, label: 'subnet \u2194 subnet' };
  }
  // host <-> host
  if (kinds[0] === 'host' && kinds[1] === 'host') {
    return { score: isAnyPort ? 50 : 20, label: isAnyPort ? 'host \u2194 host (any port)' : 'host \u2194 host' };
  }

  return { score: 40, label: 'unclassified scope' };
}

// Combine exposure + service risk per the agreed algorithm:
//   max(exposure, service) + small flat bonus if BOTH are elevated, capped at 100
const ELEVATED_THRESHOLD = 55;
const BOTH_ELEVATED_BONUS = 10;

function combineRisk(exposureScore, serviceScore) {
  let combined = Math.max(exposureScore, serviceScore);
  let bonusApplied = false;
  if (exposureScore >= ELEVATED_THRESHOLD && serviceScore >= ELEVATED_THRESHOLD) {
    combined += BOTH_ELEVATED_BONUS;
    bonusApplied = true;
  }
  combined = Math.min(100, combined);
  return { combined, bonusApplied };
}

function riskBand(score) {
  if (score >= 80) return { label: 'Critical', color: '#ef4444' };
  if (score >= 60) return { label: 'High', color: '#f97316' };
  if (score >= 35) return { label: 'Medium', color: '#eab308' };
  if (score >= 1) return { label: 'Low', color: '#22c55e' };
  return { label: 'None', color: '#4b5563' };
}

// ---- Logging classification ----
const SYSLOG_LEVEL_NAMES = {
  0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error',
  4: 'Warning', 5: 'Notification', 6: 'Informational', 7: 'Debugging',
};

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
        ? 'No log keyword — denied traffic (possible recon/attack attempts) will not generate a per-hit syslog message.'
        : 'No log keyword — this permit generates no per-hit syslog message.',
    };
  }
  if (setting.mode === 'disabled') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'Logging disabled',
      detail: `'log disable' explicitly suppresses syslog messages for this ACE${isDeny ? ' — denied traffic will be silent' : ''}.`,
    };
  }
  if (setting.mode === 'default-behavior') {
    return {
      flagged: true,
      severity: isDeny ? 'high' : 'medium',
      label: 'Logging disabled',
      detail: `'log default' reverts to the ASA's built-in logging behavior for this ACE, which does not include a per-hit message${isDeny ? ' — denied traffic will be silent' : ''}.`,
    };
  }
  // mode === 'level'
  const name = SYSLOG_LEVEL_NAMES[setting.level] ?? 'Unknown';
  const isBareDefaultLog = setting.level === 6;
  return {
    flagged: false,
    severity: 'none',
    label: isBareDefaultLog ? `Default (6 – ${name})` : `${setting.level} – ${name}`,
    detail: isBareDefaultLog
      ? "Bare 'log' keyword — ASA defaults to level 6 (Informational)."
      : `Explicit log level ${setting.level} (${name}).`,
  };
}

