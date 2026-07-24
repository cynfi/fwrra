// ============================================================
// Risk Scoring Engine
// ============================================================

// Well-known risky ports/protocols -> risk value (0-100)
// Tunable table. Keyed by "protocol/port" or protocol name for whole-protocol risk.
//
// subnetPenaltyEligible: true marks services where a *raw CIDR subnet* endpoint
// (as opposed to an explicit, named object-group of hosts) gets the exponential
// "indiscriminate subnet" penalty in combineRisk() below, on top of its normal
// score. The distinction: a subnet permits anyone who lands an address in that
// range, intentionally or not (DHCP reassignment, a new VM, a compromised
// neighbor) — an object-group is a deliberately curated, documented list of
// hosts, and stays low-risk even when large. Only services where over-broad
// access is itself the governance concern (interactive remote access, file
// transfer, data stores, infrastructure control planes, and ports with no
// legitimate use that are common C2/backdoor signatures) are flagged eligible.
const SERVICE_RISK_TABLE = {
  // File transfer / exfiltration
  'tcp/21': { name: 'FTP', score: 55, note: 'Clear-text file transfer / exfil path', subnetPenaltyEligible: true },
  'tcp/20': { name: 'FTP-DATA', score: 55, note: 'Clear-text file transfer / exfil path', subnetPenaltyEligible: true },
  'udp/69': { name: 'TFTP', score: 55, note: 'Unauthenticated file transfer', subnetPenaltyEligible: true },
  'tcp/22': { name: 'SSH', score: 50, note: 'Remote shell / tunneling / SCP-SFTP exfil — encrypted, so it can smuggle arbitrary protocols past inspection', subnetPenaltyEligible: true },
  'tcp/23': { name: 'Telnet', score: 60, note: 'Clear-text remote shell — credentials and session content are visible to anyone on-path, even though that also makes it detectable by passive monitoring', subnetPenaltyEligible: true },
  'tcp/445': { name: 'SMB', score: 55, note: 'File share / lateral movement / worm vector', subnetPenaltyEligible: true },
  'tcp/139': { name: 'NetBIOS-SSN', score: 50, note: 'Legacy file share / lateral movement', subnetPenaltyEligible: true },
  'udp/137': { name: 'NetBIOS-NS', score: 35, note: 'NetBIOS name service' },
  'udp/138': { name: 'NetBIOS-DGM', score: 35, note: 'NetBIOS datagram service' },
  'tcp/3389': { name: 'RDP', score: 50, note: 'Remote desktop / common ransomware entry vector', subnetPenaltyEligible: true },
  'tcp/5900': { name: 'VNC', score: 45, note: 'Remote desktop' },
  'tcp/135': { name: 'MS-RPC', score: 45, note: 'Windows RPC endpoint mapper' },
  'tcp/1433': { name: 'MS-SQL', score: 45, note: 'Database theft; dangerous features (e.g. xp_cmdshell) can yield OS execution', subnetPenaltyEligible: true },
  'tcp/3306': { name: 'MySQL', score: 40, note: 'Database access / theft', subnetPenaltyEligible: true },
  'tcp/5432': { name: 'PostgreSQL', score: 40, note: 'Database access / theft', subnetPenaltyEligible: true },
  'tcp/6379': { name: 'Redis', score: 55, note: 'No auth by default in many deployments — remote unauthenticated access enables data theft, ransomware, or RCE via Lua scripting', subnetPenaltyEligible: true },
  'tcp/9200': { name: 'Elasticsearch', score: 50, note: 'REST API often exposed without auth by default; scripting engines have yielded RCE in the wild', subnetPenaltyEligible: true },
  'tcp/9300': { name: 'Elasticsearch', score: 50, note: 'Node-to-node transport port; same exposure concern as 9200', subnetPenaltyEligible: true },
  'tcp/27017': { name: 'MongoDB', score: 50, note: 'Historically shipped with no auth by default; subject of mass internet-wide data-theft/ransomware campaigns when exposed', subnetPenaltyEligible: true },
  'tcp/2375': { name: 'Docker API (no TLS)', score: 65, note: 'Unauthenticated — equivalent to root on the host; trivially used to mount the host filesystem or launch privileged containers', subnetPenaltyEligible: true },
  'tcp/2376': { name: 'Docker API (TLS)', score: 30, note: 'Still full host/container control if a client cert is compromised, but not open to anyone who reaches the port', subnetPenaltyEligible: true },
  'tcp/6443': { name: 'Kubernetes API', score: 55, note: 'Cluster control-plane; misconfigured RBAC/anonymous-auth exposure yields full cluster compromise', subnetPenaltyEligible: true },
  'tcp/10250': { name: 'Kubelet API', score: 55, note: 'Unauthenticated access allows arbitrary command execution inside pods on the node', subnetPenaltyEligible: true },
  'tcp/8000': { name: 'Alt web/admin', score: 30, note: 'Frequently fronts an unauthenticated management interface (CI servers, dashboards, dev consoles) rather than production web traffic', subnetPenaltyEligible: true },
  'tcp/8080': { name: 'Alt web/admin', score: 30, note: 'Frequently fronts an unauthenticated management interface (CI servers, dashboards, dev consoles) rather than production web traffic', subnetPenaltyEligible: true },
  'tcp/8443': { name: 'Alt web/admin', score: 30, note: 'Frequently fronts an unauthenticated management interface (CI servers, dashboards, dev consoles) rather than production web traffic', subnetPenaltyEligible: true },
  'tcp/11211': { name: 'Memcached', score: 45, note: 'Unauthenticated by design; used for both data exposure and massive DDoS reflection/amplification', subnetPenaltyEligible: true },
  'udp/11211': { name: 'Memcached', score: 45, note: 'Unauthenticated by design; used for both data exposure and massive DDoS reflection/amplification', subnetPenaltyEligible: true },
  'udp/161': { name: 'SNMP', score: 40, note: 'Default/weak community strings ("public"/"private") allow info disclosure or, with write access, device reconfiguration', subnetPenaltyEligible: true },
  'udp/162': { name: 'SNMP-trap', score: 40, note: 'Default/weak community strings ("public"/"private") allow info disclosure or, with write access, device reconfiguration', subnetPenaltyEligible: true },
  'tcp/25': { name: 'SMTP', score: 25, note: 'Mail relay - potential exfil/spam vector' },
  'tcp/53': { name: 'DNS-TCP', score: 25, note: 'DNS tunneling potential' },
  'udp/53': { name: 'DNS', score: 20, note: 'DNS tunneling potential' },
  'tcp/6667': { name: 'IRC', score: 40, note: 'Common C2 channel' },
  'tcp/4444': { name: 'Metasploit-default', score: 60, note: 'Common malware/C2 default port' },
  'tcp/443': { name: 'HTTPS', score: 10, note: 'Encrypted - low visibility but broadly expected' },
  'tcp/80': { name: 'HTTP', score: 10, note: 'Web traffic' },

  // Legacy / unnecessary services — essentially no legitimate modern use, and their
  // obscurity makes them a common choice for hiding C2, malware, or reverse-shell traffic.
  'tcp/1': { name: 'tcpmux', score: 40, note: 'Legacy multiplexer, no legitimate modern use — an unusual port choice is itself a signal something is being disguised', subnetPenaltyEligible: true },
  'udp/1': { name: 'tcpmux', score: 40, note: 'Legacy multiplexer, no legitimate modern use — an unusual port choice is itself a signal something is being disguised', subnetPenaltyEligible: true },
  'tcp/7': { name: 'echo', score: 40, note: 'No legitimate modern use; UDP echo is a known reflection/amplification vector', subnetPenaltyEligible: true },
  'udp/7': { name: 'echo', score: 40, note: 'No legitimate modern use; UDP echo is a known reflection/amplification vector', subnetPenaltyEligible: true },
  'tcp/9': { name: 'discard', score: 35, note: 'No legitimate modern use; sometimes abused for connectivity testing or as a DoS sink', subnetPenaltyEligible: true },
  'udp/9': { name: 'discard', score: 35, note: 'No legitimate modern use; sometimes abused for connectivity testing or as a DoS sink', subnetPenaltyEligible: true },
  'tcp/11': { name: 'systat', score: 40, note: 'Exposes running-process/user info; legacy, no legitimate modern use', subnetPenaltyEligible: true },
  'tcp/13': { name: 'daytime', score: 35, note: 'Legacy time service; UDP variant usable for reflection/amplification', subnetPenaltyEligible: true },
  'udp/13': { name: 'daytime', score: 35, note: 'Legacy time service; UDP variant usable for reflection/amplification', subnetPenaltyEligible: true },
  'tcp/15': { name: 'netstat', score: 40, note: 'Exposes network-connection info; legacy, no legitimate modern use', subnetPenaltyEligible: true },
  'tcp/19': { name: 'chargen', score: 45, note: 'Classic DDoS amplification vector (chargen/echo pairing); no legitimate modern use', subnetPenaltyEligible: true },
  'udp/19': { name: 'chargen', score: 45, note: 'Classic DDoS amplification vector (chargen/echo pairing); no legitimate modern use', subnetPenaltyEligible: true },
  'tcp/79': { name: 'finger', score: 45, note: 'User/account enumeration; historically exploited (Morris worm), useful for recon', subnetPenaltyEligible: true },
  'udp/67': { name: 'bootp', score: 30, note: 'Legacy DHCP precursor; can enable address spoofing / rogue-server MITM if not tightly scoped', subnetPenaltyEligible: true },
  'udp/177': { name: 'XDMCP', score: 40, note: 'Remote X display manager control; can allow graphical session hijack, minimal legitimate exposure need', subnetPenaltyEligible: true },
  'tcp/512': { name: 'rexec', score: 55, note: 'Remote command execution with a cleartext password — functionally equivalent risk to telnet', subnetPenaltyEligible: true },
  'tcp/515': { name: 'lpr', score: 35, note: 'Legacy print protocol; history of spool-based buffer-overflow/injection vulnerabilities', subnetPenaltyEligible: true },
  'udp/517': { name: 'talk', score: 30, note: 'Legacy chat protocol, no legitimate modern use, reflection/amplification potential', subnetPenaltyEligible: true },
  'udp/518': { name: 'ntalk', score: 30, note: 'Legacy chat protocol, no legitimate modern use, reflection/amplification potential', subnetPenaltyEligible: true },
  'tcp/540': { name: 'uucp', score: 35, note: 'Legacy Unix-to-Unix copy protocol; historically exploitable, no legitimate modern use', subnetPenaltyEligible: true },
  'tcp/60001': { name: 'Cisco AUX (binary)', score: 45, note: 'Non-standard administrative port; presence usually indicates a misconfigured or backdoored device', subnetPenaltyEligible: true },
  'tcp/1900': { name: 'UPnP/SSDP', score: 40, note: 'Auto-discovery protocol not meant to cross network boundaries; well-known amplification vector and unauthenticated device-control risk', subnetPenaltyEligible: true },
  'udp/1900': { name: 'UPnP/SSDP', score: 40, note: 'Auto-discovery protocol not meant to cross network boundaries; well-known amplification vector and unauthenticated device-control risk', subnetPenaltyEligible: true },
  'tcp/5000': { name: 'UPnP/SSDP', score: 40, note: 'Auto-discovery protocol not meant to cross network boundaries; well-known amplification vector and unauthenticated device-control risk', subnetPenaltyEligible: true },
  'udp/5000': { name: 'UPnP/SSDP', score: 40, note: 'Auto-discovery protocol not meant to cross network boundaries; well-known amplification vector and unauthenticated device-control risk', subnetPenaltyEligible: true },
  'tcp/12345': { name: 'NetBus', score: 65, note: 'Default port for the NetBus backdoor/trojan — a permit rule here is itself a compromise indicator, not a legitimate service', subnetPenaltyEligible: true },
  'tcp/12346': { name: 'NetBus', score: 65, note: 'Default port for the NetBus backdoor/trojan — a permit rule here is itself a compromise indicator, not a legitimate service', subnetPenaltyEligible: true },
};

const PROTOCOL_WHOLE_RISK = {
  'ip': { name: 'IP (any protocol)', score: 70, note: 'All protocols permitted' },
  'gre': { name: 'GRE', score: 30, note: 'Tunneling protocol' },
  'esp': { name: 'ESP', score: 15, note: 'IPsec ESP - encrypted' },
  'ah': { name: 'AH', score: 15, note: 'IPsec AH' },
  'icmp': { name: 'ICMP', score: 35, note: 'Frequently permitted broadly and unmonitored — used for C2 and data exfil tunneled inside echo request/reply payloads' },
  '4': { name: 'IP-in-IP', score: 30, note: 'Tunnels arbitrary IP traffic, easily bypasses ACLs that only inspect the outer header' },
  'ipinip': { name: 'IP-in-IP', score: 30, note: 'Tunnels arbitrary IP traffic, easily bypasses ACLs that only inspect the outer header' },
  '41': { name: '6in4 (IPv6-in-IPv4)', score: 30, note: 'Tunnels arbitrary IPv6 traffic inside IPv4, easily bypasses ACLs that only inspect the outer header' },
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
//
// Every endpoint (host/subnet/range/group/any) is reduced to a "breadth" score
// (0-100) derived from how many distinct addresses it covers, on a log2 scale:
// breadth = log2(addressCount) / 32 * 100. A /32 host is 0; a /24 is 25; a /16
// is 50; a /8 is 75; "any" (2^32 addresses) is 100. This is what lets any two
// endpoints of any kind be compared on one continuous, monotonic scale instead
// of a pile of hand-tuned per-combination buckets: broadening an endpoint can
// never produce a lower breadth than a narrower endpoint of the same kind, and
// a host object and a same-address "/32 subnet" object score identically.
//
// A resolved object-group's breadth is the *sum* of its members' address
// counts (so a 300-host group scores meaningfully broader than a 3-host
// group) rather than just the narrowest member, which the old bucket model
// couldn't distinguish.
function estimateAddressCount(resolvedEndpoint) {
  if (!resolvedEndpoint) return 1;
  switch (resolvedEndpoint.kind) {
    case 'any':
      return 4294967296; // 2^32
    case 'host':
    case 'fqdn':
    case 'literal':
      return 1;
    case 'subnet': {
      const pfx = resolvedEndpoint.prefixLen;
      if (pfx === null || pfx === undefined) return 256; // unknown mask; assume a /24-ish default
      return Math.pow(2, 32 - pfx);
    }
    case 'range':
      return 2; // best-effort placeholder; ASA range endpoints aren't common in practice
    case 'group': {
      let total = 0;
      for (const mem of resolvedEndpoint.members) {
        if (mem.kind === 'any') return 4294967296;
        total += estimateAddressCount(mem);
      }
      return total || 1;
    }
    default:
      return 1;
  }
}

function addressCountToBreadth(count) {
  if (count <= 1) return 0;
  return Math.max(0, Math.min(100, (Math.log2(count) / 32) * 100));
}

// scope: { kind: 'any'|'host'|'subnet'|'range'|'group-multi-host'|'unknown', prefixLen, breadth }
// `kind`/`prefixLen` describe the narrowest member (used for display labels);
// `breadth` reflects the full address-count-based exposure described above and
// is what actually drives computeExposureScore().
function classifyEndpointScope(resolvedEndpoint) {
  const breadth = addressCountToBreadth(estimateAddressCount(resolvedEndpoint));
  if (!resolvedEndpoint) return { kind: 'unknown', prefixLen: null, breadth: 0 };
  if (resolvedEndpoint.kind === 'any') return { kind: 'any', prefixLen: 0, breadth };
  if (resolvedEndpoint.kind === 'host') return { kind: 'host', prefixLen: 32, breadth };
  if (resolvedEndpoint.kind === 'subnet') return { kind: 'subnet', prefixLen: resolvedEndpoint.prefixLen, breadth };
  if (resolvedEndpoint.kind === 'range') return { kind: 'range', prefixLen: null, breadth };
  if (resolvedEndpoint.kind === 'fqdn' || resolvedEndpoint.kind === 'literal') return { kind: 'host', prefixLen: 32, breadth };
  if (resolvedEndpoint.kind === 'group') {
    // worst case = broadest member (lowest prefixLen / any present), used only for the display label
    let worst = { kind: 'host', prefixLen: 32 };
    for (const mem of resolvedEndpoint.members) {
      const c = classifyEndpointScope(mem);
      if (c.kind === 'any') { worst = { kind: 'any', prefixLen: 0 }; break; }
      if (c.prefixLen !== null && (worst.prefixLen === null || c.prefixLen < worst.prefixLen)) worst = c;
    }
    const kind = worst.kind === 'host' && resolvedEndpoint.members.length > 1 ? 'group-multi-host' : worst.kind;
    return { kind, prefixLen: worst.prefixLen, breadth };
  }
  return { kind: 'unknown', prefixLen: null, breadth: 0 };
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

function scopeLabel(scope) {
  if (scope.kind === 'any') return 'any';
  if (scope.kind === 'host') return 'host';
  if (scope.kind === 'subnet') return `subnet/${scope.prefixLen ?? '?'}`;
  if (scope.kind === 'group-multi-host') return 'group';
  if (scope.kind === 'range') return 'range';
  return scope.kind;
}

// A raw CIDR subnet larger than /30 (more than 4 addresses) is "indiscriminate" --
// anyone who lands an address in that range gets access, whether authorized or
// not. An explicit object-group of the same size is "intentional" -- someone
// deliberately enumerated it, which is inherently lower-risk and easier to
// justify/document in an access review. subnetPenaltyEligible services (see
// SERVICE_RISK_TABLE above) get an exponential penalty for the subnet case that
// a same-size group never receives, applied in combineRisk() below.
const SUBNET_PENALTY_FREE_HOST_BITS = 2; // /30 and tighter (<=4 addresses) are exempt

function subnetPenaltyFor(scope, eligible) {
  if (!eligible || scope.kind !== 'subnet') return 0;
  const pfx = scope.prefixLen;
  if (pfx === null || pfx === undefined) return 0;
  const hostBits = 32 - pfx;
  if (hostBits <= SUBNET_PENALTY_FREE_HOST_BITS) return 0;
  return Math.pow(2, hostBits);
}

// When the subnet-penalty applies to a side, that side's ordinary breadth
// contribution is excluded from the blend below so its size isn't counted
// twice (once gently via breadth, once steeply via the penalty).
function effectiveBreadth(scope, eligible) {
  if (eligible && scope.kind === 'subnet') {
    const pfx = scope.prefixLen;
    if (pfx !== null && pfx !== undefined && (32 - pfx) > SUBNET_PENALTY_FREE_HOST_BITS) return 0;
  }
  return scope.breadth;
}

// Exposure score from src/dst breadth. The broader side dominates (weight
// 0.75) but the narrower side still contributes (weight 0.25), so "any" on
// one side alone doesn't automatically saturate to the same score as "any on
// both sides" -- any<->any is still the worst case, any<->host is worse than
// host<->host but distinctly less than any<->any, etc. This is a single
// continuous formula covering every src/dst kind pairing, replacing the old
// per-combination bucket tables (which had a monotonicity bug where a /24
// destination could score *below* a single-host destination).
const BREADTH_WEIGHT_MAJOR = 0.75;
const BREADTH_WEIGHT_MINOR = 0.25;
const ANY_PORT_BREADTH_BUMP = 15;

function computeExposureScore(srcScope, dstScope, isAnyPort, subnetPenaltyEligible) {
  const srcBreadth = effectiveBreadth(srcScope, subnetPenaltyEligible);
  const dstBreadth = effectiveBreadth(dstScope, subnetPenaltyEligible);
  const hi = Math.max(srcBreadth, dstBreadth);
  const lo = Math.min(srcBreadth, dstBreadth);
  let score = hi * BREADTH_WEIGHT_MAJOR + lo * BREADTH_WEIGHT_MINOR;
  if (isAnyPort) score = Math.min(100, score + ANY_PORT_BREADTH_BUMP);
  score = Math.round(Math.min(100, score));
  const label = `${scopeLabel(srcScope)} ↔ ${scopeLabel(dstScope)}`;
  return { score, label };
}

// Combine exposure + service risk via a "noisy-OR": combined = e + s - e*s/100.
// Two properties fall out of this that a flat max()+threshold-bonus can't give:
//  - At zero exposure (host<->host), combined reduces to exactly the service's
//    own table score -- a host-to-host SSH rule lands at SSH's score (50,
//    Medium) because that's SSH's inherent risk, not because of a special case.
//  - It's monotonic and cliff-free by construction: increasing exposure *or*
//    service score can never decrease the combined score, so narrowing scope
//    (subnet -> group -> host) always moves the number, at every step, for
//    every protocol -- not just above some threshold.
// On top of that, subnetPenaltyEligible services add an explicit, separately
// auditable penalty for raw-subnet sides larger than /30 (see subnetPenaltyFor
// above) -- e.g. "SSH host-to-/27 = 50 (SSH's own score) + 32 (2^5, the /27's
// indiscriminate-subnet penalty) = 82".
function combineRisk(exposureScore, serviceScore, srcScope, dstScope, subnetPenaltyEligible) {
  const noisyOr = exposureScore + serviceScore - (exposureScore * serviceScore) / 100;
  const penalty = subnetPenaltyFor(srcScope, subnetPenaltyEligible) + subnetPenaltyFor(dstScope, subnetPenaltyEligible);
  const combined = Math.round(Math.min(100, noisyOr + penalty));
  return { combined, subnetPenaltyApplied: penalty > 0, subnetPenalty: penalty };
}

function riskBand(score) {
  if (score >= 80) return { label: 'Critical', color: '#ef4444' };
  if (score >= 60) return { label: 'High', color: '#f97316' };
  if (score >= 35) return { label: 'Medium', color: '#eab308' };
  if (score >= 1) return { label: 'Low', color: '#22c55e' };
  return { label: 'None', color: '#4b5563' };
}
